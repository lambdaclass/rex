use ethrex_common::Bytes;
use ethrex_common::{Address, H32, U256};
use ethrex_rpc::clients::eth::errors::CalldataEncodeError;
use keccak_hash::keccak;
use serde::{Deserialize, Serialize};

/// Struct representing the possible solidity types for function arguments
/// - `Uint` -> `uint256`
/// - `Address` -> `address`
/// - `Bool` -> `bool`
/// - `Bytes` -> `bytes`
/// - `String` -> `string`
/// - `Array` -> `T[]`
/// - `Tuple` -> `(X_1, ..., X_k)`
/// - `FixedArray` -> `T[k]`
/// - `FixedBytes` -> `bytesN`
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum Value {
    Address(Address),
    Uint(U256),
    Int(U256),
    Bool(bool),
    Bytes(Bytes),
    String(String),
    Array(Vec<Value>),
    Tuple(Vec<Value>),
    FixedArray(Vec<Value>),
    FixedBytes(Bytes),
}

#[derive(Debug, thiserror::Error)]
pub enum CalldataDecodeError {
    #[error("Failed to parse function signature: {0}")]
    ParseError(String),
    #[error("Invalid calldata. Tried to read more bytes than there are.")]
    OutOfBounds,
    #[error("Internal Calldata decoding error. This is most likely a bug")]
    InternalError,
}

pub fn parse_signature(signature: &str) -> Result<(String, Vec<String>), CalldataEncodeError> {
    let sig = signature.trim().trim_start_matches("function ");
    let (name, params) = sig
        .split_once('(')
        .ok_or(CalldataEncodeError::ParseError(signature.to_owned()))?;
    let params = params.rsplit_once(')').map_or(params, |(left, _)| left);

    // We use this to only keep track of top level tuples
    // "address,(uint256,uint256)" -> "address" and "(uint256,uint256)"
    // "address,(unit256,(uint256,uint256))" -> "address" and "(unit256,(uint256,uint256))"
    let mut splitted_params = Vec::new();
    let mut current_param = String::new();
    let mut parenthesis_depth = 0;

    for ch in params.chars() {
        match ch {
            '(' => {
                parenthesis_depth += 1;
                current_param.push(ch);
            }
            ')' => {
                parenthesis_depth -= 1;
                current_param.push(ch);
            }
            ',' if parenthesis_depth == 0 => {
                if !current_param.is_empty() {
                    splitted_params.push(current_param.trim().to_string());
                    current_param = String::new();
                }
            }
            _ => current_param.push(ch),
        }
    }

    // push the last param if it exists
    if !current_param.is_empty() {
        splitted_params.push(current_param.trim().to_string());
    }

    Ok((name.to_string(), splitted_params))
}

fn compute_function_selector(name: &str, params: &[String]) -> Result<H32, CalldataEncodeError> {
    let normalized_signature = format!("{name}({})", params.join(","));
    let hash = keccak(normalized_signature.as_bytes());

    Ok(H32::from(&hash[..4].try_into().map_err(|_| {
        CalldataEncodeError::ParseError(name.to_owned())
    })?))
}

pub fn encode_calldata(signature: &str, values: &[Value]) -> Result<Vec<u8>, CalldataEncodeError> {
    let (name, params) = parse_signature(signature)?;

    // Checks if params = [""]
    // that case happen when we have a function selector as follows: function name()
    let mut params = params;
    if params.is_empty() {
        params = vec![];
    }

    if params.len() != values.len() {
        return Err(CalldataEncodeError::WrongArgumentLength(
            signature.to_owned(),
        ));
    }

    let function_selector = compute_function_selector(&name, &params)?;
    let calldata = encode_tuple(values)?;
    let mut with_selector = function_selector.as_bytes().to_vec();

    with_selector.extend_from_slice(&calldata);

    Ok(with_selector)
}

pub fn decode_calldata(signature: &str, data: Bytes) -> Result<Vec<Value>, CalldataDecodeError> {
    let (_, params) =
        parse_signature(signature).map_err(|e| CalldataDecodeError::ParseError(e.to_string()))?;
    let mut decoder = DecodeHelper::new(&data);
    let datatype = DataType::Tuple(
        params
            .iter()
            .map(|v| DataType::parse(v))
            .collect::<Result<Vec<_>, _>>()?,
    );
    match datatype.decode(&mut decoder)? {
        Value::Tuple(values) => Ok(values),
        _ => Err(CalldataDecodeError::InternalError),
    }
}

struct DecodeHelper<'a> {
    buf: &'a [u8],
    index: usize,
}

impl<'a> DecodeHelper<'a> {
    fn new(buf: &'a [u8]) -> Self {
        DecodeHelper { buf, index: 4 }
    }
    fn consume(&mut self, n: usize) -> Result<&'a [u8], CalldataDecodeError> {
        let data = self
            .buf
            .get(self.index..self.index + n)
            .ok_or(CalldataDecodeError::OutOfBounds)?;
        self.index += n;
        Ok(data)
    }
    fn consume_u256(&mut self) -> Result<U256, CalldataDecodeError> {
        Ok(U256::from_big_endian(self.consume(32)?))
    }
    fn start_reading_at(&self, offset: usize) -> Result<Self, CalldataDecodeError> {
        let data = self
            .buf
            .get(self.index + offset..)
            .ok_or(CalldataDecodeError::OutOfBounds)?;
        Ok(DecodeHelper {
            buf: data,
            index: 0,
        })
    }
}

#[derive(Clone, Debug)]
enum DataType {
    Array(Box<DataType>),
    FixedArray(usize, Box<DataType>),
    Tuple(Vec<DataType>),
    Bytes,
    FixedBytes(usize),
    Address,
    Bool,
    Uint,
    Int,
}

impl DataType {
    fn parse(param: &str) -> Result<Self, CalldataDecodeError> {
        Ok(match param {
            _ if param.ends_with("[]") => {
                let inner = param
                    .strip_suffix("[]")
                    .ok_or(CalldataDecodeError::InternalError)?;
                DataType::Array(Box::new(DataType::parse(inner)?))
            }
            _ if param.ends_with("]") => {
                let mut n = String::new();
                let mut iter = param.chars().rev().skip(1);
                for c in iter.by_ref() {
                    if c.is_ascii_digit() {
                        n.insert(0, c);
                    } else {
                        break;
                    }
                }
                iter.next();
                let inner: String = iter.collect::<String>().chars().rev().collect();
                let n: usize = n.parse().map_err(|_| CalldataDecodeError::OutOfBounds)?;
                DataType::FixedArray(n, Box::new(DataType::parse(&inner)?))
            }
            _ if param.ends_with(")") => {
                let (_, inner) = parse_signature(param)
                    .map_err(|e| CalldataDecodeError::ParseError(e.to_string()))?;
                DataType::Tuple(
                    inner
                        .iter()
                        .map(|v| DataType::parse(v))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            "address" => DataType::Address,
            "bool" => DataType::Bool,
            "bytes" => DataType::Bytes,
            _ if param.starts_with("bytes") => {
                let n = param
                    .trim_start_matches("bytes")
                    .parse()
                    .map_err(|_| CalldataDecodeError::ParseError("invalid bytesN".to_string()))?;
                DataType::FixedBytes(n)
            }
            _ if param.starts_with("uint") => DataType::Uint,
            _ if param.starts_with("int") => DataType::Int,
            _ => {
                return Err(CalldataDecodeError::ParseError(format!(
                    "unknown type {param}"
                )));
            }
        })
    }
    fn is_dynamic(&self) -> bool {
        match self {
            DataType::Array(_) => true,
            DataType::Bytes => true,
            DataType::FixedArray(_, inner) => inner.is_dynamic(),
            DataType::Tuple(inner) => inner.iter().any(|t| t.is_dynamic()),
            _ => false,
        }
    }
    fn decode(&self, data: &mut DecodeHelper) -> Result<Value, CalldataDecodeError> {
        Ok(match self {
            DataType::Uint => Value::Uint(data.consume_u256()?),
            DataType::Int => Value::Int(data.consume_u256()?),
            DataType::Address => {
                data.consume(32 - 20)?;
                Value::Address(Address::from_slice(data.consume(20)?))
            }
            DataType::Bool => Value::Bool(!data.consume_u256()?.is_zero()),
            DataType::FixedBytes(n) => Value::FixedBytes(data.consume(32)?[0..*n].to_vec().into()),
            DataType::Bytes => {
                let n: usize = data
                    .consume_u256()?
                    .try_into()
                    .map_err(|_| CalldataDecodeError::OutOfBounds)?;
                let size = if n % 32 == 0 {
                    n
                } else {
                    n.next_multiple_of(32)
                };
                Value::Bytes(data.consume(size)?[0..n].to_vec().into())
            }
            DataType::FixedArray(n, inner_type) => {
                let inner_type = *inner_type.clone();
                let value = DataType::Tuple(vec![inner_type; *n]).decode(data)?;
                match value {
                    Value::Tuple(inner) => Value::FixedArray(inner),
                    _ => return Err(CalldataDecodeError::InternalError),
                }
            }
            DataType::Tuple(inner_types) => {
                let mut values = Vec::new();
                let start_reader = data.start_reading_at(0)?;
                for inner_type in inner_types {
                    if inner_type.is_dynamic() {
                        let offset: usize = data
                            .consume_u256()?
                            .try_into()
                            .map_err(|_| CalldataDecodeError::OutOfBounds)?;
                        values
                            .push(inner_type.decode(&mut start_reader.start_reading_at(offset)?)?);
                    } else {
                        values.push(inner_type.decode(data)?);
                    }
                }
                Value::Tuple(values)
            }
            DataType::Array(inner_type) => {
                let n: usize = data
                    .consume_u256()?
                    .try_into()
                    .map_err(|_| CalldataDecodeError::OutOfBounds)?;
                let mut values = Vec::new();
                for _ in 0..n {
                    values.push(inner_type.decode(data)?);
                }
                Value::Array(values)
            }
        })
    }
}

// This is the main entrypoint for ABI encoding solidity function arguments, as the list of arguments themselves are
// considered a tuple. Before going through this function, read the solidity ABI spec first
// https://docs.soliditylang.org/en/develop/abi-spec.html.
// The encoding of a tuple consists of two parts: a static and a dynamic one (what the spec calls the head and tail of the encoding).
// The dynamic part always follows at the end of the static one.
// Arguments are encoded in order. If the argument is static, it is encoded in place, i.e, there's no dynamic part.
// If the argument is dynamic, only its offset to the dynamic part is recorded on the static sector.
pub fn encode_tuple(values: &[Value]) -> Result<Vec<u8>, CalldataEncodeError> {
    let mut current_offset = 0;
    let mut current_dynamic_offset = 0;
    for value in values {
        current_dynamic_offset += static_offset_value(value);
    }

    let mut ret = vec![0; current_dynamic_offset];

    for value in values {
        match value {
            Value::Address(h160) => {
                write_u256(&mut ret, address_to_word(*h160), current_offset)?;
            }
            Value::Uint(u256) => {
                write_u256(&mut ret, *u256, current_offset)?;
            }
            Value::Int(u256) => {
                write_u256(&mut ret, *u256, current_offset)?;
            }
            Value::Bool(boolean) => {
                write_u256(&mut ret, U256::from(u8::from(*boolean)), current_offset)?;
            }
            Value::Bytes(bytes) => {
                write_u256(&mut ret, U256::from(current_dynamic_offset), current_offset)?;

                let bytes_encoding = encode_bytes(bytes);
                ret.extend_from_slice(&bytes_encoding);
                current_dynamic_offset += bytes_encoding.len();
            }
            Value::String(string_value) => {
                write_u256(&mut ret, U256::from(current_dynamic_offset), current_offset)?;

                let utf8_encoded = Bytes::copy_from_slice(string_value.as_bytes());
                let bytes_encoding = encode_bytes(&utf8_encoded);
                ret.extend_from_slice(&bytes_encoding);
                current_dynamic_offset += bytes_encoding.len();
            }
            Value::Array(array_values) => {
                write_u256(&mut ret, U256::from(current_dynamic_offset), current_offset)?;

                let array_encoding = encode_array(array_values)?;
                ret.extend_from_slice(&array_encoding);
                current_dynamic_offset += array_encoding.len();
            }
            Value::Tuple(tuple_values) => {
                if !is_dynamic(value) {
                    let tuple_encoding = encode_tuple(tuple_values)?;
                    ret.extend_from_slice(&tuple_encoding);
                } else {
                    write_u256(&mut ret, U256::from(current_dynamic_offset), current_offset)?;

                    let tuple_encoding = encode_tuple(tuple_values)?;
                    ret.extend_from_slice(&tuple_encoding);
                    current_dynamic_offset += tuple_encoding.len();
                }
            }
            Value::FixedArray(fixed_array_values) => {
                if !is_dynamic(value) {
                    let fixed_array_encoding = encode_tuple(fixed_array_values)?;
                    ret.extend_from_slice(&fixed_array_encoding);
                } else {
                    write_u256(&mut ret, U256::from(current_dynamic_offset), current_offset)?;

                    let tuple_encoding = encode_tuple(fixed_array_values)?;
                    ret.extend_from_slice(&tuple_encoding);
                    current_dynamic_offset += tuple_encoding.len();
                }
            }
            Value::FixedBytes(bytes) => {
                let mut to_copy = [0; 32];
                to_copy.copy_from_slice(bytes);
                copy_into(&mut ret, &to_copy, current_offset, 32)?;
            }
        }

        current_offset += static_offset_value(value);
    }

    Ok(ret)
}

fn write_u256(values: &mut [u8], number: U256, offset: usize) -> Result<(), CalldataEncodeError> {
    let to_copy = number.to_big_endian();
    copy_into(values, &to_copy, offset, 32)?;

    Ok(())
}

// Returns the size that the value occupies in the static sector of the abi encoding.
// For dynamic types, this is always 32 (the offset to the dynamic sector).
// For static types, it's 32 unless the value is a static tuple or a fixed array, in which case
// it's the sum of the sizes of their elements.
fn static_offset_value(value: &Value) -> usize {
    let mut ret = 0;

    match value {
        Value::Address(_)
        | Value::Uint(_)
        | Value::Int(_)
        | Value::Bool(_)
        | Value::Bytes(_)
        | Value::String(_)
        | Value::Array(_)
        | Value::FixedBytes(_) => ret += 32,
        Value::Tuple(vec) => {
            if is_dynamic(value) {
                ret += 32;
            } else {
                for element in vec {
                    // Here every element is guaranteed to be static, otherwise we would not be
                    // in the `else` branch of the `if` statement.
                    ret += static_offset_value(element);
                }
            }
        }
        Value::FixedArray(vec) => {
            if is_dynamic(value) {
                ret += 32;
            } else {
                for element in vec {
                    // Here every element is guaranteed to be static (and of the same type), otherwise we would not be
                    // in the `else` branch of the `if` statement.
                    ret += static_offset_value(element);
                }
            }
        }
    }

    ret
}

fn is_dynamic(value: &Value) -> bool {
    match value {
        Value::Bytes(_) | Value::String(_) | Value::Array(_) => true,
        Value::Tuple(vec) => vec.iter().any(is_dynamic),
        Value::FixedArray(vec) => {
            if let Some(first_elem) = vec.first() {
                is_dynamic(first_elem)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn encode_array(values: &[Value]) -> Result<Vec<u8>, CalldataEncodeError> {
    let mut ret = vec![];
    let to_copy = U256::from(values.len()).to_big_endian();
    ret.extend_from_slice(&to_copy);

    let tuple_encoding = encode_tuple(values)?;
    ret.extend_from_slice(&tuple_encoding);

    Ok(ret)
}

fn encode_bytes(values: &Bytes) -> Vec<u8> {
    let mut ret = vec![];

    // the bytes has to be padded to 32 bytes
    let padding = 32 - (values.len() % 32);
    let mut padded_bytes = values.to_vec();
    if padding != 32 {
        padded_bytes.extend_from_slice(&vec![0; padding]);
    }

    let to_copy = U256::from(values.len()).to_big_endian(); // we write the length without padding

    ret.extend_from_slice(&to_copy);
    ret.extend_from_slice(&padded_bytes);

    ret
}

fn copy_into(
    values: &mut [u8],
    to_copy: &[u8],
    offset: usize,
    size: usize,
) -> Result<(), CalldataEncodeError> {
    let to_copy_slice = to_copy
        .get(..size)
        .ok_or(CalldataEncodeError::InternalError)?;

    values
        .get_mut(offset..(size + offset))
        .ok_or(CalldataEncodeError::InternalError)?
        .copy_from_slice(to_copy_slice);

    Ok(())
}

fn address_to_word(address: Address) -> U256 {
    let mut word = [0u8; 32];
    for (word_byte, address_byte) in word.iter_mut().skip(12).zip(address.as_bytes().iter()) {
        *word_byte = *address_byte;
    }
    U256::from_big_endian(&word)
}

#[test]
fn calldata_test() {
    let raw_function_signature = "blockWithdrawalsLogs(uint256,bytes)";
    let mut bytes_calldata = vec![];

    bytes_calldata.extend_from_slice(&U256::zero().to_big_endian());
    bytes_calldata.extend_from_slice(&U256::one().to_big_endian());

    let arguments = vec![
        Value::Uint(U256::from(902)),
        Value::Bytes(bytes_calldata.into()),
    ];

    let calldata = encode_calldata(raw_function_signature, &arguments).unwrap();

    let decoded = decode_calldata(raw_function_signature, calldata.clone().into()).unwrap();
    assert_eq!(arguments, decoded);
    assert_eq!(
        calldata,
        vec![
            20, 108, 34, 199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 3, 134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]
    );
}

#[test]
fn raw_function_selector() {
    let raw_function_signature = "deposit((address,address,uint256,bytes))";

    let (name, params) = parse_signature(raw_function_signature).unwrap();
    let selector = compute_function_selector(&name, &params).unwrap();

    assert_eq!(selector, H32::from(&[0x02, 0xe8, 0x6b, 0xbe]));
}

#[test]
fn encode_tuple_dynamic_offset() {
    let raw_function_signature = "deposit((address,address,uint256,bytes))";
    let address = Address::from_low_u64_be(424242_u64);

    let tuple = Value::Tuple(vec![
        Value::Address(address),
        Value::Address(address),
        Value::Uint(U256::from(21000 * 5)),
        Value::Bytes(Bytes::from_static(b"")),
    ]);
    let values = vec![tuple];

    let calldata = encode_calldata(raw_function_signature, &values).unwrap();
    let decoded = decode_calldata(raw_function_signature, calldata.clone().into()).unwrap();
    assert_eq!(values, decoded);

    assert_eq!(calldata, hex::decode("02e86bbe0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000006793200000000000000000000000000000000000000000000000000000000000679320000000000000000000000000000000000000000000000000000000000019a2800000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000").unwrap());

    let mut encoding = vec![0x02, 0xe8, 0x6b, 0xbe]; // function selector
    encoding.extend_from_slice(&encode_tuple(&values).unwrap());

    assert_eq!(calldata, encoding);
}

#[test]
fn correct_tuple_parsing() {
    // the arguments are:
    // - uint256
    // - (uint256, address)
    // - ((address, address), (uint256, bytes))
    // - ((address, address), uint256)
    // - (uint256, (address, address))
    // - address
    let raw_function_signature = "my_function(uint256,(uin256,address),((address,address),(uint256,bytes)),((address,address),uint256),(uint256,(address,address)),address)";

    let exepected_arguments: Vec<String> = vec![
        "uint256".to_string(),
        "(uin256,address)".to_string(),
        "((address,address),(uint256,bytes))".to_string(),
        "((address,address),uint256)".to_string(),
        "(uint256,(address,address))".to_string(),
        "address".to_string(),
    ];
    let (name, params) = parse_signature(raw_function_signature).unwrap();
    assert_eq!(name, "my_function");
    assert_eq!(params, exepected_arguments);
}

#[test]
fn empty_calldata() {
    let calldata = encode_calldata("number()", &[]).unwrap();
    assert_eq!(calldata, hex::decode("8381f58a").unwrap());
    let decoded = decode_calldata("number()", calldata.clone().into()).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn bytes_has_padding() {
    let raw_function_signature = "my_function(bytes)";
    let bytes = Bytes::from_static(b"hello world");
    let values = vec![Value::Bytes(bytes)];

    let calldata = encode_calldata(raw_function_signature, &values).unwrap();

    assert_eq!(calldata, hex::decode("f570899b0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000b68656c6c6f20776f726c64000000000000000000000000000000000000000000").unwrap());
    let decoded = decode_calldata(raw_function_signature, calldata.clone().into()).unwrap();
    assert_eq!(values, decoded);
}
