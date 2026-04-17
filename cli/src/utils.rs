use ethrex_common::{Address, Bytes, U256};
use ethrex_l2_common::calldata::Value;
use ethrex_sdk::calldata::{encode_calldata, encode_tuple, parse_signature};
use hex::FromHexError;
use secp256k1::SecretKey;
use std::str::FromStr;

pub fn parse_private_key(s: &str) -> eyre::Result<SecretKey> {
    Ok(SecretKey::from_slice(&parse_hex(s)?)?)
}

pub fn parse_u256(s: &str) -> eyre::Result<U256> {
    let parsed = if s.starts_with("0x") {
        U256::from_str(s)?
    } else {
        U256::from_dec_str(s)?
    };
    Ok(parsed)
}

pub fn parse_hex(s: &str) -> eyre::Result<Bytes, FromHexError> {
    match s.strip_prefix("0x") {
        Some(s) => hex::decode(s).map(Into::into),
        None => hex::decode(s).map(Into::into),
    }
}

/// Parses a hex string, stripping the "0x" prefix if present.
/// Unlike `parse_hex`, the string doesn't need to be of even length.
pub fn parse_hex_string(s: &str) -> eyre::Result<String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(s.to_string())
    } else {
        Err(eyre::eyre!("Invalid hex string"))
    }
}

fn parse_call_args(args: Vec<String>) -> eyre::Result<Option<(String, Vec<Value>)>> {
    let mut args_iter = args.iter();
    let Some(signature) = args_iter.next() else {
        return Ok(None);
    };
    let (_, params) = parse_signature(signature)?;
    let mut values = Vec::new();
    for param in params {
        let val = args_iter
            .next()
            .ok_or(eyre::Error::msg("missing parameter for given signature"))?;
        values.push(match param.as_str() {
            // Array types must be checked first (before scalar uint/int)
            _ if param.contains('[') && param.contains(']') => {
                // Handle fixed-size arrays like uint64[3]
                let base_type = param.split('[').next().unwrap_or("");
                let inner = val.trim_start_matches('[').trim_end_matches(']');
                let elements: Vec<Value> = inner
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        if base_type.starts_with("uint") || base_type.starts_with("int") {
                            Ok(Value::Uint(U256::from_dec_str(s)?))
                        } else if base_type == "address" {
                            Ok(Value::Address(Address::from_str(s)?))
                        } else {
                            Err(eyre::eyre!("Unsupported array element type: {}", base_type))
                        }
                    })
                    .collect::<eyre::Result<Vec<_>>>()?;
                Value::FixedArray(elements)
            }
            "address" => Value::Address(Address::from_str(val)?),
            _ if param.starts_with("uint") => Value::Uint(U256::from_dec_str(val)?),
            _ if param.starts_with("int") => {
                if let Some(val) = val.strip_prefix("-") {
                    let x = U256::from_str(val)?;
                    if x.is_zero() {
                        Value::Uint(x)
                    } else {
                        Value::Uint(U256::max_value() - x + 1)
                    }
                } else {
                    Value::Uint(U256::from_dec_str(val)?)
                }
            }
            "bool" => match val.as_str() {
                "true" => Value::Uint(U256::from(1)),
                "false" => Value::Uint(U256::from(0)),
                _ => Err(eyre::Error::msg("Invalid boolean"))?,
            },
            "bytes" => {
                let val = val.strip_prefix("0x").unwrap_or(val);
                Value::Bytes(hex::decode(val)?.into())
            }
            _ if param.starts_with("bytes") => {
                let val = val.strip_prefix("0x").unwrap_or(val);
                Value::FixedBytes(hex::decode(val)?.into())
            }
            _ => todo!("type unsupported"),
        });
    }
    Ok(Some((signature.to_string(), values)))
}

pub fn parse_func_call(args: Vec<String>) -> eyre::Result<Bytes> {
    let Some((signature, values)) = parse_call_args(args)? else {
        return Ok(Bytes::new());
    };
    Ok(encode_calldata(&signature, &values)?.into())
}

pub fn parse_contract_creation(args: Vec<String>) -> eyre::Result<Bytes> {
    let Some((_signature, values)) = parse_call_args(args)? else {
        return Ok(Bytes::new());
    };
    Ok(encode_tuple(&values)?.into())
}

/// Parse a single typed-prefix constructor argument like `address:0x…`,
/// `uint256:100`, `bool:true`, `string:hi`, `bytes32:0xdead…`, or
/// `uint256[]:[1,2,3]`. Types mirror Solidity ABI names.
pub fn parse_typed_value(arg: &str) -> eyre::Result<Value> {
    let (ty, val) = arg
        .split_once(':')
        .ok_or_else(|| eyre::eyre!("constructor arg must be 'type:value' (got '{arg}')"))?;
    let ty = ty.trim();
    let val = val.trim();

    if let Some(inner_ty) = array_inner_type(ty) {
        let list = val.trim_start_matches('[').trim_end_matches(']');
        let elements = list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| parse_typed_value(&format!("{inner_ty}:{s}")))
            .collect::<eyre::Result<Vec<_>>>()?;
        return Ok(if ty.ends_with("[]") {
            Value::Array(elements)
        } else {
            Value::FixedArray(elements)
        });
    }

    Ok(match ty {
        "address" => Value::Address(Address::from_str(val)?),
        "bool" => match val {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => return Err(eyre::eyre!("invalid bool value '{val}'")),
        },
        "string" => Value::String(val.to_owned()),
        "bytes" => {
            let stripped = val.strip_prefix("0x").unwrap_or(val);
            Value::Bytes(hex::decode(stripped)?.into())
        }
        _ if ty.starts_with("bytes") => {
            let stripped = val.strip_prefix("0x").unwrap_or(val);
            Value::FixedBytes(hex::decode(stripped)?.into())
        }
        _ if ty.starts_with("uint") => Value::Uint(parse_uint_value(val)?),
        _ if ty.starts_with("int") => {
            if let Some(rest) = val.strip_prefix('-') {
                let x = parse_uint_value(rest)?;
                if x.is_zero() {
                    Value::Uint(x)
                } else {
                    Value::Uint(U256::max_value() - x + 1)
                }
            } else {
                Value::Uint(parse_uint_value(val)?)
            }
        }
        _ => return Err(eyre::eyre!("unsupported constructor arg type '{ty}'")),
    })
}

fn array_inner_type(ty: &str) -> Option<&str> {
    let open = ty.rfind('[')?;
    let close = ty.rfind(']')?;
    if close != ty.len() - 1 || open >= close {
        return None;
    }
    Some(&ty[..open])
}

fn parse_uint_value(s: &str) -> eyre::Result<U256> {
    if let Some(rest) = s.strip_prefix("0x") {
        Ok(U256::from_str(&format!("0x{rest}"))?)
    } else {
        Ok(U256::from_dec_str(s)?)
    }
}

pub fn encode_constructor_args(args: &[String]) -> eyre::Result<Bytes> {
    if args.is_empty() {
        return Ok(Bytes::new());
    }
    let values: Vec<Value> = args
        .iter()
        .map(|a| parse_typed_value(a))
        .collect::<eyre::Result<_>>()?;
    Ok(encode_tuple(&values)?.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typed_scalars() {
        let v = parse_typed_value("uint256:100").unwrap();
        assert!(matches!(v, Value::Uint(x) if x == U256::from(100u64)));

        let v = parse_typed_value("bool:true").unwrap();
        assert!(matches!(v, Value::Bool(true)));

        let v = parse_typed_value("string:hello").unwrap();
        assert!(matches!(v, Value::String(s) if s == "hello"));
    }

    #[test]
    fn parses_typed_address() {
        let v =
            parse_typed_value("address:0x8943545177806ed17b9f23f0a21ee5948ecaa776").unwrap();
        assert!(matches!(v, Value::Address(_)));
    }

    #[test]
    fn parses_typed_array() {
        let v = parse_typed_value("uint256[]:[1,2,3]").unwrap();
        match v {
            Value::Array(vs) => assert_eq!(vs.len(), 3),
            _ => panic!("expected Array"),
        }
    }

    #[test]
    fn encodes_empty_args_to_empty_bytes() {
        let b = encode_constructor_args(&[]).unwrap();
        assert!(b.is_empty());
    }

    #[test]
    fn encodes_single_address_matches_abi() {
        // abi.encode(address) is 32 bytes left-padded.
        let addr = "0x8943545177806ed17b9f23f0a21ee5948ecaa776";
        let encoded =
            encode_constructor_args(&[format!("address:{addr}")]).unwrap();
        assert_eq!(encoded.len(), 32);
        let expected_suffix = hex::decode(&addr[2..]).unwrap();
        assert_eq!(&encoded[12..], expected_suffix.as_slice());
    }
}
