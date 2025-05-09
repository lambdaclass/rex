use ethrex_common::{Address, Bytes, U256};
use hex::FromHexError;
use rex_sdk::calldata::{Value, encode_calldata, encode_tuple, parse_signature};
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
            "bytes" => Value::Bytes(hex::decode(val)?.into()),
            _ if param.starts_with("bytes") => Value::FixedBytes(hex::decode(val)?.into()),
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
