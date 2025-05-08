use ethrex_common::{Bytes, U256};
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
