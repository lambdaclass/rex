use ethrex_common::{Bytes, H256, U256};
use hex::FromHexError;
use secp256k1::SecretKey;
use std::str::FromStr;

use crate::common::{AddressOpts, HashOpts};

pub fn parse_private_key(s: &str) -> eyre::Result<SecretKey> {
    Ok(SecretKey::from_slice(&parse_hex(s)?)?)
}

pub fn parse_message(s: &str) -> eyre::Result<secp256k1::Message> {
    let parsed = secp256k1::Message::from_digest(*parse_h256(s)?.as_fixed_bytes());
    Ok(parsed)
}

pub fn parse_h256(s: &str) -> eyre::Result<H256> {
    let parsed = H256::from_slice(&parse_hex(s)?);
    Ok(parsed)
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

pub fn parse_hash_opts(s: &str) -> eyre::Result<HashOpts> {
    HashOpts::try_from(s)
}

pub fn parse_address_opts(s: &str) -> eyre::Result<AddressOpts> {
    AddressOpts::try_from(s)
}
