use ethrex_common::H256;
use keccak_hash::keccak;
use secp256k1::SecretKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn secret_key_deserializer<'de, D>(deserializer: D) -> Result<SecretKey, D::Error>
where
    D: Deserializer<'de>,
{
    let hex = H256::deserialize(deserializer)?;
    SecretKey::from_slice(hex.as_bytes()).map_err(serde::de::Error::custom)
}

pub fn secret_key_serializer<S>(secret_key: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex = H256::from_slice(&secret_key.secret_bytes());
    hex.serialize(serializer)
}

/// EIP-55 Checksum Address.
/// This is how addresses are actually displayed on ethereum apps
/// Returns address as string without "0x" prefix
pub fn to_checksum_address(address: &str) -> String {
    // Trim if necessary
    let addr = address.trim_start_matches("0x").to_lowercase();

    // Hash the raw address using Keccak-256
    let hash = keccak(&addr);

    // Convert hash to hex string
    let hash_hex = hex::encode(hash);

    // Apply checksum by walking each nibble
    let mut checksummed = String::with_capacity(40);

    for (i, c) in addr.chars().enumerate() {
        let hash_char = hash_hex.chars().nth(i).unwrap();
        let hash_value = hash_char.to_digit(16).unwrap();

        if c.is_ascii_alphabetic() && hash_value >= 8 {
            checksummed.push(c.to_ascii_uppercase());
        } else {
            checksummed.push(c);
        }
    }

    checksummed
}
