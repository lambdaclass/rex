use ethrex_common::types::AuthorizationTuple;
use ethrex_common::{Address, H256, U256};
use ethrex_rlp::encode::RLPEncode;
use keccak_hash::keccak;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
const MAGIC: u8 = 0x05;

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

pub fn make_auth_tuple(
    signing_key: &SecretKey,
    chain_id: u64,
    delegated_code_addr: Address,
    nonce: u64,
) -> AuthorizationTuple {
    // keccak256(MAGIC || rlp([chain_id, address, nonce]))
    let mut buf = Vec::with_capacity(1 + 128);
    buf.push(MAGIC);
    (U256::from(chain_id), delegated_code_addr, nonce).encode(&mut buf);
    let digest = keccak(&buf);
    let msg = Message::from_digest(digest.into());

    let secp = Secp256k1::new();
    let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, signing_key);
    let (rec_id, sig_bytes) = sig.serialize_compact();

    let r_signature = U256::from_big_endian(&sig_bytes[0..32]);
    let s_signature = U256::from_big_endian(&sig_bytes[32..64]);
    let y_parity = U256::from(Into::<i32>::into(rec_id));

    AuthorizationTuple {
        chain_id: U256::from(chain_id),
        address: delegated_code_addr,
        nonce,
        y_parity,
        r_signature,
        s_signature,
    }
}
