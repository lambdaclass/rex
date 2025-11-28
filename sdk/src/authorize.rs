use ethrex_common::{Address, U256, types::AuthorizationTuple};
use ethrex_l2_common::utils::get_address_from_secret_key;
use ethrex_rlp::encode::RLPEncode;
use ethrex_rpc::{
    EthClient,
    clients::EthClientError,
    types::block_identifier::{BlockIdentifier, BlockTag},
};
use keccak_hash::keccak;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{Message, Secp256k1, SecretKey};

// MAGIC is 0x05 (crates/vm/levm/src/constants.rs)
const MAGIC: u8 = 0x05;

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

pub async fn build_authorization_tuple(
    client: &EthClient,
    delegated_address: Address,
    private_key: &SecretKey,
    chain_id: Option<u64>,
    nonce: Option<u64>,
) -> Result<AuthorizationTuple, EthClientError> {
    let chain_id = match chain_id {
        Some(id) => id,
        None => client.get_chain_id().await?.as_u64(),
    };

    let from = get_address_from_secret_key(&private_key.secret_bytes())
        .map_err(|e| EthClientError::Custom(e.to_string()))?;

    let nonce = match nonce {
        Some(nonce) => nonce,
        None => {
            client
                .get_nonce(from, BlockIdentifier::Tag(BlockTag::Latest))
                .await?
        }
    };

    Ok(make_auth_tuple(
        private_key,
        chain_id,
        delegated_address,
        nonce,
    ))
}
