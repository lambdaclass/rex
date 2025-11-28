use ethrex_common::{Address, types::AuthorizationTuple};
use ethrex_l2_common::utils::get_address_from_secret_key;
use ethrex_rpc::{
    EthClient,
    clients::EthClientError,
    types::block_identifier::{BlockIdentifier, BlockTag},
};
use secp256k1::SecretKey;

use crate::utils::make_auth_tuple;

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
