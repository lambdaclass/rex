use crate::{
    client::{EthClient, EthClientError},
    transfer,
};
use ethrex_common::{Address, H256, U256};
use secp256k1::SecretKey;

pub async fn deposit_through_transfer(
    amount: U256,
    from: Address,
    from_pk: &SecretKey,
    bridge_address: Address,
    eth_client: &EthClient,
) -> Result<H256, EthClientError> {
    transfer(amount, from, bridge_address, from_pk, eth_client).await
}
