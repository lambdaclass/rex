use crate::l2::l1_to_l2_tx_data::{L1ToL2TransactionData, send_l1_to_l2_tx};
use crate::{bridge_address, get_address_from_secret_key};
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
    eth_client: &EthClient,
) -> Result<H256, EthClientError> {
    println!("Depositing {amount} from {from:#x} to bridge");
    transfer(
        amount,
        from,
        bridge_address().map_err(|err| EthClientError::Custom(err.to_string()))?,
        from_pk,
        eth_client,
    )
    .await
}

pub async fn deposit_through_contract_call(
    amount: impl Into<U256>,
    to: Address,
    l1_gas_limit: u64,
    l2_gas_limit: u64,
    depositor_private_key: &SecretKey,
    bridge_address: Address,
    eth_client: &EthClient,
) -> Result<H256, EthClientError> {
    let l1_from = get_address_from_secret_key(depositor_private_key)?;
    send_l1_to_l2_tx(
        l1_from,
        Some(amount),
        Some(l1_gas_limit),
        L1ToL2TransactionData::new_deposit_data(to, l2_gas_limit),
        depositor_private_key,
        bridge_address,
        eth_client,
    )
    .await
}
