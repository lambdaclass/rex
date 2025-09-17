use crate::transfer;
use ethrex_common::{Address, U256, types::TxType};
use ethrex_l2_common::calldata::Value;
use ethrex_l2_rpc::{
    clients::send_generic_transaction,
    signer::{LocalSigner, Signer},
};
use ethrex_rpc::{
    EthClient,
    clients::{EthClientError, Overrides},
};
use ethrex_sdk::{calldata::encode_calldata, get_address_from_secret_key};
use keccak_hash::H256;
use secp256k1::SecretKey;

const DEPOSIT_ERC20_SIGNATURE: &str = "depositERC20(address,address,address,uint256)";

pub async fn deposit_through_transfer(
    amount: U256,
    from: Address,
    from_pk: &SecretKey,
    bridge_address: Address,
    eth_client: &EthClient,
) -> Result<H256, EthClientError> {
    transfer(amount, from, bridge_address, from_pk, eth_client).await
}

pub async fn deposit_through_contract_call(
    amount: U256,
    to: Address,
    depositor_private_key: &SecretKey,
    bridge_address: Address,
    eth_client: &EthClient,
) -> Result<H256, EthClientError> {
    let l1_from = get_address_from_secret_key(depositor_private_key)?;
    let calldata = encode_calldata("deposit(address)", &[Value::Address(to)])?;
    let gas_price = eth_client
        .get_gas_price_with_extra(20)
        .await?
        .try_into()
        .map_err(|_| {
            EthClientError::InternalError("Failed to convert gas_price to a u64".to_owned())
        })?;

    let deposit_tx = eth_client
        .build_generic_tx(
            TxType::EIP1559,
            bridge_address,
            l1_from,
            calldata.into(),
            Overrides {
                from: Some(l1_from),
                value: Some(amount),
                max_fee_per_gas: Some(gas_price),
                max_priority_fee_per_gas: Some(gas_price),
                ..Default::default()
            },
        )
        .await?;

    let signer = Signer::Local(LocalSigner::new(*depositor_private_key));

    send_generic_transaction(eth_client, deposit_tx, &signer).await
}

pub async fn deposit_erc20(
    token_l1: Address,
    token_l2: Address,
    amount: U256,
    from: Address,
    from_pk: SecretKey,
    eth_client: &EthClient,
    bridge_address: Address,
) -> Result<H256, EthClientError> {
    println!(
        "Depositing {amount} from {from:#x} to token L2: {token_l2:#x} via L1 token: {token_l1:#x}"
    );

    let calldata_values = vec![
        Value::Address(token_l1),
        Value::Address(token_l2),
        Value::Address(from),
        Value::Uint(amount),
    ];

    let deposit_data = encode_calldata(DEPOSIT_ERC20_SIGNATURE, &calldata_values)?;

    let deposit_tx = eth_client
        .build_generic_tx(
            TxType::EIP1559,
            bridge_address,
            from,
            deposit_data.into(),
            Overrides {
                from: Some(from),
                ..Default::default()
            },
        )
        .await?;

    let signer = Signer::Local(LocalSigner::new(from_pk));

    send_generic_transaction(eth_client, deposit_tx, &signer).await
}
