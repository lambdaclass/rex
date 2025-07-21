use crate::calldata::{Value, encode_calldata};
use crate::client::Overrides;
use crate::{
    client::eth::get_address_from_secret_key,
    client::{EthClient, EthClientError},
    transfer,
};
use ethrex_common::{Address, H256, U256};
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
    l1_gas_limit: u64,
    depositor_private_key: &SecretKey,
    bridge_address: Address,
    eth_client: &EthClient,
) -> Result<H256, EthClientError> {
    let l1_from = get_address_from_secret_key(depositor_private_key)?;
    let calldata = encode_calldata("deposit(address)", &[Value::Address(to)])?;

    let deposit_tx = eth_client
        .build_eip1559_transaction(
            bridge_address,
            l1_from,
            calldata.into(),
            Overrides {
                from: Some(l1_from),
                value: Some(amount),
                gas_limit: Some(l1_gas_limit),
                ..Default::default()
            },
        )
        .await?;

    eth_client
        .send_eip1559_transaction(&deposit_tx, depositor_private_key)
        .await
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
        .build_eip1559_transaction(
            bridge_address,
            from,
            deposit_data.into(),
            Overrides {
                from: Some(from),
                ..Default::default()
            },
        )
        .await?;

    eth_client
        .send_eip1559_transaction(&deposit_tx, &from_pk)
        .await
}
