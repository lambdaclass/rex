use crate::calldata::{Value, encode_calldata};
use crate::client::Overrides;
use crate::l2::l1_to_l2_tx_data::{L1ToL2TransactionData, send_l1_to_l2_tx};

use crate::{
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
