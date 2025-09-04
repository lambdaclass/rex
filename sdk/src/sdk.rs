use ethrex_common::{Address, U256, types::TxType};
use ethrex_l2_common::calldata::Value;
use ethrex_l2_rpc::{
    clients::send_generic_transaction,
    signer::{LocalSigner, Signer},
};

use ethrex_rpc::{
    EthClient,
    clients::{EthClientError, Overrides},
    types::receipt::RpcReceipt,
};
use ethrex_sdk::{calldata::encode_calldata, get_address_from_secret_key};
use keccak_hash::H256;
use secp256k1::SecretKey;

pub mod client;
pub mod create;
pub mod errors;
pub mod keystore;
pub mod sign;
pub mod utils;

pub mod l2;

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("Failed to parse address from hex")]
    FailedToParseAddressFromHex,
    #[error("Failed deserializing log: {0}")]
    FailedToDeserializeLog(String),
}

pub async fn transfer(
    amount: U256,
    from: Address,
    to: Address,
    private_key: &SecretKey,
    client: &EthClient,
) -> Result<H256, EthClientError> {
    let gas_price = client
        .get_gas_price_with_extra(20)
        .await?
        .try_into()
        .map_err(|_| {
            EthClientError::InternalError("Failed to convert gas_price to a u64".to_owned())
        })?;

    let tx = client
        .build_generic_tx(
            TxType::EIP1559,
            to,
            from,
            Default::default(),
            Overrides {
                value: Some(amount),
                max_fee_per_gas: Some(gas_price),
                max_priority_fee_per_gas: Some(gas_price),
                ..Default::default()
            },
        )
        .await?;

    let signer = LocalSigner::new(*private_key).into();
    send_generic_transaction(client, tx, &signer).await
}

pub async fn wait_for_transaction_receipt(
    tx_hash: H256,
    client: &EthClient,
    max_retries: u64,
    silent: bool,
) -> Result<RpcReceipt, EthClientError> {
    let mut receipt = client.get_transaction_receipt(tx_hash).await?;
    let mut r#try = 1;
    while receipt.is_none() {
        if !silent {
            println!("[{try}/{max_retries}] Retrying to get transaction receipt for {tx_hash:#x}");
        }

        if max_retries == r#try {
            return Err(EthClientError::Custom(format!(
                "Transaction receipt for {tx_hash:#x} not found after {max_retries} retries"
            )));
        }
        r#try += 1;

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        receipt = client.get_transaction_receipt(tx_hash).await?;
    }
    receipt.ok_or(EthClientError::Custom(
        "Transaction receipt is None".to_owned(),
    ))
}

pub fn balance_in_eth(eth: bool, balance: U256) -> String {
    if eth {
        let mut balance = format!("{balance}");
        let len = balance.len();

        balance = match len {
            18 => {
                let mut front = "0.".to_owned();
                front.push_str(&balance);
                front
            }
            0..=17 => {
                let mut front = "0.".to_owned();
                let zeros = "0".repeat(18 - len);
                front.push_str(&zeros);
                front.push_str(&balance);
                front
            }
            19.. => {
                balance.insert(len - 18, '.');
                balance
            }
        };
        balance
    } else {
        format!("{balance}")
    }
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

#[test]
fn test_balance_in_ether() {
    // test more than 1 ether
    assert_eq!(
        "999999999.999003869993631450",
        balance_in_eth(
            true,
            U256::from_dec_str("999999999999003869993631450").unwrap()
        )
    );

    // test 0.5
    assert_eq!(
        "0.509003869993631450",
        balance_in_eth(
            true,
            U256::from_dec_str("000000000509003869993631450").unwrap()
        )
    );

    // test 0.005
    assert_eq!(
        "0.005090038699936314",
        balance_in_eth(
            true,
            U256::from_dec_str("000000000005090038699936314").unwrap()
        )
    );

    // test 0.0
    assert_eq!("0.000000000000000000", balance_in_eth(true, U256::zero()));
}
