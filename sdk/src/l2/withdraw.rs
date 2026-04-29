use std::time::Duration;

use ethrex_common::{Address, Bytes, U256, types::TxType};
use ethrex_l2_common::{
    calldata::Value, messages::L1MessageProof, utils::get_address_from_secret_key,
};
use ethrex_l2_rpc::signer::{LocalSigner, Signer};
use ethrex_rpc::{
    EthClient,
    clients::{EthClientError, Overrides},
};
use ethrex_sdk::{
    COMMON_BRIDGE_L2_ADDRESS, build_generic_tx, calldata::encode_calldata, send_generic_transaction,
};
use keccak_hash::H256;
use secp256k1::SecretKey;

use crate::l2::constants::{
    CLAIM_WITHDRAWAL_ERC20_SIGNATURE, L2_WITHDRAW_SIGNATURE, L2_WITHDRAW_SIGNATURE_ERC20,
};

pub async fn withdraw(
    amount: U256,
    from: Address,
    from_pk: SecretKey,
    proposer_client: &EthClient,
    nonce: Option<u64>,
) -> Result<H256, EthClientError> {
    let withdraw_transaction = build_generic_tx(
        proposer_client,
        TxType::EIP1559,
        COMMON_BRIDGE_L2_ADDRESS,
        from,
        Bytes::from(
            encode_calldata(L2_WITHDRAW_SIGNATURE, &[Value::Address(from)])
                .expect("Failed to encode calldata"),
        ),
        Overrides {
            value: Some(amount),
            nonce,
            ..Default::default()
        },
    )
    .await?;

    let signer = Signer::Local(LocalSigner::new(from_pk));

    send_generic_transaction(proposer_client, withdraw_transaction, &signer).await
}

pub async fn withdraw_erc20(
    amount: U256,
    from: Address,
    from_pk: SecretKey,
    token_l1: Address,
    token_l2: Address,
    l2_client: &EthClient,
) -> Result<H256, EthClientError> {
    let data = [
        Value::Address(token_l1),
        Value::Address(token_l2),
        Value::Address(from),
        Value::Uint(amount),
    ];
    let withdraw_data = encode_calldata(L2_WITHDRAW_SIGNATURE_ERC20, &data)
        .expect("Failed to encode calldata for withdraw ERC20");
    let withdraw_transaction = build_generic_tx(
        l2_client,
        TxType::EIP1559,
        COMMON_BRIDGE_L2_ADDRESS,
        from,
        Bytes::from(withdraw_data),
        Default::default(),
    )
    .await?;
    let signer = Signer::Local(LocalSigner::new(from_pk));
    send_generic_transaction(l2_client, withdraw_transaction, &signer).await
}

pub async fn claim_withdraw(
    amount: U256,
    from: Address,
    from_pk: SecretKey,
    eth_client: &EthClient,
    message_proof: &L1MessageProof,
    bridge_address: Address,
) -> Result<H256, EthClientError> {
    println!("Claiming {amount} from bridge to {from:#x}");

    const CLAIM_WITHDRAWAL_SIGNATURE: &str = "claimWithdrawal(uint256,uint256,uint256,bytes32[])";

    let calldata_values = vec![
        Value::Uint(amount),
        Value::Uint(message_proof.batch_number.into()),
        Value::Uint(message_proof.message_id),
        Value::Array(
            message_proof
                .merkle_proof
                .iter()
                .map(|hash| Value::FixedBytes(hash.as_fixed_bytes().to_vec().into()))
                .collect(),
        ),
    ];

    let claim_withdrawal_data = encode_calldata(CLAIM_WITHDRAWAL_SIGNATURE, &calldata_values)
        .expect("Failed to encode calldata for claim withdrawal");

    println!(
        "Claiming withdrawal with calldata: {}",
        hex::encode(&claim_withdrawal_data)
    );

    let claim_tx = build_generic_tx(
        eth_client,
        TxType::EIP1559,
        bridge_address,
        from,
        claim_withdrawal_data.into(),
        Overrides {
            from: Some(from),
            ..Default::default()
        },
    )
    .await?;
    let signer = Signer::Local(LocalSigner::new(from_pk));

    send_generic_transaction(eth_client, claim_tx, &signer).await
}

pub async fn claim_erc20withdraw(
    token_l1: Address,
    token_l2: Address,
    amount: U256,
    from_pk: SecretKey,
    eth_client: &EthClient,
    message_proof: &L1MessageProof,
    bridge_address: Address,
) -> Result<H256, EthClientError> {
    let from =
        get_address_from_secret_key(&from_pk.secret_bytes()).map_err(EthClientError::Custom)?;
    let calldata_values = vec![
        Value::Address(token_l1),
        Value::Address(token_l2),
        Value::Uint(amount),
        Value::Uint(U256::from(message_proof.batch_number)),
        Value::Uint(message_proof.message_id),
        Value::Array(
            message_proof
                .merkle_proof
                .clone()
                .into_iter()
                .map(|v| Value::FixedBytes(Bytes::copy_from_slice(v.as_bytes())))
                .collect(),
        ),
    ];

    let claim_withdrawal_data =
        encode_calldata(CLAIM_WITHDRAWAL_ERC20_SIGNATURE, &calldata_values)?;

    println!(
        "Claiming withdrawal with calldata: {}",
        hex::encode(&claim_withdrawal_data)
    );

    let claim_tx = build_generic_tx(
        eth_client,
        TxType::EIP1559,
        bridge_address,
        from,
        claim_withdrawal_data.into(),
        Overrides {
            from: Some(from),
            ..Default::default()
        },
    )
    .await?;

    let signer = Signer::Local(LocalSigner::new(from_pk));

    send_generic_transaction(eth_client, claim_tx, &signer).await
}

// Native rollup withdrawal support

fn deserialize_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    U256::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeWithdrawalProof {
    pub from: Address,
    pub receiver: Address,
    #[serde(deserialize_with = "deserialize_u256")]
    pub amount: U256,
    #[serde(deserialize_with = "deserialize_u256")]
    pub message_id: U256,
    #[serde(deserialize_with = "deserialize_u64")]
    pub block_number: u64,
    pub account_proof: Vec<String>,
    pub storage_proof: Vec<String>,
}

pub async fn get_native_withdrawal_proof(
    l2_rpc_url: &str,
    tx_hash: H256,
) -> Result<NativeWithdrawalProof, EthClientError> {
    #[derive(serde::Deserialize)]
    struct JsonRpcResponse {
        result: Option<NativeWithdrawalProof>,
        error: Option<JsonRpcError>,
    }

    #[derive(serde::Deserialize)]
    struct JsonRpcError {
        message: String,
    }

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ethrex_getNativeWithdrawalProof",
        "params": [format!("{tx_hash:#x}")],
        "id": 1
    });

    let max_retries: u32 = 60;
    let mut attempts: u32 = 0;

    loop {
        let response = client
            .post(l2_rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| EthClientError::Custom(e.to_string()))?;

        let rpc_response: JsonRpcResponse = response
            .json()
            .await
            .map_err(|e| EthClientError::Custom(e.to_string()))?;

        if let Some(error) = rpc_response.error {
            attempts = attempts.checked_add(1).unwrap_or(u32::MAX);
            if attempts >= max_retries {
                return Err(EthClientError::Custom(format!(
                    "Failed to get native withdrawal proof after {max_retries} attempts: {}",
                    error.message
                )));
            }
            println!(
                "Waiting for native withdrawal proof (attempt {attempts}/{max_retries})..."
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        return rpc_response.result.ok_or(EthClientError::Custom(
            "RPC response contained neither result nor error".to_owned(),
        ));
    }
}

pub async fn claim_native_withdraw(
    proof: &NativeWithdrawalProof,
    from_pk: SecretKey,
    eth_client: &EthClient,
    native_rollup_address: Address,
) -> Result<H256, EthClientError> {
    let from =
        get_address_from_secret_key(&from_pk.secret_bytes()).map_err(EthClientError::Custom)?;

    println!(
        "Claiming native withdrawal of {} to {:#x}",
        proof.amount, proof.receiver
    );

    const CLAIM_NATIVE_WITHDRAWAL_SIGNATURE: &str =
        "claimWithdrawal(address,address,uint256,uint256,uint256,bytes[],bytes[])";

    let account_proof: Vec<Value> = proof
        .account_proof
        .iter()
        .map(|s| {
            let hex_str = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(hex_str)
                .map(|bytes| Value::Bytes(Bytes::from(bytes)))
                .map_err(|e| EthClientError::Custom(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let storage_proof: Vec<Value> = proof
        .storage_proof
        .iter()
        .map(|s| {
            let hex_str = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(hex_str)
                .map(|bytes| Value::Bytes(Bytes::from(bytes)))
                .map_err(|e| EthClientError::Custom(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let calldata_values = vec![
        Value::Address(proof.from),
        Value::Address(proof.receiver),
        Value::Uint(proof.amount),
        Value::Uint(proof.message_id),
        Value::Uint(U256::from(proof.block_number)),
        Value::Array(account_proof),
        Value::Array(storage_proof),
    ];

    let calldata = encode_calldata(CLAIM_NATIVE_WITHDRAWAL_SIGNATURE, &calldata_values)?;

    let claim_tx = build_generic_tx(
        eth_client,
        TxType::EIP1559,
        native_rollup_address,
        from,
        calldata.into(),
        Overrides {
            from: Some(from),
            ..Default::default()
        },
    )
    .await?;

    let signer = Signer::Local(LocalSigner::new(from_pk));
    send_generic_transaction(eth_client, claim_tx, &signer).await
}
