use ethrex_common::{Address, Bytes, U256, types::TxType};
use ethrex_l2_common::{
    calldata::Value, l1_messages::L1MessageProof, utils::get_address_from_secret_key,
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
