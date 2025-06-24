use crate::bridge_address;
use crate::{
    calldata::{Value, encode_calldata},
    client::{EthClient, EthClientError, Overrides},
    l2::{
        constants::{COMMON_BRIDGE_L2_ADDRESS, L2_WITHDRAW_SIGNATURE},
        merkle_tree::merkle_proof,
    },
};
use ethrex_common::{
    Address, Bytes, H256, U256,
    types::{Transaction, TxKind},
};
use ethrex_rpc::clients::eth::WithdrawalProof;
use ethrex_rpc::types::block::BlockBodyWrapper;
use itertools::Itertools;
use secp256k1::SecretKey;

pub async fn withdraw(
    amount: U256,
    from: Address,
    from_pk: SecretKey,
    proposer_client: &EthClient,
) -> Result<H256, EthClientError> {
    let withdraw_transaction = proposer_client
        .build_eip1559_transaction(
            COMMON_BRIDGE_L2_ADDRESS,
            from,
            Bytes::from(encode_calldata(
                L2_WITHDRAW_SIGNATURE,
                &[Value::Address(from)],
            )?),
            Overrides {
                value: Some(amount),
                ..Default::default()
            },
        )
        .await?;

    proposer_client
        .send_eip1559_transaction(&withdraw_transaction, &from_pk)
        .await
}

pub async fn claim_withdraw(
    amount: U256,
    l2_withdrawal_tx_hash: H256,
    from: Address,
    from_pk: SecretKey,
    eth_client: &EthClient,
    withdrawal_proof: &WithdrawalProof,
) -> Result<H256, EthClientError> {
    println!("Claiming {amount} from bridge to {from:#x}");

    const CLAIM_WITHDRAWAL_SIGNATURE: &str =
        "claimWithdrawal(bytes32,uint256,uint256,uint256,bytes32[])";

    let calldata_values = vec![
        Value::Uint(U256::from_big_endian(
            l2_withdrawal_tx_hash.as_fixed_bytes(),
        )),
        Value::Uint(amount),
        Value::Uint(withdrawal_proof.batch_number.into()),
        Value::Uint(U256::from(withdrawal_proof.index)),
        Value::Array(
            withdrawal_proof
                .merkle_proof
                .iter()
                .map(|hash| Value::FixedBytes(hash.as_fixed_bytes().to_vec().into()))
                .collect(),
        ),
    ];

    let claim_withdrawal_data = encode_calldata(CLAIM_WITHDRAWAL_SIGNATURE, &calldata_values)?;

    println!(
        "Claiming withdrawal with calldata: {}",
        hex::encode(&claim_withdrawal_data)
    );

    let claim_tx = eth_client
        .build_eip1559_transaction(
            bridge_address().map_err(|err| EthClientError::Custom(err.to_string()))?,
            from,
            claim_withdrawal_data.into(),
            Overrides {
                from: Some(from),
                ..Default::default()
            },
        )
        .await?;

    eth_client
        .send_eip1559_transaction(&claim_tx, &from_pk)
        .await
}

/// Returns the formated hash of the withdrawal transaction,
/// or None if the transaction is not a withdrawal.
/// The hash is computed as keccak256(to || value || tx_hash)
pub fn get_withdrawal_hash(tx: &Transaction) -> Option<H256> {
    let to_bytes: [u8; 20] = match tx.data().get(16..36)?.try_into() {
        Ok(value) => value,
        Err(_) => return None,
    };
    let to = Address::from(to_bytes);

    let value = tx.value().to_big_endian();

    Some(keccak_hash::keccak(
        [to.as_bytes(), &value, tx.compute_hash().as_bytes()].concat(),
    ))
}

pub async fn get_withdraw_merkle_proof(
    client: &EthClient,
    tx_hash: H256,
) -> Result<(u64, Vec<H256>), EthClientError> {
    let tx_receipt =
        client
            .get_transaction_receipt(tx_hash)
            .await?
            .ok_or(EthClientError::Custom(
                "Failed to get transaction receipt".to_string(),
            ))?;

    let block = client
        .get_block_by_hash(tx_receipt.block_info.block_hash)
        .await?;

    let transactions = match block.body {
        BlockBodyWrapper::Full(body) => body.transactions,
        BlockBodyWrapper::OnlyHashes(_) => unreachable!(),
    };
    let Some(Some((index, tx_withdrawal_hash))) = transactions
        .iter()
        .filter(|tx| match &tx.tx.to() {
            ethrex_common::types::TxKind::Call(to) => *to == COMMON_BRIDGE_L2_ADDRESS,
            ethrex_common::types::TxKind::Create => false,
        })
        .find_position(|tx| tx.hash == tx_hash)
        .map(|(i, tx)| get_withdrawal_hash(&tx.tx).map(|withdrawal_hash| (i, (withdrawal_hash))))
    else {
        return Err(EthClientError::Custom(
            "Failed to get widthdrawal hash, transaction is not a withdrawal".to_string(),
        ));
    };

    let path = merkle_proof(
        transactions
            .iter()
            .filter_map(|tx| match tx.tx.to() {
                TxKind::Call(to) if to == COMMON_BRIDGE_L2_ADDRESS => get_withdrawal_hash(&tx.tx),
                _ => None,
            })
            .collect(),
        tx_withdrawal_hash,
    )
    .map_err(|err| EthClientError::Custom(format!("Failed to generate merkle proof: {err}")))?
    .ok_or(EthClientError::Custom(
        "Failed to generate merkle proof, element is not on the tree".to_string(),
    ))?;

    Ok((
        index
            .try_into()
            .map_err(|err| EthClientError::Custom(format!("index does not fit in u64: {}", err)))?,
        path,
    ))
}
