use ethrex_common::{Address, H160, H256, U256};
use ethrex_rpc::types::receipt::RpcLogInfo;

use crate::SdkError;

// Duplicated from https://github.com/lambdaclass/ethrex/blob/c673d17568fdb044dce05513ecb17ec6db431e3f/crates/l2/sequencer/l1_watcher.rs#L303
pub struct PrivilegedTransactionData {
    pub value: U256,
    pub to_address: H160,
    pub transaction_id: U256,
    pub from: H160,
    pub gas_limit: U256,
    pub calldata: Vec<u8>,
}

impl PrivilegedTransactionData {
    pub fn from_log(log: RpcLogInfo) -> Result<PrivilegedTransactionData, SdkError> {
        let from =
            H256::from_slice(log.data.get(0..32).ok_or(SdkError::FailedToDeserializeLog(
                "Failed to parse gas_limit from log: log.data[0..32] out of bounds".to_owned(),
            ))?);
        let from_address = hash_to_address(from);

        let to = H256::from_slice(
            log.data
                .get(32..64)
                .ok_or(SdkError::FailedToDeserializeLog(
                    "Failed to parse gas_limit from log: log.data[32..64] out of bounds".to_owned(),
                ))?,
        );
        let to_address = hash_to_address(to);

        let transaction_id = U256::from_big_endian(log.data.get(64..96).ok_or(
            SdkError::FailedToDeserializeLog(
                "Failed to parse gas_limit from log: log.data[64..96] out of bounds".to_owned(),
            ),
        )?);

        let value = U256::from_big_endian(log.data.get(96..128).ok_or(
            SdkError::FailedToDeserializeLog(
                "Failed to parse gas_limit from log: log.data[96..128] out of bounds".to_owned(),
            ),
        )?);

        let gas_limit = U256::from_big_endian(log.data.get(128..160).ok_or(
            SdkError::FailedToDeserializeLog(
                "Failed to parse gas_limit from log: log.data[128..160] out of bounds".to_owned(),
            ),
        )?);

        // 160..192 is taken by offset_data, which we do not need

        let calldata_len = U256::from_big_endian(
            log.data
                .get(192..224)
                .ok_or(SdkError::FailedToDeserializeLog(
                    "Failed to parse calldata_len from log: log.data[192..224] out of bounds"
                        .to_owned(),
                ))?,
        );

        let calldata = log
            .data
            .get(224..224 + calldata_len.as_usize())
            .ok_or(SdkError::FailedToDeserializeLog(
            "Failed to parse calldata from log: log.data[224..224 + calldata_len] out of bounds"
                .to_owned(),
        ))?;

        Ok(Self {
            value,
            to_address,
            transaction_id,
            from: from_address,
            gas_limit,
            calldata: calldata.to_vec(),
        })
    }
}

pub fn hash_to_address(hash: H256) -> Address {
    Address::from_slice(&hash.as_fixed_bytes()[12..])
}
