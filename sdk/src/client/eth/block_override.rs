//! Block override set for `eth_call` / `eth_estimateGas`.
//!
//! JSON-RPC shape matches geth's Block Override Set
//! (<https://geth.ethereum.org/docs/interacting-with-geth/rpc/objects#block-overrides>),
//! also supported by ethrex as of PR lambdaclass/ethrex#6660. Field names follow
//! the spelling ethrex and reth/alloy accept (`coinbase`, `random`,
//! `blobBaseFeePerGas`); recent geth renamed those to `feeRecipient`,
//! `prevRandao` and `blobBaseFee`.

use ethrex_common::{Address, H256, U256};
use serde_json::{Value, json};

/// Block override set: each field, when present, replaces the corresponding
/// header field of the block the call is simulated against. Omitted fields keep
/// the real header values.
///
/// Serializes to the JSON shape expected as the 4th parameter of `eth_call`:
///
/// ```json
/// {
///   "number": "0x1234",
///   "time": "0x665f0d00",
///   "coinbase": "0xabc..."
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct BlockOverrideSet {
    pub number: Option<u64>,
    pub time: Option<u64>,
    pub gas_limit: Option<u64>,
    pub coinbase: Option<Address>,
    /// Override for PREVRANDAO.
    pub random: Option<H256>,
    pub base_fee_per_gas: Option<u64>,
    pub blob_base_fee_per_gas: Option<U256>,
    /// No-op on post-merge blocks.
    pub difficulty: Option<U256>,
}

impl BlockOverrideSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.number.is_none()
            && self.time.is_none()
            && self.gas_limit.is_none()
            && self.coinbase.is_none()
            && self.random.is_none()
            && self.base_fee_per_gas.is_none()
            && self.blob_base_fee_per_gas.is_none()
            && self.difficulty.is_none()
    }

    /// Render to the JSON form geth/ethrex expect. Numeric values are emitted
    /// as hex strings; `random` as a 32-byte hash.
    pub fn to_rpc_value(&self) -> Value {
        let mut out = serde_json::Map::new();
        if let Some(number) = self.number {
            out.insert("number".into(), json!(format!("{number:#x}")));
        }
        if let Some(time) = self.time {
            out.insert("time".into(), json!(format!("{time:#x}")));
        }
        if let Some(gas_limit) = self.gas_limit {
            out.insert("gasLimit".into(), json!(format!("{gas_limit:#x}")));
        }
        if let Some(coinbase) = self.coinbase {
            out.insert("coinbase".into(), json!(format!("{coinbase:#x}")));
        }
        if let Some(random) = self.random {
            out.insert("random".into(), json!(format!("{random:#x}")));
        }
        if let Some(base_fee) = self.base_fee_per_gas {
            out.insert("baseFeePerGas".into(), json!(format!("{base_fee:#x}")));
        }
        if let Some(blob_base_fee) = self.blob_base_fee_per_gas {
            out.insert(
                "blobBaseFeePerGas".into(),
                json!(format!("{blob_base_fee:#x}")),
            );
        }
        if let Some(difficulty) = self.difficulty {
            out.insert("difficulty".into(), json!(format!("{difficulty:#x}")));
        }
        Value::Object(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set_serializes_to_empty_object() {
        let set = BlockOverrideSet::new();
        assert!(set.is_empty());
        assert_eq!(set.to_rpc_value(), json!({}));
    }

    #[test]
    fn numeric_fields_serialize_as_hex() {
        let set = BlockOverrideSet {
            number: Some(0x1234),
            time: Some(1_700_000_000),
            gas_limit: Some(30_000_000),
            base_fee_per_gas: Some(7),
            ..Default::default()
        };
        assert_eq!(
            set.to_rpc_value(),
            json!({
                "number": "0x1234",
                "time": "0x6553f100",
                "gasLimit": "0x1c9c380",
                "baseFeePerGas": "0x7"
            })
        );
    }

    #[test]
    fn coinbase_and_random_serialize_full_width() {
        let set = BlockOverrideSet {
            coinbase: Some(
                "0x000000000000000000000000000000000000beef"
                    .parse()
                    .unwrap(),
            ),
            random: Some(H256::from_low_u64_be(1)),
            ..Default::default()
        };
        assert_eq!(
            set.to_rpc_value(),
            json!({
                "coinbase": "0x000000000000000000000000000000000000beef",
                "random": "0x0000000000000000000000000000000000000000000000000000000000000001"
            })
        );
    }

    #[test]
    fn blob_base_fee_and_difficulty_serialize_as_hex() {
        let set = BlockOverrideSet {
            blob_base_fee_per_gas: Some(U256::from(0xaau64)),
            difficulty: Some(U256::from(0x42u64)),
            ..Default::default()
        };
        assert_eq!(
            set.to_rpc_value(),
            json!({ "blobBaseFeePerGas": "0xaa", "difficulty": "0x42" })
        );
    }
}
