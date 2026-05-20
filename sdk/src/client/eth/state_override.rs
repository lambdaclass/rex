//! State override set for `eth_call` / `eth_estimateGas` / `eth_createAccessList`.
//!
//! JSON-RPC shape matches geth's State Override Set
//! (<https://geth.ethereum.org/docs/interacting-with-geth/rpc/objects#state-override-set>),
//! also supported by ethrex as of PR lambdaclass/ethrex#6660.

use std::collections::BTreeMap;

use ethrex_common::{Address, Bytes, H256, U256};
use serde::Serialize;
use serde_json::{Value, json};

/// Per-address state overlay. `state` and `state_diff` are mutually exclusive
/// — supplying both produces an RPC error server-side.
#[derive(Debug, Default, Clone, Serialize)]
pub struct AccountOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Bytes>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub state: BTreeMap<H256, U256>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", rename = "stateDiff")]
    pub state_diff: BTreeMap<H256, U256>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "movePrecompileToAddress"
    )]
    pub move_precompile_to: Option<Address>,
}

/// State override set: address → [`AccountOverride`].
///
/// Serializes to the JSON shape expected as the 3rd parameter of `eth_call`:
///
/// ```json
/// {
///   "0xabc...": { "balance": "0x100", "nonce": "0x5" },
///   "0xdef...": { "code": "0x600160005260206000f3" }
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct StateOverrideSet(pub BTreeMap<Address, AccountOverride>);

impl StateOverrideSet {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn entry(&mut self, address: Address) -> &mut AccountOverride {
        self.0.entry(address).or_default()
    }

    /// Render to the JSON form geth/ethrex expect. Values are emitted as hex
    /// strings (`balance`, `nonce`, `code`, storage slot keys/values).
    pub fn to_rpc_value(&self) -> Value {
        let mut out = serde_json::Map::new();
        for (addr, ov) in &self.0 {
            let mut entry = serde_json::Map::new();
            if let Some(balance) = ov.balance {
                entry.insert("balance".into(), json!(format!("{balance:#x}")));
            }
            if let Some(nonce) = ov.nonce {
                entry.insert("nonce".into(), json!(format!("{nonce:#x}")));
            }
            if let Some(code) = &ov.code {
                entry.insert("code".into(), json!(format!("0x{}", hex::encode(code))));
            }
            if !ov.state.is_empty() {
                let mut storage = serde_json::Map::new();
                for (slot, value) in &ov.state {
                    storage.insert(format!("{slot:#x}"), json!(format!("{value:#x}")));
                }
                entry.insert("state".into(), Value::Object(storage));
            }
            if !ov.state_diff.is_empty() {
                let mut storage = serde_json::Map::new();
                for (slot, value) in &ov.state_diff {
                    storage.insert(format!("{slot:#x}"), json!(format!("{value:#x}")));
                }
                entry.insert("stateDiff".into(), Value::Object(storage));
            }
            if let Some(target) = ov.move_precompile_to {
                entry.insert(
                    "movePrecompileToAddress".into(),
                    json!(format!("{target:#x}")),
                );
            }
            out.insert(format!("{addr:#x}"), Value::Object(entry));
        }
        Value::Object(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(hex: &str) -> Address {
        hex.parse().unwrap()
    }

    #[test]
    fn empty_set_serializes_to_empty_object() {
        let set = StateOverrideSet::new();
        assert_eq!(set.to_rpc_value(), json!({}));
    }

    #[test]
    fn balance_and_nonce_serialize_as_hex() {
        let mut set = StateOverrideSet::new();
        let a = addr("0x000000000000000000000000000000000000beef");
        let entry = set.entry(a);
        entry.balance = Some(U256::from(0x100u64));
        entry.nonce = Some(5);
        assert_eq!(
            set.to_rpc_value(),
            json!({
                "0x000000000000000000000000000000000000beef": {
                    "balance": "0x100",
                    "nonce": "0x5"
                }
            })
        );
    }

    #[test]
    fn code_serializes_with_0x_prefix() {
        let mut set = StateOverrideSet::new();
        let a = addr("0x00000000000000000000000000000000000000aa");
        set.entry(a).code = Some(Bytes::from_static(&[0x60, 0x01, 0x60, 0x02]));
        assert_eq!(
            set.to_rpc_value(),
            json!({
                "0x00000000000000000000000000000000000000aa": { "code": "0x60016002" }
            })
        );
    }

    #[test]
    fn state_diff_renders_slot_map() {
        let mut set = StateOverrideSet::new();
        let a = addr("0x00000000000000000000000000000000000000cc");
        let slot = H256::from_low_u64_be(1);
        set.entry(a).state_diff.insert(slot, U256::from(0xaau64));
        let v = set.to_rpc_value();
        let entry = v.get("0x00000000000000000000000000000000000000cc").unwrap();
        let diff = entry.get("stateDiff").unwrap().as_object().unwrap();
        assert!(diff.contains_key(&format!("{slot:#x}")));
    }
}
