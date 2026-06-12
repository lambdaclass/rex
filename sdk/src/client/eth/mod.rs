use ethrex_common::{Address, Bytes, U256, types::TxKind};
use ethrex_rpc::{
    EthClient,
    clients::{EthClientError, Overrides},
    utils::{RpcRequest, RpcResponse},
};
use serde_json::{Value, json};

pub mod block_override;
pub mod state_override;

pub use block_override::BlockOverrideSet;
pub use state_override::{AccountOverride, StateOverrideSet};

// 0x70a08231 == balanceOf(address)
pub const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

pub async fn get_token_balance(
    eth_client: &EthClient,
    address: Address,
    token_address: Address,
) -> Result<U256, EthClientError> {
    get_token_balance_with_overrides(
        eth_client,
        address,
        token_address,
        &StateOverrideSet::new(),
        &BlockOverrideSet::new(),
    )
    .await
}

pub async fn get_token_balance_with_state_overrides(
    eth_client: &EthClient,
    address: Address,
    token_address: Address,
    state_overrides: &StateOverrideSet,
) -> Result<U256, EthClientError> {
    get_token_balance_with_overrides(
        eth_client,
        address,
        token_address,
        state_overrides,
        &BlockOverrideSet::new(),
    )
    .await
}

pub async fn get_token_balance_with_overrides(
    eth_client: &EthClient,
    address: Address,
    token_address: Address,
    state_overrides: &StateOverrideSet,
    block_overrides: &BlockOverrideSet,
) -> Result<U256, EthClientError> {
    let mut calldata = Vec::from(BALANCE_OF_SELECTOR);
    calldata.resize(16, 0);
    calldata.extend(address.to_fixed_bytes());
    let raw = call_with_overrides(
        eth_client,
        token_address,
        calldata.into(),
        Overrides::default(),
        state_overrides,
        block_overrides,
    )
    .await?;
    U256::from_str_radix(raw.trim_start_matches("0x"), 16).map_err(|_| {
        EthClientError::Custom(format!("Address {token_address} did not return a uint256"))
    })
}

/// Like [`EthClient::call`] but threads a State Override Set as the 3rd
/// `eth_call` parameter. When `state_overrides` is empty, behaves like a normal
/// 2-param `eth_call` so older nodes keep working.
pub async fn call_with_state_overrides(
    eth_client: &EthClient,
    to: Address,
    calldata: Bytes,
    overrides: Overrides,
    state_overrides: &StateOverrideSet,
) -> Result<String, EthClientError> {
    call_with_overrides(
        eth_client,
        to,
        calldata,
        overrides,
        state_overrides,
        &BlockOverrideSet::new(),
    )
    .await
}

/// Like [`EthClient::call`] but threads a State Override Set and a Block
/// Override Set as the 3rd and 4th `eth_call` parameters. Trailing empty sets
/// are omitted, so with both empty this behaves like a normal 2-param
/// `eth_call` and older nodes keep working. When only block overrides are
/// given, an empty object (a no-op) is sent as the 3rd parameter to keep the
/// 4th in position.
pub async fn call_with_overrides(
    eth_client: &EthClient,
    to: Address,
    calldata: Bytes,
    overrides: Overrides,
    state_overrides: &StateOverrideSet,
    block_overrides: &BlockOverrideSet,
) -> Result<String, EthClientError> {
    let mut tx_json = json!({
        "to": format!("{to:#x}"),
        "input": format!("0x{}", hex::encode(&calldata)),
        "value": format!("{:#x}", overrides.value.unwrap_or_default()),
        "from": format!("{:#x}", overrides.from.unwrap_or_default()),
    });
    if let Some(nonce) = overrides.nonce {
        tx_json["nonce"] = json!(format!("{nonce:#x}"));
    }
    if let Some(gas) = overrides.gas_limit {
        tx_json["gas"] = json!(format!("{gas:#x}"));
    }
    if let Some(price) = overrides.max_fee_per_gas {
        tx_json["gasPrice"] = json!(format!("{price:#x}"));
    }
    let _ = TxKind::Call(to); // keep TxKind import meaningful for future variants

    let block_param: Value = overrides
        .block
        .map(Into::into)
        .unwrap_or_else(|| Value::String("latest".to_string()));

    let mut params = vec![tx_json, block_param];
    if !state_overrides.is_empty() || !block_overrides.is_empty() {
        params.push(state_overrides.to_rpc_value());
    }
    if !block_overrides.is_empty() {
        params.push(block_overrides.to_rpc_value());
    }

    let request = RpcRequest::new("eth_call", Some(params));
    match eth_client.send_request(request).await? {
        RpcResponse::Success(result) => serde_json::from_value::<String>(result.result)
            .map_err(|e| EthClientError::Custom(format!("eth_call decode failed: {e}"))),
        RpcResponse::Error(err) => Err(EthClientError::Custom(format!(
            "eth_call rpc error: {}{}",
            err.error.message,
            err.error
                .data
                .map(|d| format!(" (data: {d})"))
                .unwrap_or_default()
        ))),
    }
}
