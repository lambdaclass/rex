use bytes::Bytes;
use ethrex_common::{Address, H256, types::AuthorizationTuple};
use ethrex_l2_rpc::clients::send_ethrex_transaction;
use ethrex_rlp::decode::RLPDecode;
use ethrex_rpc::{EthClient, clients::EthClientError};
use hex;

pub fn parse_authorization_list(
    auth_list: &[String],
) -> Result<Vec<AuthorizationTuple>, eyre::Error> {
    let mut parsed = Vec::new();
    for auth_tuple_raw in auth_list {
        let bytes = hex::decode(auth_tuple_raw.trim_start_matches("0x"))?;
        let auth_tuple = AuthorizationTuple::decode(&bytes)?;
        parsed.push(auth_tuple);
    }
    Ok(parsed)
}

pub async fn send_authorized_transaction(
    client: &EthClient,
    to: Address,
    calldata: Bytes,
    auth_list_hex: &[String],
) -> Result<H256, EthClientError> {
    let auth_list = parse_authorization_list(auth_list_hex)
        .map_err(|e| EthClientError::Custom(e.to_string()))?;
    let auth_list = if auth_list.is_empty() {
        None
    } else {
        Some(auth_list)
    };

    send_ethrex_transaction(client, to, calldata, auth_list).await
}
