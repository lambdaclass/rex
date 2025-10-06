use ethrex_common::{Address, U256};
use ethrex_rpc::{
    EthClient,
    clients::{EthClientError, Overrides},
};
use keccak_hash::{H256, keccak};
use secp256k1::SecretKey;

// 0x70a08231 == balanceOf(address)
pub const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

pub async fn get_token_balance(
    eth_client: &EthClient,
    address: Address,
    token_address: Address,
) -> Result<U256, EthClientError> {
    let mut calldata = Vec::from(BALANCE_OF_SELECTOR);
    calldata.resize(16, 0);
    calldata.extend(address.to_fixed_bytes());
    U256::from_str_radix(
        &eth_client
            .call(
                token_address,
                calldata.into(),
                ethrex_rpc::clients::Overrides::default(),
            )
            .await?,
        16,
    )
    .map_err(|_| {
        EthClientError::Custom(format!("Address {token_address} did not return a uint256"))
    })
}

pub async fn get_pending_deposit_logs(
    eth_client: &EthClient,
    common_bridge_address: Address,
) -> Result<Vec<H256>, EthClientError> {
    let response = _generic_call(
        eth_client,
        b"getPendingDepositLogs()",
        common_bridge_address,
    )
    .await?;
    from_hex_string_to_h256_array(&response)
}

async fn _generic_call(
    client: &EthClient,
    selector: &[u8],
    contract_address: Address,
) -> Result<String, EthClientError> {
    let selector = keccak(selector)
        .as_bytes()
        .get(..4)
        .ok_or(EthClientError::Custom("Failed to get selector.".to_owned()))?
        .to_vec();

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&selector);

    let leading_zeros = 32 - ((calldata.len() - 4) % 32);
    calldata.extend(vec![0; leading_zeros]);

    let hex_string = client
        .call(contract_address, calldata.into(), Overrides::default())
        .await?;

    Ok(hex_string)
}

pub fn from_hex_string_to_h256_array(hex_string: &str) -> Result<Vec<H256>, EthClientError> {
    let bytes = hex::decode(hex_string.strip_prefix("0x").unwrap_or(hex_string))
        .map_err(|_| EthClientError::Custom("Invalid hex string".to_owned()))?;

    // The ABI encoding for dynamic arrays is:
    // 1. Offset to data (32 bytes)
    // 2. Length of array (32 bytes)
    // 3. Array elements (each 32 bytes)
    if bytes.len() < 64 {
        return Err(EthClientError::Custom("Response too short".to_owned()));
    }

    // Get the offset (should be 0x20 for simple arrays)
    let offset = U256::from_big_endian(&bytes[0..32]).as_usize();

    // Get the length of the array
    let length = U256::from_big_endian(&bytes[offset..offset + 32]).as_usize();

    // Calculate the start of the array data
    let data_start = offset + 32;
    let data_end = data_start + (length * 32);

    if data_end > bytes.len() {
        return Err(EthClientError::Custom("Invalid array length".to_owned()));
    }

    // Convert the slice directly to H256 array
    bytes[data_start..data_end]
        .chunks_exact(32)
        .map(|chunk| Ok(H256::from_slice(chunk)))
        .collect()
}

pub fn get_address_from_secret_key(secret_key: &SecretKey) -> Result<Address, EthClientError> {
    let public_key = secret_key
        .public_key(secp256k1::SECP256K1)
        .serialize_uncompressed();
    let hash = keccak(&public_key[1..]);

    // Get the last 20 bytes of the hash
    let address_bytes: [u8; 20] = hash
        .as_ref()
        .get(12..32)
        .ok_or(EthClientError::Custom(
            "Failed to get_address_from_secret_key: error slicing address_bytes".to_owned(),
        ))?
        .try_into()
        .map_err(|err| {
            EthClientError::Custom(format!("Failed to get_address_from_secret_key: {err}"))
        })?;

    Ok(Address::from(address_bytes))
}
