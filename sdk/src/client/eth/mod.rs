use ethrex_common::{Address, U256};
use ethrex_rpc::{EthClient, clients::EthClientError};

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
