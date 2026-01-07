use ethrex_common::{Address, U256};
use ethrex_l2_rpc::clients::{
    get_base_fee_vault_address, get_l1_blob_base_fee_per_gas, get_l1_fee_vault_address,
    get_operator_fee, get_operator_fee_vault_address,
};
use ethrex_rpc::{
    EthClient,
    clients::EthClientError,
    types::block_identifier::{BlockIdentifier, BlockTag},
};

#[derive(Clone, Debug)]
pub struct FeeInfo {
    pub block_number: u64,
    pub base_fee_vault_address: Option<Address>,
    pub operator_fee_vault_address: Option<Address>,
    pub l1_fee_vault_address: Option<Address>,
    pub operator_fee: U256,
    pub blob_base_fee: u64,
}

pub async fn fetch_fee_info(
    client: &EthClient,
    block: Option<u64>,
) -> Result<FeeInfo, EthClientError> {
    let (block_identifier, block_number) = match block {
        Some(block_number) => (BlockIdentifier::Number(block_number), block_number),
        None => {
            let latest_block = client.get_block_number().await?.as_u64();
            (BlockIdentifier::Tag(BlockTag::Latest), latest_block)
        }
    };

    let base_fee_vault_address =
        get_base_fee_vault_address(client, block_identifier.clone()).await?;
    let operator_fee_vault_address =
        get_operator_fee_vault_address(client, block_identifier.clone()).await?;
    let l1_fee_vault_address = get_l1_fee_vault_address(client, block_identifier.clone()).await?;

    let operator_fee = get_operator_fee(client, block_identifier.clone()).await?;
    let blob_base_fee = get_l1_blob_base_fee_per_gas(client, block_number).await?;

    Ok(FeeInfo {
        block_number,
        base_fee_vault_address,
        operator_fee_vault_address,
        l1_fee_vault_address,
        operator_fee,
        blob_base_fee,
    })
}
