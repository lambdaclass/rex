use ethrex_common::{Address, Bytes, H160, H256, U256, types::BlockNumber};
use ethrex_l2::sequencer::l1_watcher::PrivilegedTransactionData;
use ethrex_rpc::types::receipt::RpcReceipt;
use keccak_hash::keccak;
use rex_sdk::client::EthClient;
use rex_sdk::client::Overrides;
use rex_sdk::client::eth::BlockByNumber;
use rex_sdk::client::eth::get_address_from_secret_key;
use rex_sdk::l2::deposit::deposit_through_transfer;
use rex_sdk::wait_for_transaction_receipt;
use secp256k1::SecretKey;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

const DEFAULT_ETH_URL: &str = "http://localhost:8545";
const DEFAULT_PROPOSER_URL: &str = "http://localhost:1729";

// 0x941e103320615d394a55708be13e45994c7d93b932b064dbcb2b511fe3254e2e
const DEFAULT_L1_RICH_WALLET_PRIVATE_KEY: H256 = H256([
    0x94, 0x1e, 0x10, 0x33, 0x20, 0x61, 0x5d, 0x39, 0x4a, 0x55, 0x70, 0x8b, 0xe1, 0x3e, 0x45, 0x99,
    0x4c, 0x7d, 0x93, 0xb9, 0x32, 0xb0, 0x64, 0xdb, 0xcb, 0x2b, 0x51, 0x1f, 0xe3, 0x25, 0x4e, 0x2e,
]);
// 0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31
const DEFAULT_L2_RETURN_TRANSFER_PRIVATE_KEY: H256 = H256([
    0xbc, 0xdf, 0x20, 0x24, 0x9a, 0xbf, 0x0e, 0xd6, 0xd9, 0x44, 0xc0, 0x28, 0x8f, 0xad, 0x48, 0x9e,
    0x33, 0xf6, 0x6b, 0x39, 0x60, 0xd9, 0xe6, 0x22, 0x9c, 0x1c, 0xd2, 0x14, 0xed, 0x3b, 0xbe, 0x31,
]);
// 0x8ccf74999c496e4d27a2b02941673f41dd0dab2a
const DEFAULT_BRIDGE_ADDRESS: Address = H160([
    0x8c, 0xcf, 0x74, 0x99, 0x9c, 0x49, 0x6e, 0x4d, 0x27, 0xa2, 0xb0, 0x29, 0x41, 0x67, 0x3f, 0x41,
    0xdd, 0x0d, 0xab, 0x2a,
]);
// 0x0007a881CD95B1484fca47615B64803dad620C8d
const DEFAULT_PROPOSER_COINBASE_ADDRESS: Address = H160([
    0x00, 0x07, 0xa8, 0x81, 0xcd, 0x95, 0xb1, 0x48, 0x4f, 0xca, 0x47, 0x61, 0x5b, 0x64, 0x80, 0x3d,
    0xad, 0x62, 0x0c, 0x8d,
]);

#[tokio::test]
async fn sdk_integration_test() -> Result<(), Box<dyn std::error::Error>> {
    read_env_file_by_config();

    let eth_client = eth_client();
    let proposer_client = proposer_client();
    let rich_wallet_private_key = l1_rich_wallet_private_key();
    let _transfer_return_private_key = l2_return_transfer_private_key();
    let bridge_address = common_bridge_address();
    let deposit_recipient_address = get_address_from_secret_key(&rich_wallet_private_key)
        .expect("Failed to get address from l1 rich wallet pk");

    test_deposit(
        &rich_wallet_private_key,
        bridge_address,
        deposit_recipient_address,
        &eth_client,
        &proposer_client,
    )
    .await?;

    Ok(())
}

pub fn read_env_file_by_config() {
    let env_file_path = PathBuf::from("../../ethrex/crates/l2/.env");

    let reader = BufReader::new(File::open(env_file_path).expect("Failed to open .env file"));

    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        if line.starts_with("#") {
            // Skip comments
            continue;
        };
        match line.split_once('=') {
            Some((key, value)) => {
                eprintln!("key {} value {}", key, value);
                if std::env::vars().any(|(k, _)| k == key) {
                    continue;
                }
                unsafe { std::env::set_var(key, value) }
            }
            None => continue,
        };
    }
}

fn eth_client() -> EthClient {
    EthClient::new(
        &std::env::var("INTEGRATION_TEST_ETH_URL").unwrap_or(DEFAULT_ETH_URL.to_string()),
    )
    .unwrap()
}

fn proposer_client() -> EthClient {
    EthClient::new(
        &std::env::var("INTEGRATION_TEST_PROPOSER_URL").unwrap_or(DEFAULT_PROPOSER_URL.to_string()),
    )
    .unwrap()
}

fn l1_rich_wallet_private_key() -> SecretKey {
    let l1_rich_wallet_pk = std::env::var("INTEGRATION_TEST_L1_RICH_WALLET_PRIVATE_KEY")
        .map(|pk| pk.parse().expect("Invalid l1 rich wallet pk"))
        .unwrap_or(DEFAULT_L1_RICH_WALLET_PRIVATE_KEY);
    SecretKey::from_slice(l1_rich_wallet_pk.as_bytes()).unwrap()
}

fn l2_return_transfer_private_key() -> SecretKey {
    let l2_return_deposit_private_key =
        std::env::var("INTEGRATION_TEST_RETURN_TRANSFER_PRIVATE_KEY")
            .map(|pk| pk.parse().expect("Invalid l1 rich wallet pk"))
            .unwrap_or(DEFAULT_L2_RETURN_TRANSFER_PRIVATE_KEY);
    SecretKey::from_slice(l2_return_deposit_private_key.as_bytes()).unwrap()
}

fn common_bridge_address() -> Address {
    std::env::var("ETHREX_WATCHER_BRIDGE_ADDRESS")
        .expect("ETHREX_WATCHER_BRIDGE_ADDRESS env var not set")
        .parse()
        .unwrap_or_else(|_| {
            println!(
                "ETHREX_WATCHER_BRIDGE_ADDRESS env var not set, using default: {DEFAULT_BRIDGE_ADDRESS}"
            );
            DEFAULT_BRIDGE_ADDRESS
        })
}

fn fees_vault() -> Address {
    std::env::var("INTEGRATION_TEST_PROPOSER_COINBASE_ADDRESS")
        .map(|address| address.parse().expect("Invalid proposer coinbase address"))
        .unwrap_or(DEFAULT_PROPOSER_COINBASE_ADDRESS)
}

async fn test_deposit(
    depositor_private_key: &SecretKey,
    bridge_address: Address,
    deposit_recipient_address: Address,
    eth_client: &EthClient,
    proposer_client: &EthClient,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Fetching initial balances on L1 and L2");

    let depositor = get_address_from_secret_key(depositor_private_key)?;
    let deposit_value = std::env::var("INTEGRATION_TEST_DEPOSIT_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid deposit value"))
        .unwrap_or(U256::from(1000000000000000000000u128));

    let depositor_l1_initial_balance = eth_client
        .get_balance(depositor, BlockByNumber::Latest)
        .await?;

    assert!(
        depositor_l1_initial_balance >= deposit_value,
        "L1 depositor doesn't have enough balance to deposit"
    );

    let deposit_recipient_l2_initial_balance = proposer_client
        .get_balance(deposit_recipient_address, BlockByNumber::Latest)
        .await?;

    let bridge_initial_balance = eth_client
        .get_balance(bridge_address, BlockByNumber::Latest)
        .await?;

    let fee_vault_balance_before_deposit = proposer_client
        .get_balance(fees_vault(), BlockByNumber::Latest)
        .await?;

    println!("Depositing funds from L1 to L2");

    let deposit_tx_hash = deposit_through_transfer(
        deposit_value,
        deposit_recipient_address,
        depositor_private_key,
        bridge_address,
        eth_client,
    )
    .await?;

    println!("Waiting for L1 deposit transaction receipt");

    let deposit_tx_receipt =
        wait_for_transaction_receipt(deposit_tx_hash, eth_client, 5, true).await?;

    let depositor_l1_balance_after_deposit = eth_client
        .get_balance(depositor, BlockByNumber::Latest)
        .await?;

    assert_eq!(
        depositor_l1_balance_after_deposit,
        depositor_l1_initial_balance
            - deposit_value
            - deposit_tx_receipt.tx_info.gas_used * deposit_tx_receipt.tx_info.effective_gas_price,
        "Depositor L1 balance didn't decrease as expected after deposit"
    );

    let bridge_balance_after_deposit = eth_client
        .get_balance(bridge_address, BlockByNumber::Latest)
        .await?;

    assert_eq!(
        bridge_balance_after_deposit,
        bridge_initial_balance + deposit_value,
        "Bridge balance didn't increase as expected after deposit"
    );

    println!("Waiting for L2 deposit tx receipt");

    let _ = wait_for_l2_deposit_receipt(
        deposit_tx_receipt.block_info.block_number,
        eth_client,
        proposer_client,
    )
    .await?;

    let deposit_recipient_l2_balance_after_deposit = proposer_client
        .get_balance(deposit_recipient_address, BlockByNumber::Latest)
        .await?;

    assert_eq!(
        deposit_recipient_l2_balance_after_deposit,
        deposit_recipient_l2_initial_balance + deposit_value,
        "Deposit recipient L2 balance didn't increase as expected after deposit"
    );

    let fee_vault_balance_after_deposit = proposer_client
        .get_balance(fees_vault(), BlockByNumber::Latest)
        .await?;

    assert_eq!(
        fee_vault_balance_after_deposit, fee_vault_balance_before_deposit,
        "Fee vault balance should not change after deposit"
    );

    Ok(())
}

async fn wait_for_l2_deposit_receipt(
    l1_receipt_block_number: BlockNumber,
    eth_client: &EthClient,
    proposer_client: &EthClient,
) -> Result<RpcReceipt, Box<dyn std::error::Error>> {
    let topic = keccak(b"PrivilegedTxSent(address,address,address,uint256,uint256,uint256,bytes)");
    let logs = eth_client
        .get_logs(
            U256::from(l1_receipt_block_number),
            U256::from(l1_receipt_block_number),
            common_bridge_address(),
            topic,
        )
        .await?;
    let data = PrivilegedTransactionData::from_log(logs.first().unwrap().log.clone())?;

    let l2_deposit_tx_hash = eth_client
        .build_privileged_transaction(
            data.to_address,
            data.from,
            Bytes::copy_from_slice(&data.calldata),
            Overrides {
                chain_id: Some(proposer_client.get_chain_id().await?.try_into().unwrap()),
                nonce: Some(data.transaction_id.as_u64()),
                value: Some(data.value),
                gas_limit: Some(data.gas_limit.as_u64()),
                max_fee_per_gas: Some(0),
                max_priority_fee_per_gas: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .get_privileged_hash()
        .unwrap();

    println!("Waiting for deposit transaction receipt on L2");

    Ok(wait_for_transaction_receipt(l2_deposit_tx_hash, proposer_client, 1000, true).await?)
}
