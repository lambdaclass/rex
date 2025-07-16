use ethrex_common::{Address, H160, H256};
use rex_sdk::client::EthClient;
use rex_sdk::client::eth::get_address_from_secret_key;
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

#[tokio::test]
async fn sdk_integration_test() {
    read_env_file_by_config();

    let eth_client = eth_client();
    let proposer_client = proposer_client();
    let rich_wallet_private_key = l1_rich_wallet_private_key();
    let transfer_return_private_key = l2_return_transfer_private_key();
    let bridge_address = common_bridge_address();
    let deposit_recipient_address = get_address_from_secret_key(&rich_wallet_private_key)
        .expect("Failed to get address from l1 rich wallet pk");
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
