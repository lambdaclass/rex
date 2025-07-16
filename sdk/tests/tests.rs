use rex_sdk::client::EthClient;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

const DEFAULT_ETH_URL: &str = "http://localhost:8545";
const DEFAULT_PROPOSER_URL: &str = "http://localhost:1729";

#[tokio::test]
async fn sdk_integration_test() {
    read_env_file_by_config();

    let eth_client = eth_client();
    let proposer_client = proposer_client();

    assert!(true);
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
