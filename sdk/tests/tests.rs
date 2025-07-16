use rex_sdk::client::EthClient;

const DEFAULT_ETH_URL: &str = "http://localhost:8545";
const DEFAULT_PROPOSER_URL: &str = "http://localhost:1729";

#[tokio::test]
async fn sdk_integration_test() {
    assert!(true);
}

fn eth_client() -> EthClient {
    EthClient::new(
        &std::env::var("INTEGRATION_TEST_ETH_URL").unwrap_or(DEFAULT_ETH_URL.to_string()),
    )
    .unwrap()
}
