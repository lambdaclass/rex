use clap::Parser;
use ethrex_common::{Address, Bytes, U256};
use ethrex_rpc::{
    EthClient,
    clients::Overrides,
    types::block_identifier::{BlockIdentifier, BlockTag},
};
use hex::FromHexError;
use rex_sdk::{client::eth::get_address_from_secret_key, transfer, wait_for_transaction_receipt};
use secp256k1::SecretKey;
use std::str::FromStr;

#[derive(Parser)]
struct SimpleUsageArgs {
    #[arg(long, value_parser = parse_private_key, env = "PRIVATE_KEY", help = "The private key to derive the address from.")]
    private_key: SecretKey,
    #[arg(long, default_value = "http://localhost:8545", env = "RPC_URL")]
    rpc_url: String,
}

fn parse_private_key(s: &str) -> eyre::Result<SecretKey> {
    Ok(SecretKey::from_slice(&parse_hex(s)?)?)
}

fn parse_hex(s: &str) -> eyre::Result<Bytes, FromHexError> {
    match s.strip_prefix("0x") {
        Some(s) => hex::decode(s).map(Into::into),
        None => hex::decode(s).map(Into::into),
    }
}

#[tokio::main]
async fn main() {
    let args = SimpleUsageArgs::parse();

    let account = get_address_from_secret_key(&args.private_key).unwrap();

    let eth_client = EthClient::new(&args.rpc_url).unwrap();

    let account_balance = eth_client
        .get_balance(account, BlockIdentifier::Tag(BlockTag::Latest))
        .await
        .unwrap();

    let account_nonce = eth_client
        .get_nonce(account, BlockIdentifier::Tag(BlockTag::Latest))
        .await
        .unwrap();

    let chain_id = eth_client.get_chain_id().await.unwrap();

    println!("Account balance: {account_balance}");
    println!("Account nonce: {account_nonce}");
    println!("Chain id: {chain_id}");

    let amount = U256::from_dec_str("1000000000000000000").unwrap(); // 1 ETH in wei
    let from = account;
    let to = Address::from_str("0x4852f44fd706e34cb906b399b729798665f64a83").unwrap();

    let tx_hash = transfer(
        amount,
        from,
        to,
        &args.private_key,
        &eth_client,
        Overrides::default(),
    )
    .await
    .unwrap();

    // Wait for the transaction to be finalized
    wait_for_transaction_receipt(tx_hash, &eth_client, 100, false)
        .await
        .unwrap();

    let tx_receipt = eth_client.get_transaction_receipt(tx_hash).await.unwrap();

    println!("transfer tx receipt: {tx_receipt:?}");

    let tx_details = eth_client.get_transaction_by_hash(tx_hash).await.unwrap();

    println!("transfer tx details: {tx_details:?}");
}
