use ethrex_common::types::TxType;
use ethrex_common::{Address, Bytes, H160, H256, U256};
use ethrex_l2_common::{calldata::Value, utils::get_address_from_secret_key};
use ethrex_l2_rpc::signer::{LocalSigner, Signer};
use ethrex_rpc::{
    EthClient,
    clients::Overrides,
    types::{
        block_identifier::{BlockIdentifier, BlockTag},
        receipt::RpcReceipt,
    },
};
use ethrex_sdk::{
    L1ToL2TransactionData, calldata::encode_calldata, get_last_verified_batch, send_l1_to_l2_tx,
    wait_for_l1_message_proof,
};
use keccak_hash::keccak;
use reqwest::Url;
use rex_sdk::{
    deploy,
    l2::{
        deposit::{deposit_through_contract_call, deposit_through_transfer},
        privileged_transaction_data::PrivilegedTransactionData,
        withdraw::{claim_withdraw, withdraw},
    },
    transfer, wait_for_transaction_receipt,
};
use secp256k1::SecretKey;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    ops::Mul,
    path::PathBuf,
    time::Duration,
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
const DEFAULT_BRIDGE_ADDRESS: Address = ethrex_sdk::DEFAULT_BRIDGE_ADDRESS;
// 0x3e141f8f9f083024c6e1ec3de2509de5da47c354
const DEFAULT_ON_CHAIN_PROPOSER_ADDRESS: Address = H160([
    0x3e, 0x14, 0x1f, 0x8f, 0x9f, 0x08, 0x30, 0x24, 0xc6, 0xe1, 0xec, 0x3d, 0xe2, 0x50, 0x9d, 0xe5,
    0xda, 0x47, 0xc3, 0x54,
]);
// 0x0007a881CD95B1484fca47615B64803dad620C8d
const DEFAULT_PROPOSER_COINBASE_ADDRESS: Address = H160([
    0x00, 0x07, 0xa8, 0x81, 0xcd, 0x95, 0xb1, 0x48, 0x4f, 0xca, 0x47, 0x61, 0x5b, 0x64, 0x80, 0x3d,
    0xad, 0x62, 0x0c, 0x8d,
]);

const L2_GAS_COST_MAX_DELTA: U256 = U256([100_000_000_000_000, 0, 0, 0]);

#[tokio::test]
async fn sdk_integration_test() -> Result<(), Box<dyn std::error::Error>> {
    read_env_file_by_config();

    let eth_client = eth_client();
    let proposer_client = proposer_client();
    let rich_wallet_private_key = l1_rich_wallet_private_key();
    let transfer_return_private_key = l2_return_transfer_private_key();
    let bridge_address = common_bridge_address();
    let deposit_recipient_address =
        get_address_from_secret_key(&rich_wallet_private_key.secret_bytes())
            .expect("Failed to get address from l1 rich wallet pk");

    test_deposit_through_transfer(
        &rich_wallet_private_key,
        bridge_address,
        deposit_recipient_address,
        &eth_client,
        &proposer_client,
    )
    .await?;

    test_deposit_through_contract_call(
        &rich_wallet_private_key,
        bridge_address,
        deposit_recipient_address,
        &eth_client,
        &proposer_client,
    )
    .await?;

    test_transfer(
        &rich_wallet_private_key,
        &transfer_return_private_key,
        &proposer_client,
    )
    .await?;

    test_transfer_with_privileged_tx(
        &rich_wallet_private_key,
        &transfer_return_private_key,
        &eth_client,
        &proposer_client,
    )
    .await?;

    test_gas_burning(&eth_client).await?;

    test_privileged_tx_with_contract_call(&proposer_client, &eth_client).await?;

    test_privileged_tx_with_contract_call_revert(&proposer_client, &eth_client).await?;

    let withdrawals_count = std::env::var("INTEGRATION_TEST_WITHDRAW_COUNT")
        .map(|amount| amount.parse().expect("Invalid withdrawal amount value"))
        .unwrap_or(5);

    test_n_withdraws(
        &rich_wallet_private_key,
        &eth_client,
        &proposer_client,
        bridge_address,
        withdrawals_count,
    )
    .await?;

    Ok(())
}

pub fn read_env_file_by_config() {
    let env_file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    let Ok(env_file) = File::open(env_file_path) else {
        println!(".env file not found, skipping");
        return;
    };

    let reader = BufReader::new(env_file);

    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        if line.starts_with("#") {
            // Skip comments
            continue;
        };
        match line.split_once('=') {
            Some((key, value)) => {
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
        Url::parse(
            std::env::var("INTEGRATION_TEST_ETH_URL")
                .unwrap_or(DEFAULT_ETH_URL.to_string())
                .as_str(),
        )
        .expect("Invalid ETH URL"),
    )
    .unwrap()
}

fn proposer_client() -> EthClient {
    EthClient::new(
        Url::parse(
            std::env::var("INTEGRATION_TEST_PROPOSER_URL")
                .unwrap_or(DEFAULT_PROPOSER_URL.to_string())
                .as_str(),
        )
        .expect("Invalid proposer URL"),
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
        .unwrap_or(format!("{DEFAULT_BRIDGE_ADDRESS:#x}"))
        .parse()
        .expect("Invalid bridge address")
}

fn on_chain_proposer_address() -> Address {
    std::env::var("ETHREX_COMMITTER_ON_CHAIN_PROPOSER_ADDRESS")
        .unwrap_or(format!("{DEFAULT_ON_CHAIN_PROPOSER_ADDRESS:#x}"))
        .parse()
        .expect("Invalid OnChainProposer address")
}

fn fees_vault() -> Address {
    std::env::var("INTEGRATION_TEST_PROPOSER_COINBASE_ADDRESS")
        .map(|address| address.parse().expect("Invalid proposer coinbase address"))
        .unwrap_or(DEFAULT_PROPOSER_COINBASE_ADDRESS)
}

async fn test_deposit_through_transfer(
    depositor_private_key: &SecretKey,
    bridge_address: Address,
    deposit_recipient_address: Address,
    eth_client: &EthClient,
    proposer_client: &EthClient,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Fetching initial balances on L1 and L2");

    let depositor = get_address_from_secret_key(&depositor_private_key.secret_bytes())?;
    let deposit_value = std::env::var("INTEGRATION_TEST_DEPOSIT_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid deposit value"))
        .unwrap_or(U256::from(1000000000000000000000u128));

    let depositor_l1_initial_balance = eth_client
        .get_balance(depositor, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        depositor_l1_initial_balance >= deposit_value,
        "L1 depositor doesn't have enough balance to deposit"
    );

    let deposit_recipient_l2_initial_balance = proposer_client
        .get_balance(
            deposit_recipient_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    let bridge_initial_balance = eth_client
        .get_balance(bridge_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let fee_vault_balance_before_deposit = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!("Depositing funds from L1 to L2 through transfer");

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
        wait_for_transaction_receipt(deposit_tx_hash, eth_client, 1000, true).await?;

    assert!(
        deposit_tx_receipt.receipt.status,
        "L1 deposit transaction failed"
    );

    let depositor_l1_balance_after_deposit = eth_client
        .get_balance(depositor, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        depositor_l1_balance_after_deposit,
        depositor_l1_initial_balance
            - deposit_value
            - deposit_tx_receipt.tx_info.gas_used * deposit_tx_receipt.tx_info.effective_gas_price,
        "Depositor L1 balance didn't decrease as expected after deposit"
    );

    let bridge_balance_after_deposit = eth_client
        .get_balance(bridge_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        bridge_balance_after_deposit,
        bridge_initial_balance + deposit_value,
        "Bridge balance didn't increase as expected after deposit"
    );

    println!("Waiting for L2 deposit tx receipt");

    let _ = wait_for_l2_deposit_receipt(&deposit_tx_receipt, eth_client, proposer_client).await?;

    let deposit_recipient_l2_balance_after_deposit = proposer_client
        .get_balance(
            deposit_recipient_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    assert_eq!(
        deposit_recipient_l2_balance_after_deposit,
        deposit_recipient_l2_initial_balance + deposit_value,
        "Deposit recipient L2 balance didn't increase as expected after deposit"
    );

    let fee_vault_balance_after_deposit = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        fee_vault_balance_after_deposit, fee_vault_balance_before_deposit,
        "Fee vault balance should not change after deposit"
    );

    Ok(())
}

async fn test_deposit_through_contract_call(
    depositor_private_key: &SecretKey,
    bridge_address: Address,
    deposit_recipient_address: Address,
    eth_client: &EthClient,
    proposer_client: &EthClient,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Fetching initial balances on L1 and L2");

    let depositor = get_address_from_secret_key(&depositor_private_key.secret_bytes())?;
    let deposit_value = std::env::var("INTEGRATION_TEST_DEPOSIT_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid deposit value"))
        .unwrap_or(U256::from(1000000000000000000000u128));

    let depositor_l1_initial_balance = eth_client
        .get_balance(depositor, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        depositor_l1_initial_balance >= deposit_value,
        "L1 depositor doesn't have enough balance to deposit"
    );

    let deposit_recipient_l2_initial_balance = proposer_client
        .get_balance(
            deposit_recipient_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    let bridge_initial_balance = eth_client
        .get_balance(bridge_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let fee_vault_balance_before_deposit = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!("Depositing funds from L1 to L2 through contract call");

    let deposit_tx_hash = deposit_through_contract_call(
        deposit_value,
        deposit_recipient_address,
        depositor_private_key,
        bridge_address,
        eth_client,
    )
    .await?;

    println!("Waiting for L1 deposit transaction receipt");

    let deposit_tx_receipt =
        wait_for_transaction_receipt(deposit_tx_hash, eth_client, 1000, true).await?;

    let depositor_l1_balance_after_deposit = eth_client
        .get_balance(depositor, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        depositor_l1_balance_after_deposit,
        depositor_l1_initial_balance
            - deposit_value
            - deposit_tx_receipt.tx_info.gas_used * deposit_tx_receipt.tx_info.effective_gas_price,
        "Depositor L1 balance didn't decrease as expected after deposit"
    );

    let bridge_balance_after_deposit = eth_client
        .get_balance(bridge_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        bridge_balance_after_deposit,
        bridge_initial_balance + deposit_value,
        "Bridge balance didn't increase as expected after deposit"
    );

    println!("Waiting for L2 deposit tx receipt");

    let _ = wait_for_l2_deposit_receipt(&deposit_tx_receipt, eth_client, proposer_client).await?;

    let deposit_recipient_l2_balance_after_deposit = proposer_client
        .get_balance(
            deposit_recipient_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    assert_eq!(
        deposit_recipient_l2_balance_after_deposit,
        deposit_recipient_l2_initial_balance + deposit_value,
        "Deposit recipient L2 balance didn't increase as expected after deposit"
    );

    let fee_vault_balance_after_deposit = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        fee_vault_balance_after_deposit, fee_vault_balance_before_deposit,
        "Fee vault balance should not change after deposit"
    );

    Ok(())
}

async fn test_transfer(
    transferer_private_key: &SecretKey,
    returnerer_private_key: &SecretKey,
    proposer_client: &EthClient,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Transferring funds on L2");
    let transfer_value = std::env::var("INTEGRATION_TEST_TRANSFER_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid transfer value"))
        .unwrap_or(U256::from(100000000000000000000u128));
    let transferer_address = get_address_from_secret_key(&transferer_private_key.secret_bytes())?;
    let returner_address = get_address_from_secret_key(&returnerer_private_key.secret_bytes())?;

    perform_transfer(
        proposer_client,
        transferer_private_key,
        returner_address,
        transfer_value,
    )
    .await?;

    println!("Returning funds on L2");

    // Only return 99% of the transfer, other amount is for fees
    let return_amount = (transfer_value * 99) / 100;

    perform_transfer(
        proposer_client,
        returnerer_private_key,
        transferer_address,
        return_amount,
    )
    .await?;

    Ok(())
}

async fn test_transfer_with_privileged_tx(
    transferer_private_key: &SecretKey,
    receiver_private_key: &SecretKey,
    eth_client: &EthClient,
    proposer_client: &EthClient,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Transferring funds on L2 through a deposit");
    let transfer_value = std::env::var("INTEGRATION_TEST_TRANSFER_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid transfer value"))
        .unwrap_or(U256::from(100000000000000000000u128));
    let transferer_address = get_address_from_secret_key(&transferer_private_key.secret_bytes())?;
    let receiver_address = get_address_from_secret_key(&receiver_private_key.secret_bytes())?;

    let receiver_balance_before = proposer_client
        .get_balance(receiver_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let l1_to_l2_tx_hash = send_l1_to_l2_tx(
        transferer_address,
        Some(0),
        Some(21000 * 10),
        L1ToL2TransactionData::new(receiver_address, 21000 * 5, transfer_value, Bytes::new()),
        &l1_rich_wallet_private_key(),
        common_bridge_address(),
        eth_client,
    )
    .await?;

    println!("Waiting for L1 to L2 transaction receipt on L1");

    // this sleep time shouldn't be here issue #173
    tokio::time::sleep(std::time::Duration::from_secs(12)).await;

    let l1_to_l2_tx_receipt =
        wait_for_transaction_receipt(l1_to_l2_tx_hash, eth_client, 1000, true).await?;
    println!("Waiting for L1 to L2 transaction receipt on L2");

    let _ = wait_for_l2_deposit_receipt(&l1_to_l2_tx_receipt, eth_client, proposer_client).await?;

    println!("Checking balances after transfer");

    let receiver_balance_after = proposer_client
        .get_balance(receiver_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;
    assert_eq!(
        receiver_balance_after,
        receiver_balance_before + transfer_value
    );
    Ok(())
}

async fn test_gas_burning(eth_client: &EthClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("Transferring funds on L2 through a deposit");
    let rich_private_key = l1_rich_wallet_private_key();
    let rich_address = get_address_from_secret_key(&rich_private_key.secret_bytes())?;
    let l2_gas_limit = 2_000_000;
    let l1_extra_gas_limit = 400_000;

    let l1_to_l2_tx_hash = send_l1_to_l2_tx(
        rich_address,
        Some(0),
        Some(l2_gas_limit + l1_extra_gas_limit),
        L1ToL2TransactionData::new(rich_address, l2_gas_limit, U256::zero(), Bytes::new()),
        &rich_private_key,
        common_bridge_address(),
        eth_client,
    )
    .await?;

    println!("Waiting for L1 to L2 transaction receipt on L1");

    let l1_to_l2_tx_receipt =
        wait_for_transaction_receipt(l1_to_l2_tx_hash, eth_client, 1000, true).await?;

    assert!(l1_to_l2_tx_receipt.tx_info.gas_used > l2_gas_limit);
    assert!(l1_to_l2_tx_receipt.tx_info.gas_used < l2_gas_limit + l1_extra_gas_limit);
    Ok(())
}

/// In this test we deploy a contract on L2 and call it from L1 using the CommonBridge contract.
/// We call the contract by making a deposit from L1 to L2 with the recipient being the rich account.
/// The deposit will trigger the call to the contract.
async fn test_privileged_tx_with_contract_call(
    proposer_client: &EthClient,
    eth_client: &EthClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let rich_wallet_private_key = l1_rich_wallet_private_key();

    // pragma solidity ^0.8.27;
    // contract Test {
    //     event NumberSet(uint256 indexed number);
    //     function emitNumber(uint256 _number) public {
    //         emit NumberSet(_number);
    //     }
    // }
    let init_code = hex::decode(
        "6080604052348015600e575f5ffd5b506101008061001c5f395ff3fe6080604052348015600e575f5ffd5b50600436106026575f3560e01c8063f15d140b14602a575b5f5ffd5b60406004803603810190603c919060a4565b6042565b005b807f9ec8254969d1974eac8c74afb0c03595b4ffe0a1d7ad8a7f82ed31b9c854259160405160405180910390a250565b5f5ffd5b5f819050919050565b6086816076565b8114608f575f5ffd5b50565b5f81359050609e81607f565b92915050565b5f6020828403121560b65760b56072565b5b5f60c1848285016092565b9150509291505056fea26469706673582212206f6d360696127c56e2d2a456f3db4a61e30eae0ea9b3af3c900c81ea062e8fe464736f6c634300081c0033",
    )?;

    let deployed_contract_address =
        test_deploy(&init_code, &rich_wallet_private_key, proposer_client).await?;

    let number_to_emit = U256::from(424242);
    let calldata_to_contract: Bytes =
        encode_calldata("emitNumber(uint256)", &[Value::Uint(number_to_emit)])?.into();

    // We need to get the block number before the deposit to search for logs later.
    let first_block = proposer_client.get_block_number().await?;

    test_call_to_contract_with_deposit(
        deployed_contract_address,
        calldata_to_contract,
        &rich_wallet_private_key,
        proposer_client,
        eth_client,
    )
    .await?;

    println!("Waiting for event to be emitted");

    let mut block_number = first_block;

    let topic = keccak(b"NumberSet(uint256)");

    while proposer_client
        .get_logs(
            first_block,
            block_number,
            deployed_contract_address,
            vec![topic],
        )
        .await
        .is_ok_and(|logs| logs.is_empty())
    {
        println!("Waiting for the event to be built");
        block_number += U256::one();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let logs = proposer_client
        .get_logs(
            first_block,
            block_number,
            deployed_contract_address,
            vec![topic],
        )
        .await?;

    let number_emitted = U256::from_big_endian(
        &logs
            .first()
            .unwrap()
            .log
            .topics
            .get(1)
            .unwrap()
            .to_fixed_bytes(),
    );

    assert_eq!(
        number_emitted, number_to_emit,
        "Event emitted with wrong value. Expected 424242, got {number_emitted}"
    );

    Ok(())
}

/// Test the deployment of a contract on L2 and call it from L1 using the CommonBridge contract.
/// The call to the contract should revert but the deposit should be successful.
async fn test_privileged_tx_with_contract_call_revert(
    proposer_client: &EthClient,
    eth_client: &EthClient,
) -> Result<(), Box<dyn std::error::Error>> {
    // pragma solidity ^0.8.27;
    // contract RevertTest {
    //     function revert_call() public {
    //         revert("Reverted");
    //     }
    // }
    let rich_wallet_private_key = l1_rich_wallet_private_key();
    let init_code = hex::decode(
        "6080604052348015600e575f5ffd5b506101138061001c5f395ff3fe6080604052348015600e575f5ffd5b50600436106026575f3560e01c806311ebce9114602a575b5f5ffd5b60306032565b005b6040517f08c379a000000000000000000000000000000000000000000000000000000000815260040160629060c1565b60405180910390fd5b5f82825260208201905092915050565b7f52657665727465640000000000000000000000000000000000000000000000005f82015250565b5f60ad600883606b565b915060b682607b565b602082019050919050565b5f6020820190508181035f83015260d68160a3565b905091905056fea2646970667358221220903f571921ce472f979989f9135b8637314b68e080fd70d0da6ede87ad8b5bd564736f6c634300081c0033",
    )?;

    let deployed_contract_address =
        test_deploy(&init_code, &rich_wallet_private_key, proposer_client).await?;

    let calldata_to_contract: Bytes = encode_calldata("revert_call()", &[])?.into();

    test_call_to_contract_with_deposit(
        deployed_contract_address,
        calldata_to_contract,
        &rich_wallet_private_key,
        proposer_client,
        eth_client,
    )
    .await?;

    Ok(())
}

async fn wait_for_l2_deposit_receipt(
    rpc_receipt: &RpcReceipt,
    l1_client: &EthClient,
    l2_client: &EthClient,
) -> Result<RpcReceipt, Box<dyn std::error::Error>> {
    let log = rpc_receipt.logs.first().unwrap();

    let data = PrivilegedTransactionData::from_log(log.log.clone()).unwrap();

    let l2_deposit_tx_hash = data
        .into_tx(
            l1_client,
            l2_client.get_chain_id().await?.try_into().unwrap(),
            0,
        )
        .await
        .unwrap()
        .get_privileged_hash()
        .unwrap();

    println!("Waiting for deposit transaction receipt on L2");

    Ok(wait_for_transaction_receipt(l2_deposit_tx_hash, l2_client, 1000, true).await?)
}

async fn perform_transfer(
    proposer_client: &EthClient,
    transferer_private_key: &SecretKey,
    transfer_recipient_address: Address,
    transfer_value: U256,
) -> Result<(), Box<dyn std::error::Error>> {
    let transferer_address = get_address_from_secret_key(&transferer_private_key.secret_bytes())?;

    let transferer_initial_l2_balance = proposer_client
        .get_balance(transferer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        transferer_initial_l2_balance >= transfer_value,
        "L2 transferer doesn't have enough balance to transfer"
    );

    let transfer_recipient_initial_balance = proposer_client
        .get_balance(
            transfer_recipient_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    let fee_vault_balance_before_transfer = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let transfer_tx = transfer(
        transfer_value,
        transferer_address,
        transfer_recipient_address,
        TxType::EIP1559,
        transferer_private_key,
        proposer_client,
        Overrides::default(),
    )
    .await?;

    let transfer_tx_receipt =
        wait_for_transaction_receipt(transfer_tx, proposer_client, 1000, true).await?;

    let recoverable_fees_vault_balance = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!("Recoverable Fees Balance: {recoverable_fees_vault_balance}",);

    println!("Checking balances on L2 after transfer");

    let transferer_l2_balance_after_transfer = proposer_client
        .get_balance(transferer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        (transferer_initial_l2_balance - transfer_value)
            .abs_diff(transferer_l2_balance_after_transfer)
            < L2_GAS_COST_MAX_DELTA,
        "L2 transferer balance didn't decrease as expected after transfer. Gas costs were {}/{L2_GAS_COST_MAX_DELTA}",
        (transferer_initial_l2_balance - transfer_value)
            .abs_diff(transferer_l2_balance_after_transfer)
    );

    let transfer_recipient_l2_balance_after_transfer = proposer_client
        .get_balance(
            transfer_recipient_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    assert_eq!(
        transfer_recipient_l2_balance_after_transfer,
        transfer_recipient_initial_balance + transfer_value,
        "L2 transfer recipient balance didn't increase as expected after transfer"
    );

    let fee_vault_balance_after_transfer = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let transfer_fees = get_fees_details_l2(transfer_tx_receipt, proposer_client).await;

    assert_eq!(
        fee_vault_balance_after_transfer,
        fee_vault_balance_before_transfer + transfer_fees.recoverable_fees,
        "Fee vault balance didn't increase as expected after transfer"
    );

    Ok(())
}

// FIXME: Remove this before merging
#[allow(dead_code)]
#[derive(Debug)]
struct FeesDetails {
    total_fees: U256,
    recoverable_fees: U256,
    burned_fees: U256,
}

async fn get_fees_details_l2(tx_receipt: RpcReceipt, proposer_client: &EthClient) -> FeesDetails {
    let total_fees: U256 =
        (tx_receipt.tx_info.gas_used * tx_receipt.tx_info.effective_gas_price).into();

    let effective_gas_price = tx_receipt.tx_info.effective_gas_price;
    let base_fee_per_gas = proposer_client
        .get_block_by_number(
            BlockIdentifier::Number(tx_receipt.block_info.block_number),
            false,
        )
        .await
        .unwrap()
        .header
        .base_fee_per_gas
        .unwrap();

    let max_priority_fee_per_gas_transfer: U256 = (effective_gas_price - base_fee_per_gas).into();

    let recoverable_fees = max_priority_fee_per_gas_transfer.mul(tx_receipt.tx_info.gas_used);

    FeesDetails {
        total_fees,
        recoverable_fees,
        burned_fees: total_fees - recoverable_fees,
    }
}

async fn test_deploy(
    init_code: &[u8],
    deployer_private_key: &SecretKey,
    proposer_client: &EthClient,
) -> Result<Address, Box<dyn std::error::Error>> {
    println!("Deploying contract on L2");

    let deployer = Signer::Local(LocalSigner::new(*deployer_private_key));

    let deployer_balance_before_deploy = proposer_client
        .get_balance(deployer.address(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let fee_vault_balance_before_deploy = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let (deploy_tx_hash, contract_address) = deploy(
        proposer_client,
        &deployer,
        init_code.to_vec().into(),
        Overrides::default(),
        true,
    )
    .await?;

    let deploy_tx_receipt =
        wait_for_transaction_receipt(deploy_tx_hash, proposer_client, 1000, true).await?;

    let deploy_fees = get_fees_details_l2(deploy_tx_receipt, proposer_client).await;

    let deployer_balance_after_deploy = proposer_client
        .get_balance(deployer.address(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        deployer_balance_after_deploy,
        deployer_balance_before_deploy - deploy_fees.total_fees,
        "Deployer L2 balance didn't decrease as expected after deploy"
    );

    let fee_vault_balance_after_deploy = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        fee_vault_balance_after_deploy,
        fee_vault_balance_before_deploy + deploy_fees.recoverable_fees,
        "Fee vault balance didn't increase as expected after deploy"
    );

    let deployed_contract_balance = proposer_client
        .get_balance(contract_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        deployed_contract_balance.is_zero(),
        "Deployed contract balance should be zero after deploy"
    );

    Ok(contract_address)
}

async fn test_call_to_contract_with_deposit(
    deployed_contract_address: Address,
    calldata_to_contract: Bytes,
    caller_private_key: &SecretKey,
    proposer_client: &EthClient,
    eth_client: &EthClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let caller_address = get_address_from_secret_key(&caller_private_key.secret_bytes())
        .expect("Failed to get address");

    println!("Checking balances before call");

    let caller_l1_balance_before_call = eth_client
        .get_balance(caller_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let deployed_contract_balance_before_call = proposer_client
        .get_balance(
            deployed_contract_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    let fee_vault_balance_before_call = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!("Calling contract on L2 with deposit");

    let l1_to_l2_tx_hash = send_l1_to_l2_tx(
        caller_address,
        Some(0),
        Some(21000 * 100),
        L1ToL2TransactionData::new(
            deployed_contract_address,
            21000 * 5,
            U256::zero(),
            calldata_to_contract.clone(),
        ),
        &l1_rich_wallet_private_key(),
        common_bridge_address(),
        eth_client,
    )
    .await?;

    println!("Waiting for L1 to L2 transaction receipt on L1");

    let l1_to_l2_tx_receipt =
        wait_for_transaction_receipt(l1_to_l2_tx_hash, eth_client, 1000, true).await?;

    println!("Waiting for L1 to L2 transaction receipt on L2");

    let _ = wait_for_l2_deposit_receipt(&l1_to_l2_tx_receipt, eth_client, proposer_client).await?;

    println!("Checking balances after call");

    let caller_l1_balance_after_call = eth_client
        .get_balance(caller_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        caller_l1_balance_after_call,
        caller_l1_balance_before_call
            - l1_to_l2_tx_receipt.tx_info.gas_used
                * l1_to_l2_tx_receipt.tx_info.effective_gas_price,
        "Caller L1 balance didn't decrease as expected after call"
    );

    let fee_vault_balance_after_call = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        fee_vault_balance_after_call, fee_vault_balance_before_call,
        "Fee vault balance increased unexpectedly after call"
    );

    let deployed_contract_balance_after_call = proposer_client
        .get_balance(
            deployed_contract_address,
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    assert_eq!(
        deployed_contract_balance_after_call, deployed_contract_balance_before_call,
        "Deployed contract increased unexpectedly after call"
    );

    Ok(())
}

async fn test_n_withdraws(
    withdrawer_private_key: &SecretKey,
    eth_client: &EthClient,
    proposer_client: &EthClient,
    bridge_address: Address,
    n: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Withdraw funds from L2 to L1
    let withdrawer_address = get_address_from_secret_key(&withdrawer_private_key.secret_bytes())?;
    let withdraw_value = std::env::var("INTEGRATION_TEST_WITHDRAW_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid withdraw value"))
        .unwrap_or(U256::from(100000000000000000000u128));

    println!("Checking balances on L1 and L2 before withdrawal");

    let withdrawer_l2_balance_before_withdrawal = proposer_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        withdrawer_l2_balance_before_withdrawal >= withdraw_value,
        "L2 withdrawer doesn't have enough balance to withdraw"
    );

    let bridge_balance_before_withdrawal = eth_client
        .get_balance(
            common_bridge_address(),
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    assert!(
        bridge_balance_before_withdrawal >= withdraw_value,
        "L1 bridge doesn't have enough balance to withdraw"
    );

    let withdrawer_l1_balance_before_withdrawal = eth_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let fee_vault_balance_before_withdrawal = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!("Withdrawing funds from L2 to L1");

    let mut withdraw_txs = vec![];
    let mut receipts = vec![];

    for x in 1..n + 1 {
        println!("Sending withdraw {x}/{n}");
        let withdraw_tx = withdraw(
            withdraw_value,
            withdrawer_address,
            *withdrawer_private_key,
            proposer_client,
            None,
        )
        .await?;

        withdraw_txs.push(withdraw_tx);

        let withdraw_tx_receipt =
            wait_for_transaction_receipt(withdraw_tx, proposer_client, 1000, true)
                .await
                .expect("Withdraw tx receipt not found");

        receipts.push(withdraw_tx_receipt);
    }

    println!("Checking balances on L1 and L2 after withdrawal");

    let withdrawer_l2_balance_after_withdrawal = proposer_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert!(
        (withdrawer_l2_balance_before_withdrawal - withdraw_value * n)
            .abs_diff(withdrawer_l2_balance_after_withdrawal)
            < L2_GAS_COST_MAX_DELTA * n,
        "Withdrawer L2 balance didn't decrease as expected after withdrawal"
    );

    let withdrawer_l1_balance_after_withdrawal = eth_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        withdrawer_l1_balance_after_withdrawal, withdrawer_l1_balance_before_withdrawal,
        "Withdrawer L1 balance should not change after withdrawal"
    );

    let fee_vault_balance_after_withdrawal = proposer_client
        .get_balance(fees_vault(), BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let mut withdraw_fees = U256::zero();
    for receipt in receipts {
        withdraw_fees += get_fees_details_l2(receipt, proposer_client)
            .await
            .recoverable_fees;
    }

    assert_eq!(
        fee_vault_balance_after_withdrawal,
        fee_vault_balance_before_withdrawal + withdraw_fees,
        "Fee vault balance didn't increase as expected after withdrawal"
    );

    // We need to wait for all the txs to be included in some batch
    let mut proofs = vec![];
    for (i, tx) in withdraw_txs.clone().into_iter().enumerate() {
        println!("Getting withdrawal proof {}/{n}", i + 1);
        let message_proof = wait_for_l1_message_proof(proposer_client, tx, 1000).await?;
        let withdrawal_proof = message_proof
            .into_iter()
            .next()
            .expect("no l1messages in withdrawal");
        proofs.push(withdrawal_proof);
    }

    for proof in &proofs {
        while get_last_verified_batch(eth_client, on_chain_proposer_address())
            .await
            .unwrap()
            < proof.batch_number
        {
            println!("Withdrawal is not verified on L1 yet");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    let mut withdraw_claim_txs_receipts = vec![];

    for (x, proof) in proofs.iter().enumerate() {
        println!("Claiming withdrawal on L1 {x}/{n}");

        let withdraw_claim_tx = claim_withdraw(
            withdraw_value,
            withdrawer_address,
            *withdrawer_private_key,
            eth_client,
            proof,
            bridge_address,
        )
        .await?;
        let withdraw_claim_tx_receipt =
            wait_for_transaction_receipt(withdraw_claim_tx, eth_client, 1000, true).await?;
        withdraw_claim_txs_receipts.push(withdraw_claim_tx_receipt);
    }

    println!("Checking balances on L1 and L2 after claim");

    let withdrawer_l1_balance_after_claim = eth_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    let gas_used_value: u64 = withdraw_claim_txs_receipts
        .iter()
        .map(|x| x.tx_info.gas_used * x.tx_info.effective_gas_price)
        .sum();

    assert_eq!(
        withdrawer_l1_balance_after_claim,
        withdrawer_l1_balance_after_withdrawal + withdraw_value * n - gas_used_value,
        "Withdrawer L1 balance wasn't updated as expected after claim"
    );

    let withdrawer_l2_balance_after_claim = proposer_client
        .get_balance(withdrawer_address, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    assert_eq!(
        withdrawer_l2_balance_after_claim, withdrawer_l2_balance_after_withdrawal,
        "Withdrawer L2 balance should not change after claim"
    );

    let bridge_balance_after_withdrawal = eth_client
        .get_balance(
            common_bridge_address(),
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await?;

    assert_eq!(
        bridge_balance_after_withdrawal,
        bridge_balance_before_withdrawal - withdraw_value * n,
        "Bridge balance didn't decrease as expected after withdrawal"
    );

    Ok(())
}
