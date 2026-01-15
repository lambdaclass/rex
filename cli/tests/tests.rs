use ethrex_common::{Address, H160, H256, U256};
use ethrex_l2_common::utils::get_address_from_secret_key;
use secp256k1::SecretKey;
use std::process::Command;
use std::str::FromStr;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    time::Duration,
};

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
// 0x13295e5562584289b27f92b28f5418269d3b7d82
pub const DEFAULT_BRIDGE_ADDRESS: Address = H160([
    0x13, 0x29, 0x5e, 0x55, 0x62, 0x58, 0x42, 0x89, 0xb2, 0x7f, 0x92, 0xb2, 0x8f, 0x54, 0x18, 0x26,
    0x9d, 0x3b, 0x7d, 0x82,
]);
// 0x0007a881CD95B1484fca47615B64803dad620C8d
const DEFAULT_PROPOSER_COINBASE_ADDRESS: Address = H160([
    0x00, 0x07, 0xa8, 0x81, 0xcd, 0x95, 0xb1, 0x48, 0x4f, 0xca, 0x47, 0x61, 0x5b, 0x64, 0x80, 0x3d,
    0xad, 0x62, 0x0c, 0x8d,
]);

const L2_GAS_COST_MAX_DELTA: U256 = U256([100_000_000_000_000, 0, 0, 0]);

#[tokio::test]
async fn cli_integration_test() -> Result<(), Box<dyn std::error::Error>> {
    read_env_file_by_config();

    let rich_wallet_private_key = l1_rich_wallet_private_key();
    let transfer_return_private_key = l2_return_transfer_private_key();
    let bridge_address = common_bridge_address();

    test_deposit(&rich_wallet_private_key, bridge_address).await?;

    test_transfer(&rich_wallet_private_key, &transfer_return_private_key).await?;

    let withdrawals_count = std::env::var("INTEGRATION_TEST_WITHDRAW_COUNT")
        .map(|amount| amount.parse().expect("Invalid withdrawal amount value"))
        .unwrap_or(5);

    test_withdraws(&rich_wallet_private_key, bridge_address, withdrawals_count).await?;

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

fn fees_vault() -> Address {
    std::env::var("INTEGRATION_TEST_PROPOSER_COINBASE_ADDRESS")
        .map(|address| address.parse().expect("Invalid proposer coinbase address"))
        .unwrap_or(DEFAULT_PROPOSER_COINBASE_ADDRESS)
}

async fn test_deposit(
    depositor_private_key: &SecretKey,
    bridge_address: Address,
) -> Result<(), Box<dyn std::error::Error>> {
    let deposit_value = std::env::var("INTEGRATION_TEST_DEPOSIT_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid deposit value"))
        .unwrap_or(U256::from(1000000000000000000000u128));

    let depositor_address = get_address_from_secret_key(&depositor_private_key.secret_bytes())?;

    let depositor_l1_initial_balance = get_l1_balance(depositor_address)?;

    assert!(
        depositor_l1_initial_balance >= deposit_value,
        "L1 depositor doesn't have enough balance to deposit"
    );

    let deposit_recipient_l2_initial_balance = get_l2_balance(depositor_address)?;

    let bridge_initial_balance = get_l1_balance(bridge_address)?;

    let fee_vault_balance_before_deposit = get_l2_balance(fees_vault())?;

    println!("Depositing funds from L1 to L2");

    let deposit_tx_hash = deposit_l2(deposit_value, depositor_private_key, bridge_address)?;

    println!("Waiting for L1 deposit transaction receipt");

    tokio::time::sleep(std::time::Duration::from_secs(24)).await;

    let deposit_tx_receipt = get_receipt(deposit_tx_hash)?;

    let gas_used = U256::from_str(
        deposit_tx_receipt
            .split("gas_used: ")
            .nth(1)
            .unwrap()
            .split(',')
            .next()
            .unwrap()
            .trim(),
    )
    .unwrap();

    let effective_gas_price = U256::from_str(
        deposit_tx_receipt
            .split("effective_gas_price: ")
            .nth(1)
            .unwrap()
            .split(',')
            .next()
            .unwrap()
            .trim(),
    )
    .unwrap();

    let depositor_l1_balance_after_deposit = get_l1_balance(depositor_address)?;

    assert_eq!(
        depositor_l1_balance_after_deposit,
        depositor_l1_initial_balance - deposit_value - gas_used * effective_gas_price,
        "Depositor L1 balance didn't decrease as expected after deposit"
    );

    let bridge_balance_after_deposit = get_l1_balance(bridge_address)?;

    assert_eq!(
        bridge_balance_after_deposit,
        bridge_initial_balance + deposit_value,
        "Bridge balance didn't increase as expected after deposit"
    );

    let deposit_recipient_l2_balance_after_deposit = get_l2_balance(depositor_address)?;

    assert_eq!(
        deposit_recipient_l2_balance_after_deposit,
        deposit_recipient_l2_initial_balance + deposit_value,
        "Deposit recipient L2 balance didn't increase as expected after deposit"
    );

    let fee_vault_balance_after_deposit = get_l2_balance(fees_vault())?;

    assert_eq!(
        fee_vault_balance_after_deposit, fee_vault_balance_before_deposit,
        "Fee vault balance should not change after deposit"
    );

    Ok(())
}

async fn test_transfer(
    transferer_private_key: &SecretKey,
    returnerer_private_key: &SecretKey,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Transferring funds on L2");
    let transfer_value = std::env::var("INTEGRATION_TEST_TRANSFER_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid transfer value"))
        .unwrap_or(U256::from(100000000000000000000u128));
    let returner_address = get_address_from_secret_key(&returnerer_private_key.secret_bytes())?;
    let transferer_address = get_address_from_secret_key(&transferer_private_key.secret_bytes())?;

    perform_transfer(transferer_private_key, returner_address, transfer_value).await?;

    // Only return 99% of the transfer, other amount is for fees
    let return_amount = (transfer_value * 99) / 100;

    perform_transfer(returnerer_private_key, transferer_address, return_amount).await?;

    Ok(())
}

async fn perform_transfer(
    transferer_private_key: &SecretKey,
    transfer_recipient_address: Address,
    transfer_value: U256,
) -> Result<(), Box<dyn std::error::Error>> {
    let transferer_address = get_address_from_secret_key(&transferer_private_key.secret_bytes())?;

    let transferer_initial_l2_balance = get_l2_balance(transferer_address)?;

    assert!(
        transferer_initial_l2_balance >= transfer_value,
        "L2 transferer doesn't have enough balance to transfer"
    );

    let transfer_recipient_initial_balance = get_l2_balance(transfer_recipient_address)?;

    let _ = transfer(
        transfer_value,
        transfer_recipient_address,
        transferer_private_key,
    )?;

    tokio::time::sleep(std::time::Duration::from_secs(12)).await;

    let recoverable_fees_vault_balance = get_l2_balance(fees_vault())?;

    println!("Recoverable Fees Balance: {recoverable_fees_vault_balance}",);

    println!("Checking balances on L2 after transfer");

    let transferer_l2_balance_after_transfer = get_l2_balance(transferer_address)?;

    assert!(
        (transferer_initial_l2_balance - transfer_value)
            .abs_diff(transferer_l2_balance_after_transfer)
            < L2_GAS_COST_MAX_DELTA,
        "L2 transferer balance didn't decrease as expected after transfer. Gas costs were {}/{L2_GAS_COST_MAX_DELTA}",
        (transferer_initial_l2_balance - transfer_value)
            .abs_diff(transferer_l2_balance_after_transfer)
    );

    let transfer_recipient_l2_balance_after_transfer = get_l2_balance(transfer_recipient_address)?;

    assert_eq!(
        transfer_recipient_l2_balance_after_transfer,
        transfer_recipient_initial_balance + transfer_value,
        "L2 transfer recipient balance didn't increase as expected after transfer"
    );

    Ok(())
}

fn get_l1_balance(address: Address) -> Result<U256, Box<dyn std::error::Error>> {
    let output = Command::new("rex")
        .arg("balance")
        .arg(format!("{address:#x}"))
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Error getting balance: {stderr}");
    }

    let str = String::from_utf8(output.stdout).unwrap();
    Ok(U256::from_dec_str(str.trim()).unwrap())
}

fn get_l2_balance(address: Address) -> Result<U256, Box<dyn std::error::Error>> {
    let output = Command::new("rex")
        .arg("l2")
        .arg("balance")
        .arg(format!("{address:#x}"))
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Error getting balance: {stderr}");
    }

    let str = String::from_utf8(output.stdout).unwrap();
    Ok(U256::from_dec_str(str.trim()).unwrap())
}

fn deposit_l2(
    amount: U256,
    depositor_private_key: &SecretKey,
    bridge_address: Address,
) -> Result<H256, Box<dyn std::error::Error>> {
    let output = Command::new("rex")
        .arg("l2")
        .arg("deposit")
        .arg(format!("{amount}"))
        .arg(depositor_private_key.display_secret().to_string())
        .arg(format!("{bridge_address:#x}"))
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Error depositing to l2: {stderr}");
    }

    let output = String::from_utf8(output.stdout).unwrap();

    let hash_line = output
        .lines()
        .find(|line| line.contains("Deposit sent: "))
        .unwrap();

    let hash = hash_line.strip_prefix("Deposit sent: ").unwrap().trim();

    Ok(H256::from_str(hash).unwrap())
}

fn get_receipt(tx_hash: H256) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("rex")
        .arg("receipt")
        .arg(format!("{tx_hash:#x}"))
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("{}", String::from_utf8(output.stdout).unwrap());
        panic!("Error getting receipt: {stderr}");
    }

    Ok(String::from_utf8(output.stdout).unwrap())
}

fn get_l2_receipt(tx_hash: H256) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("rex")
        .arg("l2")
        .arg("receipt")
        .arg(format!("{tx_hash:#x}"))
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("{}", String::from_utf8(output.stdout).unwrap());
        panic!("Error getting receipt: {stderr}");
    }

    Ok(String::from_utf8(output.stdout).unwrap())
}

fn transfer(
    transfer_value: U256,
    transfer_recipient_address: Address,
    transferer_private_key: &SecretKey,
) -> Result<H256, Box<dyn std::error::Error>> {
    let output = Command::new("rex")
        .arg("l2")
        .arg("transfer")
        .arg(format!("{transfer_value}"))
        .arg(format!("{transfer_recipient_address:#x}"))
        .arg(transferer_private_key.display_secret().to_string())
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Error depositing to l2: {stderr}");
    }

    let str = String::from_utf8(output.stdout).unwrap();

    let hash_line = str.lines().next().unwrap();

    let hash = hash_line.trim();

    Ok(H256::from_str(hash).unwrap())
}

async fn test_withdraws(
    withdrawer_private_key: &SecretKey,
    bridge_address: Address,
    n: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Withdraw funds from L2 to L1
    let withdrawer_address = get_address_from_secret_key(&withdrawer_private_key.secret_bytes())?;
    let withdraw_value = std::env::var("INTEGRATION_TEST_WITHDRAW_VALUE")
        .map(|value| U256::from_dec_str(&value).expect("Invalid withdraw value"))
        .unwrap_or(U256::from(100000000000000000000u128));

    println!("Checking balances on L1 and L2 before withdrawal");

    let withdrawer_l2_balance_before_withdrawal = get_l2_balance(withdrawer_address)?;

    assert!(
        withdrawer_l2_balance_before_withdrawal >= withdraw_value,
        "L2 withdrawer doesn't have enough balance to withdraw"
    );

    let bridge_balance_before_withdrawal = get_l1_balance(bridge_address)?;

    assert!(
        bridge_balance_before_withdrawal >= withdraw_value,
        "L1 bridge doesn't have enough balance to withdraw"
    );

    let withdrawer_l1_balance_before_withdrawal = get_l1_balance(withdrawer_address)?;

    println!("Withdrawing funds from L2 to L1");

    let mut withdraw_txs = vec![];
    let mut receipts = vec![];

    for x in 1..n + 1 {
        println!("Sending withdraw {x}/{n}");
        let withdraw_tx = withdraw(withdraw_value, withdrawer_private_key)?;

        withdraw_txs.push(withdraw_tx);

        let withdraw_tx_receipt = get_l2_receipt(withdraw_tx)?;
        receipts.push(withdraw_tx_receipt);
    }

    println!("Checking balances on L1 and L2 after withdrawal");

    let withdrawer_l2_balance_after_withdrawal = get_l2_balance(withdrawer_address)?;

    assert!(
        (withdrawer_l2_balance_before_withdrawal - withdraw_value * n)
            .abs_diff(withdrawer_l2_balance_after_withdrawal)
            < L2_GAS_COST_MAX_DELTA * n,
        "Withdrawer L2 balance didn't decrease as expected after withdrawal"
    );

    let withdrawer_l1_balance_after_withdrawal = get_l1_balance(withdrawer_address)?;

    assert_eq!(
        withdrawer_l1_balance_after_withdrawal, withdrawer_l1_balance_before_withdrawal,
        "Withdrawer L1 balance should not change after withdrawal"
    );

    println!("Waiting for the withdrawal to be included in some batch and verified");

    // TODO: we should use `wait_for_verified_proof` instead
    tokio::time::sleep(Duration::from_secs(60)).await;

    // We need to wait for all the txs to be included in some batch
    let mut proofs = vec![];
    for (i, tx) in withdraw_txs.clone().into_iter().enumerate() {
        println!("Getting withdrawal proof {}/{n}", i + 1);
        let message_proof = get_l2_message_proof(tx).expect("no l1 messages in withdrawal");
        proofs.push(message_proof);
    }

    let mut withdraw_claim_txs_receipts = vec![];

    for (i, tx) in withdraw_txs.clone().into_iter().enumerate() {
        println!("Claiming withdrawal on L1 {}/{n}", i + 1);

        let withdraw_claim_tx =
            claim_withdraw(withdraw_value, tx, withdrawer_private_key, bridge_address)?;
        let withdraw_claim_tx_receipt = get_receipt(withdraw_claim_tx)?;

        withdraw_claim_txs_receipts.push(withdraw_claim_tx_receipt);
    }

    println!("Checking balances on L1 and L2 after claim");

    let withdrawer_l1_balance_after_claim = get_l1_balance(withdrawer_address)?;

    let mut gas_used_value = U256::zero();
    for receipt in withdraw_claim_txs_receipts {
        let gas_used = U256::from_str(
            receipt
                .split("gas_used: ")
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap()
                .trim(),
        )
        .unwrap();

        let effective_gas_price = U256::from_str(
            receipt
                .split("effective_gas_price: ")
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap()
                .trim(),
        )
        .unwrap();

        gas_used_value += gas_used * effective_gas_price;
    }

    assert_eq!(
        withdrawer_l1_balance_after_claim,
        withdrawer_l1_balance_after_withdrawal + withdraw_value * n - gas_used_value,
        "Withdrawer L1 balance wasn't updated as expected after claim"
    );

    let withdrawer_l2_balance_after_claim = get_l2_balance(withdrawer_address)?;

    assert_eq!(
        withdrawer_l2_balance_after_claim, withdrawer_l2_balance_after_withdrawal,
        "Withdrawer L2 balance should not change after claim"
    );

    let bridge_balance_after_withdrawal = get_l1_balance(bridge_address)?;

    assert_eq!(
        bridge_balance_after_withdrawal,
        bridge_balance_before_withdrawal - withdraw_value * n,
        "Bridge balance didn't decrease as expected after withdrawal"
    );

    Ok(())
}

fn withdraw(
    withdraw_amount: U256,
    withdrawer_private_key: &SecretKey,
) -> Result<H256, Box<dyn std::error::Error>> {
    let output = Command::new("rex")
        .arg("l2")
        .arg("withdraw")
        .arg(format!("{withdraw_amount}"))
        .arg(withdrawer_private_key.display_secret().to_string())
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Error depositing to l2: {stderr}");
    }

    let str = String::from_utf8(output.stdout).unwrap();

    let hash_line = str
        .lines()
        .find(|line| line.contains("Withdrawal sent: "))
        .unwrap();

    let hash = hash_line.strip_prefix("Withdrawal sent: ").unwrap().trim();

    Ok(H256::from_str(hash).unwrap())
}

fn get_l2_message_proof(tx_hash: H256) -> Result<Vec<H256>, Box<dyn std::error::Error>> {
    let output = Command::new("rex")
        .arg("l2")
        .arg("message-proof")
        .arg(format!("{tx_hash:#x}"))
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Error depositing to l2: {stderr}");
    }
    let str = String::from_utf8(output.stdout).unwrap();

    let hash = str
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();

    let Ok(path) = H256::from_str(hash) else {
        return Ok(vec![]);
    };

    Ok(vec![path])
}

fn claim_withdraw(
    amount: U256,
    tx_hash: H256,
    private_key: &SecretKey,
    bridge_address: Address,
) -> Result<H256, Box<dyn std::error::Error>> {
    let output = Command::new("rex")
        .arg("l2")
        .arg("claim-withdraw")
        .arg(format!("{amount}"))
        .arg(format!("{tx_hash:#x}"))
        .arg(private_key.display_secret().to_string())
        .arg(format!("{bridge_address:#x}"))
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Error depositing to l2: {stderr}");
    }

    let str = String::from_utf8(output.stdout).unwrap();

    let hash_line = str
        .lines()
        .find(|line| line.contains("Withdrawal claim sent: "))
        .unwrap();

    let hash = hash_line
        .strip_prefix("Withdrawal claim sent: ")
        .unwrap()
        .trim();

    Ok(H256::from_str(hash).unwrap())
}
