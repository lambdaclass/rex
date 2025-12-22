use clap::Parser;
use ethrex_common::types::TxType;
use ethrex_common::{Bytes, H160, H256, U256};
use ethrex_l2_common::calldata::Value;
use ethrex_l2_common::utils::get_address_from_secret_key;
use ethrex_l2_rpc::signer::{LocalSigner, Signer};
use ethrex_rpc::EthClient;
use ethrex_rpc::clients::Overrides;
use ethrex_sdk::calldata::encode_calldata;
use ethrex_sdk::{build_generic_tx, send_generic_transaction};
use keccak_hash::keccak;
use reqwest::Url;
use rex_sdk::deploy;
use rex_sdk::{
    keystore::{create_new_keystore, load_keystore_from_path},
    sign::sign_hash,
    transfer, wait_for_transaction_receipt,
};
use secp256k1::SecretKey;
use std::fs::read_to_string;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

#[derive(Parser)]
struct ExampleArgs {
    #[arg(
        long,
        env = "PRIVATE_KEY",
        help = "The private key to derive the address from."
    )]
    private_key: String,
    #[arg(long, default_value = "http://localhost:8545", env = "RPC_URL")]
    rpc_url: Url,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ExampleArgs::parse();

    // 1. Download contract deps and compile contract.
    setup();

    // 2. Create a new keystore named "RexTest" in the "ContractKeystores" directory.
    create_new_keystore(None, Some("RexTest"), "LambdaClass")?;

    // 3. Load the keystore with the password.
    let keystore_secret_key = load_keystore_from_path(None, "RexTest", "LambdaClass")?;
    let keystore_address = get_address_from_secret_key(&keystore_secret_key.secret_bytes())?;

    println!("\nKeystore loaded successfully:");
    println!(
        "\tPrivate Key: 0x{}",
        hex::encode(keystore_secret_key.secret_bytes())
    );
    println!("\tAddress: {keystore_address:#x}");

    // Connect the client to a node
    let eth_client = EthClient::new(args.rpc_url)?;

    // 4. Fund the keystore account.
    let pk = &args
        .private_key
        .strip_prefix("0x")
        .unwrap_or(&args.private_key);
    let rich_wallet_pk = SecretKey::from_str(pk)?;
    let rich_wallet_address = get_address_from_secret_key(&rich_wallet_pk.secret_bytes())?;
    let amount = U256::from_dec_str("1000000000000000000").expect("Failed to parse amount");
    let transfer_tx_hash = transfer(
        amount,
        rich_wallet_address,
        keystore_address,
        &rich_wallet_pk,
        &eth_client,
        Overrides::default(),
    )
    .await?;

    let transfer_receipt =
        wait_for_transaction_receipt(transfer_tx_hash, &eth_client, 10, true).await?;

    println!("\nFunds transferred successfully:");
    println!("\tTransfer tx hash: {transfer_tx_hash:#x}");
    println!("\tTransfer receipt: {transfer_receipt:?}");

    // 5. Deploy the signer recovery example contract with the keystore account.
    let bytecode_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/keystore/contracts/solc_out")
        .join("RecoverSigner.bin");
    let bytecode = hex::decode(read_to_string(bytecode_path)?)?;
    let signer = Signer::Local(LocalSigner::new(keystore_secret_key));
    let (contract_tx_hash, deployed_address) = deploy(
        &eth_client,
        &signer,
        Bytes::from(bytecode),
        Overrides::default(),
        true,
    )
    .await?;

    let contract_deploy_receipt =
        wait_for_transaction_receipt(contract_tx_hash, &eth_client, 10, true).await?;

    println!("\nContract deployed successfully:");
    println!("\tContract deployment tx hash: {contract_tx_hash:#x}");
    println!("\tContract deployment address: {deployed_address:#x}");
    println!("\tContract deployment receipt: {contract_deploy_receipt:?}");

    // Get the current block (for later).
    let from_block = eth_client.get_block_number().await?;

    // 6. Prepare the calldata to call the example contract.
    // i. Prepare a message.
    let message = H256::random();
    let prefix = "\x19Ethereum Signed Message:\n32";
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(prefix.as_bytes());
    hash_input.extend_from_slice(message.as_bytes());
    let hash = keccak(&hash_input);

    // ii. Sign the hash of the message with the keystore private key.
    let signature = sign_hash(hash, keystore_secret_key);

    // iii. ABI-encode the parameters.
    let raw_function_signature = "recoverSigner(bytes32,bytes)";
    let arguments = vec![
        Value::FixedBytes(Bytes::from(message.to_fixed_bytes().to_vec())),
        Value::Bytes(Bytes::from(signature)),
    ];
    let calldata = encode_calldata(raw_function_signature, &arguments).unwrap();

    // 7. Prepare and send the transaction for calling the example contract.
    let tx = build_generic_tx(
        &eth_client,
        TxType::EIP1559,
        deployed_address,
        keystore_address,
        calldata.into(),
        Overrides {
            value: Some(U256::from_dec_str("0")?),
            nonce: Some(1),
            chain_id: Some(9),
            gas_limit: Some(2000000),
            max_fee_per_gas: Some(2000000),
            max_priority_fee_per_gas: Some(20000),
            ..Default::default()
        },
    )
    .await?;

    let sent_tx_hash = send_generic_transaction(&eth_client, tx, &signer).await?;

    let sent_tx_receipt =
        wait_for_transaction_receipt(sent_tx_hash, &eth_client, 100, true).await?;

    println!("\nTx sent successfully:");
    println!("\tTx hash: {sent_tx_hash:#x}");
    println!("\tTx receipt: {sent_tx_receipt:?}");

    // Get the new current block.
    let to_block = eth_client.get_block_number().await?;

    // 8. Get the log emitted by the contract call execution.
    let logs = eth_client
        .get_logs(
            from_block,
            to_block,
            deployed_address,
            vec![keccak("RecoveredSigner(address)")],
        )
        .await?;

    println!("\tTx Logs: {logs:?}");

    // 9. Compare it with the expected one.
    let address_bytes = &logs[0].log.data[logs[0].log.data.len() - 20..];
    let recovered_address = H160::from_str(&hex::encode(address_bytes))?;
    assert_eq!(recovered_address, keystore_address);

    println!("\nAddress recovered successfully!");
    println!("\tRecovered address: {recovered_address:#x}");

    Ok(())
}

fn setup() {
    download_contract_deps();
    compile_contracts();
}

fn download_contract_deps() {
    println!("Downloading contract dependencies");

    let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let lib_path = root_path.join("examples/keystore/contracts/lib");

    if !lib_path.exists() {
        std::fs::create_dir_all(&lib_path).expect("Failed to create lib directory");
    }

    git_clone(
        "https://github.com/OpenZeppelin/openzeppelin-contracts.git",
        lib_path
            .join("openzeppelin-contracts")
            .to_str()
            .expect("Failed to get str from path"),
        None,
        true,
    );

    println!("Contract dependencies downloaded");
}

pub fn git_clone(repository_url: &str, outdir: &str, branch: Option<&str>, submodules: bool) {
    println!("Cloning repository: {repository_url} into {outdir}");

    let mut git_cmd = Command::new("git");

    let git_clone_cmd = git_cmd.arg("clone").arg(repository_url);

    if let Some(branch) = branch {
        git_clone_cmd.arg("--branch").arg(branch);
    }

    if submodules {
        git_clone_cmd.arg("--recurse-submodules");
    }

    git_clone_cmd
        .arg(outdir)
        .spawn()
        .expect("Failed to spawn git clone command")
        .wait()
        .expect("Failed to wait for git clone command");

    println!("Repository cloned successfully");
}

fn compile_contracts() {
    println!("Compiling contracts");

    let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let contracts_path = root_path.join("examples/keystore/contracts");

    compile_contract(contracts_path, "RecoverSigner.sol", false);

    println!("Contracts compiled");
}

pub fn compile_contract(general_contracts_path: PathBuf, contract_path: &str, runtime_bin: bool) {
    let bin_flag = if runtime_bin {
        "--bin-runtime"
    } else {
        "--bin"
    };

    // Both the contract path and the output path are relative to where the Makefile is.
    if !Command::new("solc")
        .arg(bin_flag)
        .arg(
            "@openzeppelin/contracts=".to_string()
                + general_contracts_path
                    .join("lib")
                    .join("openzeppelin-contracts")
                    .join("lib")
                    .join("openzeppelin-contracts")
                    .join("contracts")
                    .to_str()
                    .expect("Failed to get str from path"),
        )
        .arg(
            "@openzeppelin/contracts=".to_string()
                + general_contracts_path
                    .join("lib")
                    .join("openzeppelin-contracts")
                    .join("contracts")
                    .to_str()
                    .expect("Failed to get str from path"),
        )
        .arg(
            general_contracts_path
                .join(contract_path)
                .to_str()
                .expect("Failed to get str from path"),
        )
        .arg("--via-ir")
        .arg("-o")
        .arg(
            general_contracts_path
                .join("solc_out")
                .to_str()
                .expect("Failed to get str from path"),
        )
        .arg("--overwrite")
        .arg("--allow-paths")
        .arg(
            general_contracts_path
                .to_str()
                .expect("Failed to get str from path"),
        )
        .spawn()
        .expect("Failed to spawn solc command")
        .wait()
        .expect("Failed to wait for solc command")
        .success()
    {
        panic!("Failed to compile {contract_path}");
    }
}
