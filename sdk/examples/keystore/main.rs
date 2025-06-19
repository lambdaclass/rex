use ethrex_common::{Bytes, H256, U256};
use rex_sdk::calldata::{Value, encode_calldata};
use rex_sdk::client::eth::get_address_from_secret_key;
use rex_sdk::client::{EthClient, Overrides};
use rex_sdk::{
    keystore::{create_new_keystore, load_keystore_from_path},
    sign::sign_hash,
    transfer, wait_for_transaction_receipt,
};
use secp256k1::SecretKey;
use std::fs::read_to_string;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::str::FromStr;
const RPC_URL: &str = "http://127.0.0.1:8545";
const RICH_WALLET_PK: &str = "5d2344259f42259f82d2c140aa66102ba89b57b4883ee441a8b312622bd42491";

fn get_contract_code() -> Result<Bytes, Box<dyn std::error::Error>> {
    let hex_str = "6080604052348015600e575f5ffd5b506106e68061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610029575f3560e01c806397aba7f91461002d575b5f5ffd5b6100476004803603810190610042919061051a565b610049565b005b5f6100538361009f565b90505f61006082846100d2565b90507f2fa45e087bb7f6d5a718cfa7af28ee7babd0187f360b2279b874bedf43a7a4e08160405161009191906105b3565b60405180910390a150505050565b5f7f19457468657265756d205369676e6564204d6573736167653a0a3332000000005f5281601c52603c5f209050919050565b5f5f5f5f6100e086866100fc565b9250925092506100f08282610151565b82935050505092915050565b5f5f5f604184510361013c575f5f5f602087015192506040870151915060608701515f1a905061012e888285856102b3565b95509550955050505061014a565b5f600285515f1b9250925092505b9250925092565b5f6003811115610164576101636105cc565b5b826003811115610177576101766105cc565b5b03156102af5760016003811115610191576101906105cc565b5b8260038111156101a4576101a36105cc565b5b036101db576040517ff645eedf00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b600260038111156101ef576101ee6105cc565b5b826003811115610202576102016105cc565b5b0361024657805f1c6040517ffce698f700000000000000000000000000000000000000000000000000000000815260040161023d9190610611565b60405180910390fd5b600380811115610259576102586105cc565b5b82600381111561026c5761026b6105cc565b5b036102ae57806040517fd78bce0c0000000000000000000000000000000000000000000000000000000081526004016102a59190610639565b60405180910390fd5b5b5050565b5f5f5f7f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0845f1c11156102ef575f600385925092509250610390565b5f6001888888886040515f8152602001604052604051610312949392919061066d565b6020604051602081039080840390855afa158015610332573d5f5f3e3d5ffd5b5050506020604051035190505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1603610383575f60015f5f1b93509350935050610390565b805f5f5f1b935093509350505b9450945094915050565b5f604051905090565b5f5ffd5b5f5ffd5b5f819050919050565b6103bd816103ab565b81146103c7575f5ffd5b50565b5f813590506103d8816103b4565b92915050565b5f5ffd5b5f5ffd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b61042c826103e6565b810181811067ffffffffffffffff8211171561044b5761044a6103f6565b5b80604052505050565b5f61045d61039a565b90506104698282610423565b919050565b5f67ffffffffffffffff821115610488576104876103f6565b5b610491826103e6565b9050602081019050919050565b828183375f83830152505050565b5f6104be6104b98461046e565b610454565b9050828152602081018484840111156104da576104d96103e2565b5b6104e584828561049e565b509392505050565b5f82601f830112610501576105006103de565b5b81356105118482602086016104ac565b91505092915050565b5f5f604083850312156105305761052f6103a3565b5b5f61053d858286016103ca565b925050602083013567ffffffffffffffff81111561055e5761055d6103a7565b5b61056a858286016104ed565b9150509250929050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f61059d82610574565b9050919050565b6105ad81610593565b82525050565b5f6020820190506105c65f8301846105a4565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602160045260245ffd5b5f819050919050565b61060b816105f9565b82525050565b5f6020820190506106245f830184610602565b92915050565b610633816103ab565b82525050565b5f60208201905061064c5f83018461062a565b92915050565b5f60ff82169050919050565b61066781610652565b82525050565b5f6080820190506106805f83018761062a565b61068d602083018661065e565b61069a604083018561062a565b6106a7606083018461062a565b9594505050505056fea2646970667358221220548f6fa6b1abdcb9c06fe5862d66fcd598129414b89af5c6a237be9cacf7121064736f6c634300081d0033";
    let bytes = hex::decode(hex_str)?;
    Ok(Bytes::from(bytes))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Download contract deps and compile contract.
    setup();

    // // Create a keystore.
    // create_new_keystore(None, Some("ContractKeystore"), "LambdaClass")?;

    // // Load the secret key from the keystore.
    // let secret_key = load_keystore_from_path(None, "ContractKeystore", "LambdaClass")?;

    // // Get address from secret key
    // let new_address = get_address_from_secret_key(&secret_key)?;
    // println!("New address: {:#x}", new_address);

    // // Connect the client to a node
    // let eth_client = EthClient::new(RPC_URL);

    // // Transfer funds from a rich wallet to the keystore's account
    // let rich_wallet_pk = SecretKey::from_str(RICH_WALLET_PK)?;
    // let rich_wallet_address = get_address_from_secret_key(&rich_wallet_pk)?;
    // let amount = U256::from_dec_str("1000000000000000000").unwrap();
    // let nonce = eth_client.get_nonce(rich_wallet_address).await.unwrap();
    // let transfer_tx_hash = transfer(
    //     amount,
    //     rich_wallet_address,
    //     new_address,
    //     rich_wallet_pk,
    //     &eth_client,
    //     Overrides {
    //         value: Some(amount),
    //         nonce: Some(nonce),
    //         chain_id: Some(9),
    //         ..Default::default()
    //     },
    // )
    // .await?;

    // let transfer_receipt =
    //     wait_for_transaction_receipt(transfer_tx_hash, &eth_client, 10, true).await?;
    // println!("Transfer Receipt: {transfer_receipt:?}");

    // // Deploy a contract.
    // let nonce = eth_client.get_nonce(new_address).await.unwrap();

    // let bytecode = hex::decode(read_to_string(
    //     "examples/contracts/solc_out/RecoverSigner.bin",
    // )?)?;

    // let (contract_tx_hash, deployed_address) = eth_client
    //     .deploy(
    //         new_address,
    //         secret_key,
    //         Bytes::from(bytecode),
    //         Overrides {
    //             value: Some(U256::from_dec_str("2000000000")?),
    //             nonce: Some(nonce),
    //             chain_id: Some(9),
    //             gas_limit: Some(2000000),
    //             max_fee_per_gas: Some(2000000),
    //             max_priority_fee_per_gas: Some(2000000),
    //             ..Default::default()
    //         },
    //     )
    //     .await?;

    // println!("Contract deployment tx hash: {contract_tx_hash:#x}");
    // println!("Contract deployment address: {deployed_address:#x}");

    // let contract_deploy_receipt =
    //     wait_for_transaction_receipt(contract_tx_hash, &eth_client, 10, true).await?;
    // println!("Contract deployment receipt: {contract_deploy_receipt:?}");

    // // Get the current block (for later).
    // let from_block = eth_client.get_block_number().await?;

    // // Prepare the calldata to call the contract function that emits a log.
    // let message = H256::random();
    // let signature = sign_hash(message, secret_key);

    // let raw_function_signature = "recoverSigner(bytes32,bytes)";

    // let arguments = vec![
    //     Value::FixedBytes(Bytes::from(message.to_fixed_bytes().to_vec())),
    //     Value::Bytes(Bytes::from(signature)),
    // ];

    // let calldata = encode_calldata(raw_function_signature, &arguments).unwrap();

    // // Call the contract signing with the private key and wait for its receipt.
    // let response = eth_client
    //     .call(
    //         deployed_address,
    //         Bytes::from(calldata),
    //         Overrides {
    //             value: Some(U256::from_dec_str("2000000")?),
    //             nonce: Some(0),
    //             chain_id: Some(9),
    //             gas_limit: Some(2000000),
    //             max_fee_per_gas: Some(2000000),
    //             max_priority_fee_per_gas: Some(20000),
    //             ..Default::default()
    //         },
    //     )
    //     .await?;

    // println!("Call response: {response}");
    // // Get the new current block.
    // let to_block = eth_client.get_block_number().await?;

    // // Get the emitted logs using the current block and the previous current block.
    // let logs = eth_client
    //     .get_logs_from_signature(
    //         from_block,
    //         to_block,
    //         deployed_address,
    //         "recoverSigner(bytes32,bytes)",
    //     )
    //     .await?;

    // println!("Logs: {:?}", logs);

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
