use crate::client::{EthClient, EthClientError, Overrides};
use ethrex_common::types::GenericTransaction;
use ethrex_common::{Address, H256, U256};
use ethrex_rpc::types::receipt::RpcReceipt;
use secp256k1::SecretKey;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use tracing::{info, trace};

pub mod calldata;
pub mod client;
pub mod create;
pub mod errors;
pub mod keystore;
pub mod sign;
pub mod utils;

pub mod l2;

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("Failed to parse address from hex")]
    FailedToParseAddressFromHex,
}

pub async fn transfer(
    amount: U256,
    from: Address,
    to: Address,
    private_key: &SecretKey,
    client: &EthClient,
) -> Result<H256, EthClientError> {
    let gas_price = client
        .get_gas_price_with_extra(20)
        .await?
        .try_into()
        .map_err(|_| {
            EthClientError::InternalError("Failed to convert gas_price to a u64".to_owned())
        })?;

    let mut tx = client
        .build_eip1559_transaction(
            to,
            from,
            Default::default(),
            Overrides {
                value: Some(amount),
                max_fee_per_gas: Some(gas_price),
                max_priority_fee_per_gas: Some(gas_price),
                ..Default::default()
            },
        )
        .await?;

    let mut tx_generic: GenericTransaction = tx.clone().into();
    tx_generic.from = from;
    let gas_limit = client.estimate_gas(tx_generic).await?;
    tx.gas_limit = gas_limit;
    client.send_eip1559_transaction(&tx, private_key).await
}

pub async fn wait_for_transaction_receipt(
    tx_hash: H256,
    client: &EthClient,
    max_retries: u64,
    silent: bool,
) -> Result<RpcReceipt, EthClientError> {
    let mut receipt = client.get_transaction_receipt(tx_hash).await?;
    let mut r#try = 1;
    while receipt.is_none() {
        if !silent {
            println!("[{try}/{max_retries}] Retrying to get transaction receipt for {tx_hash:#x}");
        }

        if max_retries == r#try {
            return Err(EthClientError::Custom(format!(
                "Transaction receipt for {tx_hash:#x} not found after {max_retries} retries"
            )));
        }
        r#try += 1;

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        receipt = client.get_transaction_receipt(tx_hash).await?;
    }
    receipt.ok_or(EthClientError::Custom(
        "Transaction receipt is None".to_owned(),
    ))
}

pub fn balance_in_eth(eth: bool, balance: U256) -> String {
    if eth {
        let mut balance = format!("{balance}");
        let len = balance.len();

        balance = match len {
            18 => {
                let mut front = "0.".to_owned();
                front.push_str(&balance);
                front
            }
            0..=17 => {
                let mut front = "0.".to_owned();
                let zeros = "0".repeat(18 - len);
                front.push_str(&zeros);
                front.push_str(&balance);
                front
            }
            19.. => {
                balance.insert(len - 18, '.');
                balance
            }
        };
        balance
    } else {
        format!("{balance}")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("Failed to clone: {0}")]
    DependencyError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Failed to get string from path")]
    FailedToGetStringFromPath,
}

pub fn download_contract_deps(contracts_path: &Path) -> Result<(), GitError> {
    trace!("Downloading contract dependencies");
    std::fs::create_dir_all(contracts_path.join("lib")).map_err(|err| {
        GitError::DependencyError(format!("Failed to create contracts/lib: {err}"))
    })?;

    git_clone(
        "https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git",
        contracts_path
            .join("lib/openzeppelin-contracts-upgradeable")
            .to_str()
            .ok_or(GitError::FailedToGetStringFromPath)?,
        None,
        true,
    )?;

    git_clone(
        "https://github.com/succinctlabs/sp1-contracts.git",
        contracts_path
            .join("lib/sp1-contracts")
            .to_str()
            .ok_or(GitError::FailedToGetStringFromPath)?,
        None,
        false,
    )?;

    trace!("Contract dependencies downloaded");
    Ok(())
}

pub fn git_clone(
    repository_url: &str,
    outdir: &str,
    branch: Option<&str>,
    submodules: bool,
) -> Result<ExitStatus, GitError> {
    info!(repository_url = %repository_url, outdir = %outdir, branch = ?branch, "Cloning or updating git repository");

    if PathBuf::from(outdir).join(".git").exists() {
        info!(outdir = %outdir, "Found existing git repository, updating...");

        let branch_name = if let Some(b) = branch {
            b.to_string()
        } else {
            // Look for default branch name (could be main, master or other)
            let output = Command::new("git")
                .current_dir(outdir)
                .arg("symbolic-ref")
                .arg("refs/remotes/origin/HEAD")
                .output()
                .map_err(|e| {
                    GitError::DependencyError(format!(
                        "Failed to get default branch for {outdir}: {e}"
                    ))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(GitError::DependencyError(format!(
                    "Failed to get default branch for {outdir}: {stderr}"
                )));
            }

            String::from_utf8(output.stdout)
                .map_err(|_| GitError::InternalError("Failed to parse git output".to_string()))?
                .trim()
                .split('/')
                .next_back()
                .ok_or(GitError::InternalError(
                    "Failed to parse default branch".to_string(),
                ))?
                .to_string()
        };

        trace!(branch = %branch_name, "Updating to branch");

        // Fetch
        let fetch_status = Command::new("git")
            .current_dir(outdir)
            .args(["fetch", "origin"])
            .spawn()
            .map_err(|err| GitError::DependencyError(format!("Failed to spawn git fetch: {err}")))?
            .wait()
            .map_err(|err| {
                GitError::DependencyError(format!("Failed to wait for git fetch: {err}"))
            })?;
        if !fetch_status.success() {
            return Err(GitError::DependencyError(format!(
                "git fetch failed for {outdir}"
            )));
        }

        // Checkout to branch
        let checkout_status = Command::new("git")
            .current_dir(outdir)
            .arg("checkout")
            .arg(&branch_name)
            .spawn()
            .map_err(|err| {
                GitError::DependencyError(format!("Failed to spawn git checkout: {err}"))
            })?
            .wait()
            .map_err(|err| {
                GitError::DependencyError(format!("Failed to wait for git checkout: {err}"))
            })?;
        if !checkout_status.success() {
            return Err(GitError::DependencyError(format!(
                "git checkout of branch {branch_name} failed for {outdir}, try deleting the repo folder"
            )));
        }

        // Reset branch to origin
        let reset_status = Command::new("git")
            .current_dir(outdir)
            .arg("reset")
            .arg("--hard")
            .arg(format!("origin/{branch_name}"))
            .spawn()
            .map_err(|err| GitError::DependencyError(format!("Failed to spawn git reset: {err}")))?
            .wait()
            .map_err(|err| {
                GitError::DependencyError(format!("Failed to wait for git reset: {err}"))
            })?;

        if !reset_status.success() {
            return Err(GitError::DependencyError(format!(
                "git reset failed for {outdir}"
            )));
        }

        // Update submodules
        if submodules {
            let submodule_status = Command::new("git")
                .current_dir(outdir)
                .arg("submodule")
                .arg("update")
                .arg("--init")
                .arg("--recursive")
                .spawn()
                .map_err(|err| {
                    GitError::DependencyError(format!(
                        "Failed to spawn git submodule update: {err}"
                    ))
                })?
                .wait()
                .map_err(|err| {
                    GitError::DependencyError(format!(
                        "Failed to wait for git submodule update: {err}"
                    ))
                })?;
            if !submodule_status.success() {
                return Err(GitError::DependencyError(format!(
                    "git submodule update failed for {outdir}"
                )));
            }
        }

        Ok(reset_status)
    } else {
        trace!(repository_url = %repository_url, outdir = %outdir, branch = ?branch, "Cloning git repository");
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
            .map_err(|err| GitError::DependencyError(format!("Failed to spawn git: {err}")))?
            .wait()
            .map_err(|err| GitError::DependencyError(format!("Failed to wait for git: {err}")))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ContractCompilationError {
    #[error("The path is not a valid utf-8 string")]
    FailedToGetStringFromPath,
    #[error("Deployer compilation error: {0}")]
    CompilationError(String),
    #[error("Could not read file")]
    FailedToReadFile(#[from] std::io::Error),
    #[error("Failed to serialize/deserialize")]
    SerializationError(#[from] serde_json::Error),
}

pub fn compile_contract(
    general_contracts_path: &Path,
    contract_path: &str,
    runtime_bin: bool,
) -> Result<(), ContractCompilationError> {
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
                    .join("openzeppelin-contracts-upgradeable")
                    .join("lib")
                    .join("openzeppelin-contracts")
                    .join("contracts")
                    .to_str()
                    .ok_or(ContractCompilationError::FailedToGetStringFromPath)?,
        )
        .arg(
            "@openzeppelin/contracts-upgradeable=".to_string()
                + general_contracts_path
                    .join("lib")
                    .join("openzeppelin-contracts-upgradeable")
                    .join("contracts")
                    .to_str()
                    .ok_or(ContractCompilationError::FailedToGetStringFromPath)?,
        )
        .arg(
            general_contracts_path
                .join(contract_path)
                .to_str()
                .ok_or(ContractCompilationError::FailedToGetStringFromPath)?,
        )
        .arg("--via-ir")
        .arg("-o")
        .arg(
            general_contracts_path
                .join("solc_out")
                .to_str()
                .ok_or(ContractCompilationError::FailedToGetStringFromPath)?,
        )
        .arg("--overwrite")
        .arg("--allow-paths")
        .arg(
            general_contracts_path
                .to_str()
                .ok_or(ContractCompilationError::FailedToGetStringFromPath)?,
        )
        .spawn()
        .map_err(|err| {
            ContractCompilationError::CompilationError(format!("Failed to spawn solc: {err}"))
        })?
        .wait()
        .map_err(|err| {
            ContractCompilationError::CompilationError(format!("Failed to wait for solc: {err}"))
        })?
        .success()
    {
        return Err(ContractCompilationError::CompilationError(
            format!("Failed to compile {contract_path}").to_owned(),
        ));
    }

    Ok(())
}

#[test]
fn test_balance_in_ether() {
    // test more than 1 ether
    assert_eq!(
        "999999999.999003869993631450",
        balance_in_eth(
            true,
            U256::from_dec_str("999999999999003869993631450").unwrap()
        )
    );

    // test 0.5
    assert_eq!(
        "0.509003869993631450",
        balance_in_eth(
            true,
            U256::from_dec_str("000000000509003869993631450").unwrap()
        )
    );

    // test 0.005
    assert_eq!(
        "0.005090038699936314",
        balance_in_eth(
            true,
            U256::from_dec_str("000000000005090038699936314").unwrap()
        )
    );

    // test 0.0
    assert_eq!("0.000000000000000000", balance_in_eth(true, U256::zero()));
}
