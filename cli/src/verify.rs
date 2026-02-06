use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;
use std::time::Duration;

use ethrex_common::Address;
use eyre::ContextCompat;
use regex::Regex;
use serde::Deserialize;

pub struct VerifyParams {
    pub contract_address: Address,
    pub contract_path: PathBuf,
    pub contract_name: Option<String>,
    pub constructor_args: Vec<u8>,
    pub remappings: Vec<(String, PathBuf)>,
    pub optimize_runs: Option<u64>,
    pub etherscan_api_key: String,
    pub chain_id: u64,
}

#[derive(Deserialize)]
struct EtherscanResponse {
    status: String,
    result: String,
    message: String,
}

pub async fn verify_contract_on_etherscan(params: VerifyParams) -> eyre::Result<()> {
    let solc_version = get_solc_version()?;

    let source_file_key = file_name_str(&params.contract_path);

    let contract_name = params.contract_name.unwrap_or_else(|| {
        params
            .contract_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    });

    let standard_json = build_standard_json_input(
        &params.contract_path,
        &params.remappings,
        params.optimize_runs,
    )?;
    let standard_json_str = serde_json::to_string(&standard_json)?;

    let constructor_args_hex = hex::encode(&params.constructor_args);

    println!("\nVerifying contract on Etherscan...");
    println!("  Compiler version: {solc_version}");
    println!("  Contract name: {contract_name}");

    let client = reqwest::Client::new();

    println!("  Submitting verification request...");

    let chain_id_str = params.chain_id.to_string();
    let contract_address_str = format!("{:#x}", params.contract_address);
    let contract_name_str = format!("{source_file_key}:{contract_name}");

    let form = [
        ("apikey", params.etherscan_api_key.as_str()),
        ("module", "contract"),
        ("action", "verifysourcecode"),
        ("contractaddress", &contract_address_str),
        ("sourceCode", &standard_json_str),
        ("codeformat", "solidity-standard-json-input"),
        ("contractname", &contract_name_str),
        ("compilerversion", &solc_version),
        ("constructorArguements", &constructor_args_hex),
    ];

    let url = format!("{ETHERSCAN_API_V2}?chainid={chain_id_str}");

    // Etherscan may not have indexed the contract yet, retry submission
    let guid = {
        const MAX_SUBMIT_RETRIES: u32 = 12;
        const SUBMIT_INTERVAL: Duration = Duration::from_secs(10);
        let mut guid = None;

        for attempt in 1..=MAX_SUBMIT_RETRIES {
            let resp = client
                .post(&url)
                .form(&form)
                .send()
                .await?
                .json::<EtherscanResponse>()
                .await?;

            if resp.status == "1" {
                println!("  Verification submitted (GUID: {})", resp.result);
                guid = Some(resp.result);
                break;
            }

            if resp.result.contains("Unable to locate") {
                println!(
                    "  [{attempt}/{MAX_SUBMIT_RETRIES}] Waiting for Etherscan to index the contract..."
                );
                tokio::time::sleep(SUBMIT_INTERVAL).await;
                continue;
            }

            return Err(eyre::eyre!(
                "Etherscan verification submission failed: {} ({})",
                resp.result,
                resp.message,
            ));
        }

        guid.ok_or_else(|| {
            eyre::eyre!("Etherscan did not index the contract after {MAX_SUBMIT_RETRIES} retries")
        })?
    };

    poll_verification_status(&client, &params.etherscan_api_key, &chain_id_str, &guid).await?;

    let explorer_base = etherscan_explorer_url(params.chain_id);
    println!(
        "  {explorer_base}/address/{:#x}#code",
        params.contract_address
    );

    Ok(())
}

fn build_standard_json_input(
    contract_path: &Path,
    remappings: &[(String, PathBuf)],
    optimize_runs: Option<u64>,
) -> eyre::Result<serde_json::Value> {
    let sources = resolve_sources(contract_path, remappings)?;

    let remappings_list: Vec<String> = remappings
        .iter()
        .map(|(prefix, path)| format!("{prefix}={}", path.display()))
        .collect();

    let optimizer = match optimize_runs {
        Some(runs) => serde_json::json!({ "enabled": true, "runs": runs }),
        None => serde_json::json!({ "enabled": false }),
    };

    Ok(serde_json::json!({
        "language": "Solidity",
        "sources": sources.into_iter().map(|(k, v)| {
            (k, serde_json::json!({ "content": v }))
        }).collect::<serde_json::Map<String, serde_json::Value>>(),
        "settings": {
            "viaIR": true,
            "metadata": { "appendCBOR": false },
            "optimizer": optimizer,
            "remappings": remappings_list,
            "outputSelection": {
                "*": { "*": ["evm.bytecode"] }
            }
        }
    }))
}

fn resolve_sources(
    contract_path: &Path,
    remappings: &[(String, PathBuf)],
) -> eyre::Result<BTreeMap<String, String>> {
    let mut sources = BTreeMap::new();
    let mut visited = HashSet::new();

    let canonical = contract_path.canonicalize().map_err(|e| {
        eyre::eyre!(
            "Failed to resolve contract path {}: {}",
            contract_path.display(),
            e
        )
    })?;

    resolve_sources_recursive(&canonical, remappings, &mut sources, &mut visited)?;

    Ok(sources)
}

fn resolve_sources_recursive(
    file_path: &Path,
    remappings: &[(String, PathBuf)],
    sources: &mut BTreeMap<String, String>,
    visited: &mut HashSet<PathBuf>,
) -> eyre::Result<()> {
    if !visited.insert(file_path.to_path_buf()) {
        return Ok(());
    }

    let content = std::fs::read_to_string(file_path)
        .map_err(|e| eyre::eyre!("Failed to read source file {}: {}", file_path.display(), e))?;

    let key = file_name_str(file_path);

    static IMPORT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"import\s+(?:\{[^}]*\}\s+from\s+)?["']([^"']+)["']"#).expect("valid regex")
    });

    for cap in IMPORT_RE.captures_iter(&content) {
        let import_path_str = &cap[1];
        let resolved = resolve_import_path(import_path_str, file_path, remappings)?;
        resolve_sources_recursive(&resolved, remappings, sources, visited)?;
    }

    sources.insert(key, content);

    Ok(())
}

fn resolve_import_path(
    import_str: &str,
    importing_file: &Path,
    remappings: &[(String, PathBuf)],
) -> eyre::Result<PathBuf> {
    // Try remappings first
    for (prefix, target_path) in remappings {
        if let Some(rest) = import_str.strip_prefix(prefix.as_str()) {
            let rest = rest.strip_prefix('/').unwrap_or(rest);
            let resolved = target_path.join(rest);
            return resolved.canonicalize().map_err(|e| {
                eyre::eyre!(
                    "Failed to resolve remapped import '{}' -> {}: {}",
                    import_str,
                    resolved.display(),
                    e,
                )
            });
        }
    }

    // Relative import
    let parent = importing_file
        .parent()
        .context("importing file has no parent directory")?;
    let resolved = parent.join(import_str);
    resolved.canonicalize().map_err(|e| {
        eyre::eyre!(
            "Failed to resolve import '{}' relative to {}: {}",
            import_str,
            parent.display(),
            e,
        )
    })
}

/// Parses `solc --version` output like "Version: 0.8.28+commit.7893614a.Linux.g++"
/// into "v0.8.28+commit.7893614a".
fn get_solc_version() -> eyre::Result<String> {
    let output = Command::new("solc").arg("--version").output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    static SOLC_VERSION_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(\d+\.\d+\.\d+\+commit\.[0-9a-f]+)").expect("valid regex"));
    let version = SOLC_VERSION_RE
        .find(&stdout)
        .context("Could not parse solc version from output")?
        .as_str();

    Ok(format!("v{version}"))
}

fn file_name_str(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

const ETHERSCAN_API_V2: &str = "https://api.etherscan.io/v2/api";

fn etherscan_explorer_url(chain_id: u64) -> &'static str {
    match chain_id {
        1 => "https://etherscan.io",
        11155111 => "https://sepolia.etherscan.io",
        17000 => "https://holesky.etherscan.io",
        _ => "https://etherscan.io",
    }
}

async fn poll_verification_status(
    client: &reqwest::Client,
    api_key: &str,
    chain_id: &str,
    guid: &str,
) -> eyre::Result<()> {
    const MAX_RETRIES: u32 = 60;
    const POLL_INTERVAL: Duration = Duration::from_secs(5);

    for attempt in 1..=MAX_RETRIES {
        tokio::time::sleep(POLL_INTERVAL).await;

        println!("  [{attempt}/{MAX_RETRIES}] Checking verification status...");

        let resp = client
            .get(ETHERSCAN_API_V2)
            .query(&[
                ("chainid", chain_id),
                ("module", "contract"),
                ("action", "checkverifystatus"),
                ("guid", guid),
                ("apikey", api_key),
            ])
            .send()
            .await?
            .json::<EtherscanResponse>()
            .await?;

        if resp.status == "1" {
            println!("  Contract verified successfully!");
            return Ok(());
        }

        if resp.result.contains("Already Verified") {
            println!("  Contract is already verified.");
            return Ok(());
        }

        // "Pending in queue" and "Unable to locate" are normal in-progress states
        if resp.result.contains("Pending in queue") || resp.result.contains("Unable to locate") {
            continue;
        }

        // Any other non-pending result is a failure
        return Err(eyre::eyre!(
            "Etherscan verification failed: {} ({})",
            resp.result,
            resp.message,
        ));
    }

    Err(eyre::eyre!(
        "Etherscan verification timed out after {} seconds",
        MAX_RETRIES * POLL_INTERVAL.as_secs() as u32
    ))
}
