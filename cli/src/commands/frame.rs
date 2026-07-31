//! EIP-8141 frame transaction support (tx type 0x06).
//!
//! This uses ethrex's canonical `FrameTransaction` types directly (via the
//! `ethrex-common` dependency pinned to 21.0.0) so the wire format, `sig_hash`,
//! and RLP encoding stay in lockstep with the deployed chain and cannot drift
//! out of the spec.
//!
//! Envelope: `0x06 || rlp([chain_id, nonce, sender, frames, signatures,
//! max_priority_fee, max_fee, max_fee_per_blob_gas, blob_versioned_hashes])`
//!   - frame     = `rlp([mode, flags, target, gas_limit, value, data])`
//!   - signature = `rlp([scheme, signer, msg, signature_bytes])`
//!   - sig_hash  = `keccak(0x06 || rlp(envelope with empty-msg signature bytes elided))`
//!
//! - `mode`:  0 = DEFAULT, 1 = VERIFY, 2 = SENDER (3-255 reserved)
//! - `flags`: bit 0 = PAYMENT approval, bit 1 = EXECUTION approval, bit 2 = atomic batch
//! - a secp256k1 outer signature is `v(1) || r(32) || s(32)`, v = recovery_id + 27

use clap::Subcommand;
use ethrex_common::types::{
    FRAME_SIG_SCHEME_SECP256K1, Frame, FrameSignature, FrameTransaction, Transaction,
};
use ethrex_common::{Address, Bytes, H256, U256};
use ethrex_l2_common::utils::get_address_from_secret_key;
use ethrex_rpc::EthClient;
use ethrex_rpc::utils::{RpcRequest, RpcResponse};
use rex_sdk::sign::sign_hash;
use secp256k1::SecretKey;
use serde::Deserialize;
use std::str::FromStr;
use url::Url;

use crate::utils::{parse_hex, parse_private_key};

pub const MODE_DEFAULT: u8 = 0;
pub const MODE_VERIFY: u8 = 1;
pub const MODE_SENDER: u8 = 2;

/// Flag bitmasks (0x01 = PAYMENT, 0x02 = EXECUTION, 0x04 = atomic batch).
pub const FLAG_PAYMENT: u8 = 0x01;
pub const FLAG_EXECUTION: u8 = 0x02;
pub const FLAG_BOTH: u8 = 0x03;
pub const FLAG_ATOMIC_BATCH: u8 = 0x04;

fn mode_name(mode: u8) -> &'static str {
    match mode {
        MODE_DEFAULT => "DEFAULT",
        MODE_VERIFY => "VERIFY",
        MODE_SENDER => "SENDER",
        _ => "RESERVED",
    }
}

/// Human-readable flag decode: APPROVE scope + atomic-batch bit.
fn flags_desc(flags: u8) -> String {
    let scope = match flags & 0x03 {
        0x00 => "APPROVE none",
        FLAG_PAYMENT => "APPROVE payment",
        FLAG_EXECUTION => "APPROVE execution",
        FLAG_BOTH => "APPROVE execution+payment",
        _ => unreachable!(),
    };
    if flags & FLAG_ATOMIC_BATCH != 0 {
        format!("{scope}, atomic-batch")
    } else {
        scope.to_string()
    }
}

/// A secp256k1 outer signature over `sig_hash`, encoded as ethrex expects
/// (`v || r || s`, v = recovery_id + 27). `msg` is empty, so its signature bytes
/// are elided from the sig_hash; `signer` is the account whose key signed.
fn secp256k1_signature(sig_hash: H256, signer: Address, secret: &SecretKey) -> FrameSignature {
    // sign_hash returns r(32) || s(32) || v(1, already +27).
    let sig = sign_hash(sig_hash, *secret);
    let mut bytes = Vec::with_capacity(65);
    bytes.push(sig[64]); // v
    bytes.extend_from_slice(&sig[0..32]); // r
    bytes.extend_from_slice(&sig[32..64]); // s
    FrameSignature {
        scheme: FRAME_SIG_SCHEME_SECP256K1,
        signer,
        msg: Bytes::new(),
        signature: Bytes::from(bytes),
    }
}

/// An empty-bytes signature placeholder: fixes the signatures-list length,
/// scheme, signer and (empty) msg so `compute_sig_hash` sees the final structure.
/// The empty bytes are elided from the hash and filled in after signing.
fn signature_placeholder(signer: Address) -> FrameSignature {
    FrameSignature {
        scheme: FRAME_SIG_SCHEME_SECP256K1,
        signer,
        msg: Bytes::new(),
        signature: Bytes::new(),
    }
}

fn raw_canonical(tx: FrameTransaction) -> Vec<u8> {
    Transaction::FrameTransaction(tx).encode_canonical_to_vec()
}

fn u256_to_u64(v: U256, field: &str) -> eyre::Result<u64> {
    u64::try_from(v).map_err(|_| eyre::eyre!("{field} does not fit in u64: {v}"))
}

/// Parse a "1ether"/"1.5gwei"/"0x…"/plain-wei amount into a wei `U256`.
fn parse_amount(s: &str) -> eyre::Result<U256> {
    const UNITS: &[(&str, u32)] = &[
        ("ether", 18),
        ("finney", 15),
        ("szabo", 12),
        ("gwei", 9),
        ("mwei", 6),
        ("kwei", 3),
        ("wei", 0),
    ];
    let trimmed = s.trim();
    let lower = trimmed.to_ascii_lowercase();
    let (num, decimals) = UNITS
        .iter()
        .find_map(|(unit, decimals)| {
            lower.strip_suffix(unit).map(|_| {
                (
                    trimmed
                        .get(..lower.len() - unit.len())
                        .unwrap_or("")
                        .trim_end(),
                    *decimals,
                )
            })
        })
        .unwrap_or((trimmed, 0));

    if let Some(rest) = num.strip_prefix("0x") {
        if decimals != 0 {
            return Err(eyre::eyre!("hex amounts cannot carry a unit suffix: {s}"));
        }
        return Ok(U256::from_str(&format!("0x{rest}"))?);
    }

    let (int_part, frac_part) = num.split_once('.').unwrap_or((num, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(eyre::eyre!("empty amount: {s}"));
    }
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return Err(eyre::eyre!("invalid digits in amount: {s}"));
    }
    let frac_len =
        u32::try_from(frac_part.len()).map_err(|_| eyre::eyre!("fractional part too long: {s}"))?;
    if frac_len > decimals {
        return Err(eyre::eyre!("too many fractional digits for unit: {s}"));
    }
    let scale_zeros = decimals
        .checked_sub(frac_len)
        .ok_or_else(|| eyre::eyre!("scale overflow: {s}"))?;
    let mut combined = String::with_capacity(int_part.len() + frac_part.len() + 1);
    combined.push_str(int_part);
    combined.push_str(frac_part);
    for _ in 0..scale_zeros {
        combined.push('0');
    }
    let combined = combined.trim_start_matches('0');
    if combined.is_empty() {
        Ok(U256::zero())
    } else {
        Ok(U256::from_dec_str(combined)?)
    }
}

// ------ CLI ------------------------------------------------------------------

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Command {
    #[clap(about = "Send a frame (EIP-8141, tx type 0x06) transaction.")]
    Send {
        #[arg(long, help = "Recipient of the SENDER frame.")]
        to: Address,
        #[arg(
            long,
            default_value = "0",
            value_parser = parse_amount,
            help = "Amount to transfer. Accepts unit suffixes: 1ether, 1.5gwei, or plain wei."
        )]
        value: U256,
        #[arg(
            long,
            default_value = "",
            value_parser = parse_hex,
            help = "Calldata for the SENDER frame. Empty for plain ETH transfer."
        )]
        data: Bytes,
        #[arg(
            long,
            help = "Optional gas-sponsor (paymaster) address for a sponsored tx."
        )]
        sponsor: Option<Address>,
        #[arg(
            long,
            default_value = "",
            value_parser = parse_hex,
            requires = "sponsor",
            help = "Static calldata passed to the sponsor's VERIFY frame (e.g. 0xfc735e99 for GasSponsor)."
        )]
        sponsor_calldata: Bytes,
        #[arg(
            long,
            value_parser = parse_private_key,
            requires = "sponsor",
            env = "SPONSOR_OWNER_KEY",
            help = "Private key that owns the sponsor contract. When set, a second outer signature (signer = the owner) is added to the signatures list."
        )]
        sponsor_owner_key: Option<SecretKey>,
        #[arg(long, default_value_t = 100_000)]
        frame_gas_limit: u64,
        #[arg(long, default_value_t = 200_000)]
        sponsor_gas_limit: u64,
        #[arg(long, value_parser = parse_amount)]
        max_fee_per_gas: Option<U256>,
        #[arg(
            long,
            default_value = "1gwei",
            value_parser = parse_amount,
            help = "maxPriorityFeePerGas. Accepts unit suffixes."
        )]
        max_priority_fee_per_gas: U256,
        #[arg(long, value_parser = parse_private_key, env = "PRIVATE_KEY")]
        private_key: SecretKey,
        #[arg(long, default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: Url,
        #[arg(long, help = "Print the raw tx hex instead of sending it.")]
        dry_run: bool,
    },
    #[clap(
        about = "Build a raw frame tx from explicit frames (no RPC calls).",
        long_about = "Build a frame tx envelope from explicit parameters. --frames is a JSON \
                      array of {mode, flags, target, gasLimit, value, data} objects. The \
                      envelope is left unsigned (empty signatures list); useful for inspecting \
                      the raw 0x06 bytes before sending."
    )]
    Build {
        #[arg(long)]
        chain_id: u64,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        sender: Address,
        #[arg(
            long,
            help = "JSON array of frames, e.g. '[{\"mode\":1,\"flags\":3,\"target\":\"0x…\",\"gasLimit\":100000,\"value\":\"0\",\"data\":\"0x\"}]'."
        )]
        frames: String,
        #[arg(long, default_value = "10gwei", value_parser = parse_amount)]
        max_fee: U256,
        #[arg(long, default_value = "1gwei", value_parser = parse_amount)]
        max_priority_fee: U256,
    },
    #[clap(
        about = "Inspect a frame tx: decode its frames and pair them with their per-frame results.",
        alias = "receipt"
    )]
    Inspect {
        tx_hash: H256,
        #[arg(long, default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: Url,
    },
}

#[derive(Deserialize)]
struct FrameJson {
    mode: u8,
    #[serde(default)]
    flags: u8,
    #[serde(default)]
    target: Option<Address>,
    #[serde(alias = "gasLimit", alias = "gas_limit")]
    gas_limit: u64,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    data: String,
}

impl Command {
    pub async fn run(self) -> eyre::Result<()> {
        match self {
            Command::Send {
                to,
                value,
                data,
                sponsor,
                sponsor_calldata,
                sponsor_owner_key,
                frame_gas_limit,
                sponsor_gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                private_key,
                rpc_url,
                dry_run,
            } => {
                let client = EthClient::new(rpc_url.clone())?;
                let sender = get_address_from_secret_key(&private_key.secret_bytes())
                    .map_err(|e| eyre::eyre!(e))?;

                let chain_id = client.get_chain_id().await?;
                let nonce = client
                    .get_nonce(
                        sender,
                        ethrex_rpc::types::block_identifier::BlockIdentifier::Tag(
                            ethrex_rpc::types::block_identifier::BlockTag::Latest,
                        ),
                    )
                    .await?;
                let max_fee = match max_fee_per_gas {
                    Some(f) => f,
                    None => {
                        let gas_price = client.get_gas_price().await?;
                        let doubled = gas_price.saturating_mul(U256::from(2u64));
                        U256::max(doubled, U256::from(10_000_000_000u64))
                    }
                };

                // Build the frames. SENDER frames carry their value/data directly
                // (per-frame `value`), not an encoded call list in `data`.
                let (frames, mut signatures) = if let Some(sponsor_addr) = sponsor {
                    let owner = match &sponsor_owner_key {
                        Some(k) => get_address_from_secret_key(&k.secret_bytes())
                            .map_err(|e| eyre::eyre!(e))?,
                        None => sponsor_addr,
                    };
                    (
                        vec![
                            Frame {
                                mode: MODE_VERIFY,
                                flags: FLAG_EXECUTION,
                                target: Some(sender),
                                gas_limit: frame_gas_limit,
                                value: U256::zero(),
                                data: Bytes::new(),
                            },
                            Frame {
                                mode: MODE_VERIFY,
                                flags: FLAG_PAYMENT,
                                target: Some(sponsor_addr),
                                gas_limit: sponsor_gas_limit,
                                value: U256::zero(),
                                data: sponsor_calldata,
                            },
                            Frame {
                                mode: MODE_SENDER,
                                flags: 0,
                                target: Some(to),
                                gas_limit: frame_gas_limit,
                                value,
                                data,
                            },
                        ],
                        // sender approves execution; owner (or sponsor) approves payment.
                        vec![signature_placeholder(sender), signature_placeholder(owner)],
                    )
                } else {
                    (
                        vec![
                            Frame {
                                mode: MODE_VERIFY,
                                flags: FLAG_BOTH,
                                target: Some(sender),
                                gas_limit: frame_gas_limit,
                                value: U256::zero(),
                                data: Bytes::new(),
                            },
                            Frame {
                                mode: MODE_SENDER,
                                flags: 0,
                                target: Some(to),
                                gas_limit: frame_gas_limit,
                                value,
                                data,
                            },
                        ],
                        vec![signature_placeholder(sender)],
                    )
                };

                let chain_id_u64: u64 = chain_id
                    .try_into()
                    .map_err(|_| eyre::eyre!("chain id {chain_id} does not fit in u64"))?;

                let mut tx = FrameTransaction {
                    chain_id: chain_id_u64,
                    nonce,
                    sender,
                    frames,
                    signatures: signatures.clone(),
                    max_priority_fee_per_gas: u256_to_u64(
                        max_priority_fee_per_gas,
                        "max_priority_fee_per_gas",
                    )?,
                    max_fee_per_gas: u256_to_u64(max_fee, "max_fee_per_gas")?,
                    max_fee_per_blob_gas: U256::zero(),
                    blob_versioned_hashes: Vec::new(),
                    ..Default::default()
                };

                // Sign the sig_hash (signatures' empty-msg bytes are elided from it),
                // then fill the real signature bytes back in.
                let sig_hash = tx.compute_sig_hash();
                signatures[0] = secp256k1_signature(sig_hash, sender, &private_key);
                if let Some(owner_key) = &sponsor_owner_key {
                    let owner = get_address_from_secret_key(&owner_key.secret_bytes())
                        .map_err(|e| eyre::eyre!(e))?;
                    signatures[1] = secp256k1_signature(sig_hash, owner, owner_key);
                }
                // Set the real signatures before any canonical encoding runs, so
                // the (still-empty) canonical cache is populated from the signed tx.
                tx.signatures = signatures;

                let raw = raw_canonical(tx);

                if dry_run {
                    println!("sig_hash:  0x{sig_hash:x}");
                    println!("raw_tx:    0x{}", hex::encode(&raw));
                    println!("size:      {} bytes", raw.len());
                    return Ok(());
                }

                let tx_hash = client.send_raw_transaction(&raw).await?;
                println!("{tx_hash:#x}");
                // The typed RpcReceipt doesn't model tx type 0x06, so inspect via raw JSON.
                poll_and_inspect(&client, tx_hash, 100).await
            }
            Command::Build {
                chain_id,
                nonce,
                sender,
                frames,
                max_fee,
                max_priority_fee,
            } => {
                let parsed: Vec<FrameJson> = serde_json::from_str(&frames)?;
                let mut out_frames = Vec::with_capacity(parsed.len());
                for f in parsed {
                    let data_bytes = if f.data.is_empty() {
                        Bytes::new()
                    } else {
                        let s = f.data.strip_prefix("0x").unwrap_or(&f.data);
                        Bytes::from(hex::decode(s)?)
                    };
                    let value = match f.value {
                        Some(v) => parse_amount(&v)?,
                        None => U256::zero(),
                    };
                    out_frames.push(Frame {
                        mode: f.mode,
                        flags: f.flags,
                        target: f.target,
                        gas_limit: f.gas_limit,
                        value,
                        data: data_bytes,
                    });
                }
                let tx = FrameTransaction {
                    chain_id,
                    nonce,
                    sender,
                    frames: out_frames,
                    signatures: Vec::new(),
                    max_priority_fee_per_gas: u256_to_u64(max_priority_fee, "max_priority_fee")?,
                    max_fee_per_gas: u256_to_u64(max_fee, "max_fee")?,
                    max_fee_per_blob_gas: U256::zero(),
                    blob_versioned_hashes: Vec::new(),
                    ..Default::default()
                };
                println!("0x{}", hex::encode(raw_canonical(tx)));
                Ok(())
            }
            Command::Inspect { tx_hash, rpc_url } => {
                let client = EthClient::new(rpc_url)?;
                inspect_frame_tx(&client, tx_hash).await
            }
        }
    }
}

async fn send_raw_rpc(
    client: &EthClient,
    method: &str,
    tx_hash: H256,
) -> eyre::Result<serde_json::Value> {
    let request = RpcRequest::new(
        method,
        Some(vec![serde_json::json!(format!("0x{tx_hash:x}"))]),
    );
    match client.send_request(request).await? {
        RpcResponse::Success(s) => Ok(s.result),
        RpcResponse::Error(e) => Err(eyre::eyre!("rpc error: {}", e.error.message)),
    }
}

async fn inspect_frame_tx(client: &EthClient, tx_hash: H256) -> eyre::Result<()> {
    let receipt = send_raw_rpc(client, "eth_getTransactionReceipt", tx_hash).await?;
    let receipt = receipt
        .as_object()
        .ok_or_else(|| eyre::eyre!("receipt not found for {tx_hash:#x}"))?;
    // The transaction carries the frames themselves (the receipt only has results).
    let tx = send_raw_rpc(client, "eth_getTransactionByHash", tx_hash)
        .await
        .ok()
        .and_then(|v| v.as_object().cloned());
    print_frame_tx(tx.as_ref(), receipt);
    Ok(())
}

async fn poll_and_inspect(client: &EthClient, tx_hash: H256, max_retries: u64) -> eyre::Result<()> {
    for attempt in 1..=max_retries {
        let value = send_raw_rpc(client, "eth_getTransactionReceipt", tx_hash).await?;
        if value.as_object().is_some() {
            return inspect_frame_tx(client, tx_hash).await;
        }
        if attempt == max_retries {
            return Err(eyre::eyre!(
                "receipt for {tx_hash:#x} not found after {max_retries} retries"
            ));
        }
        println!("[{attempt}/{max_retries}] waiting for receipt…");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    Ok(())
}

fn s<'a>(obj: &'a serde_json::Map<String, serde_json::Value>, key: &str) -> &'a str {
    obj.get(key).and_then(|v| v.as_str()).unwrap_or("?")
}

/// Print a unified, decoded view: header (sender/payer/nonce/fees) + a
/// frame-by-frame listing pairing each frame (mode, flags, target, value, data)
/// with its result (status, gas, #logs). Works with just the receipt when the
/// transaction body isn't available (e.g. still pending).
fn print_frame_tx(
    tx: Option<&serde_json::Map<String, serde_json::Value>>,
    receipt: &serde_json::Map<String, serde_json::Value>,
) {
    let status = match s(receipt, "status") {
        "0x1" => "SUCCESS",
        "0x0" => "FAILED",
        other => other,
    };
    println!("Frame transaction (type 0x06)");
    println!("  status:    {status}");
    println!("  block:     {}", s(receipt, "blockNumber"));
    println!("  gas used:  {}", s(receipt, "gasUsed"));

    // The canonical FrameTransaction JSON names the account `sender`; RPC
    // transaction objects conventionally also expose `from`.
    let sender = tx.and_then(|t| {
        t.get("from")
            .or_else(|| t.get("sender"))
            .and_then(|v| v.as_str())
    });
    let payer = receipt.get("payer").and_then(|v| v.as_str());
    match (payer, sender) {
        (Some(p), Some(f)) if p.eq_ignore_ascii_case(f) => println!("  payer:     {p} (self)"),
        (Some(p), _) => println!("  payer:     {p}"),
        (None, _) => println!("  payer:     N/A"),
    }
    if let Some(t) = tx {
        if let Some(sender) = sender {
            println!("  sender:    {sender}");
        }
        println!("  nonce:     {}", s(t, "nonce"));
        println!(
            "  maxFee:    {}  maxPriorityFee: {}",
            s(t, "maxFeePerGas"),
            s(t, "maxPriorityFeePerGas")
        );
        if let Some(sigs) = t.get("signatures").and_then(|v| v.as_array()) {
            println!("  signatures: {}", sigs.len());
        }
    }

    let frames = tx.and_then(|t| t.get("frames").and_then(|v| v.as_array()));
    let results = receipt.get("frameReceipts").and_then(|v| v.as_array());
    let frame_count = frames.map(|f| f.len()).unwrap_or(0);
    let result_count = results.map(|r| r.len()).unwrap_or(0);
    let count = frame_count.max(result_count);

    println!("  frames:    {count}");
    for i in 0..count {
        let frame = frames.and_then(|f| f.get(i)).and_then(|v| v.as_object());
        let result = results.and_then(|r| r.get(i)).and_then(|v| v.as_object());

        // Frame structure (from the tx body).
        let header = if let Some(fr) = frame {
            let mode = fr
                .get("mode")
                .and_then(|v| v.as_str())
                .and_then(|h| u8::from_str_radix(h.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            let flags = fr
                .get("flags")
                .and_then(|v| v.as_str())
                .and_then(|h| u8::from_str_radix(h.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            let target = fr.get("to").and_then(|v| v.as_str()).unwrap_or("(none)");
            let value = fr.get("value").and_then(|v| v.as_str()).unwrap_or("0x0");
            let data_len = fr
                .get("data")
                .and_then(|v| v.as_str())
                .map(|d| d.trim_start_matches("0x").len() / 2)
                .unwrap_or(0);
            format!(
                "{} [{}] -> {target}  value {value}  data {data_len}B",
                mode_name(mode),
                flags_desc(flags)
            )
        } else {
            "(frame body unavailable)".to_string()
        };

        // Per-frame result (from the receipt).
        let result_str = if let Some(rr) = result {
            let ok = match rr.get("status").and_then(|v| v.as_str()).unwrap_or("?") {
                "0x1" => "\u{2713}",
                "0x0" => "\u{2717}",
                other => other,
            };
            let gas = rr.get("gasUsed").and_then(|v| v.as_str()).unwrap_or("?");
            let logs = rr
                .get("logs")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            format!("{ok} gas {gas}, {logs} logs")
        } else {
            "(no result)".to_string()
        };

        println!("    [{i}] {header}");
        println!("        {result_str}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender_addr() -> Address {
        Address::from_str("0x8943545177806ed17b9f23f0a21ee5948ecaa776").unwrap()
    }

    #[test]
    fn parse_amount_basics() {
        assert_eq!(
            parse_amount("1ether").unwrap(),
            U256::from_dec_str("1000000000000000000").unwrap()
        );
        assert_eq!(parse_amount("1gwei").unwrap(), U256::from(1_000_000_000u64));
        assert_eq!(parse_amount("100").unwrap(), U256::from(100u64));
    }

    fn self_verify_tx() -> FrameTransaction {
        FrameTransaction {
            chain_id: 1,
            nonce: 0,
            sender: sender_addr(),
            frames: vec![
                Frame {
                    mode: MODE_VERIFY,
                    flags: FLAG_BOTH,
                    target: Some(sender_addr()),
                    gas_limit: 100_000,
                    value: U256::zero(),
                    data: Bytes::new(),
                },
                Frame {
                    mode: MODE_SENDER,
                    flags: 0,
                    target: Some(sender_addr()),
                    gas_limit: 30_000,
                    value: U256::from(1u64),
                    data: Bytes::new(),
                },
            ],
            signatures: vec![signature_placeholder(sender_addr())],
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 2,
            max_fee_per_blob_gas: U256::zero(),
            blob_versioned_hashes: Vec::new(),
            ..Default::default()
        }
    }

    #[test]
    fn envelope_starts_with_0x06() {
        let raw = raw_canonical(self_verify_tx());
        assert_eq!(raw[0], 0x06);
    }

    #[test]
    fn sig_hash_elides_empty_msg_signature_bytes() {
        // Empty-msg signature bytes must not change the sig_hash (so we can
        // compute it with a placeholder and fill the real bytes afterward).
        let mut a = self_verify_tx();
        let mut b = self_verify_tx();
        a.signatures[0].signature = Bytes::from(vec![0xaa; 65]);
        b.signatures[0].signature = Bytes::from(vec![0xbb; 65]);
        assert_eq!(a.compute_sig_hash(), b.compute_sig_hash());
    }

    #[test]
    fn sig_hash_covers_sender_frame_value() {
        let a = self_verify_tx();
        let mut b = self_verify_tx();
        b.frames[1].value = U256::from(2u64);
        assert_ne!(a.compute_sig_hash(), b.compute_sig_hash());
    }

    #[test]
    fn secp256k1_signature_is_v_r_s() {
        let sig_hash = H256::from_low_u64_be(42);
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let signer = sender_addr();
        let fs = secp256k1_signature(sig_hash, signer, &sk);
        assert_eq!(fs.scheme, FRAME_SIG_SCHEME_SECP256K1);
        assert_eq!(fs.signer, signer);
        assert!(fs.msg.is_empty());
        assert_eq!(fs.signature.len(), 65);
        // v sits at byte 0 (ethrex parses v || r || s), already +27.
        assert!(fs.signature[0] == 27 || fs.signature[0] == 28);
    }

    #[test]
    fn flags_and_mode_decode() {
        assert_eq!(mode_name(MODE_VERIFY), "VERIFY");
        assert_eq!(mode_name(MODE_SENDER), "SENDER");
        assert_eq!(mode_name(3), "RESERVED");
        assert_eq!(flags_desc(FLAG_BOTH), "APPROVE execution+payment");
        assert_eq!(
            flags_desc(FLAG_PAYMENT | FLAG_ATOMIC_BATCH),
            "APPROVE payment, atomic-batch"
        );
    }
}
