//! EIP-8141 frame transaction support (tx type 0x06).
//!
//! The frame-tx envelope is `0x06 || rlp(chain_id, nonce, sender, frames,
//! max_priority_fee, max_fee, max_blob_fee, blob_hashes)` where each frame is
//! `rlp(mode, flags, target, gas_limit, data)` (5 fields).
//!
//! - `mode`:  execution mode (1 = VERIFY, 2 = SENDER)
//! - `flags`: bitmask — 0x01 = PAYMENT approval, 0x02 = EXECUTION approval,
//!   0x03 = both, 0x04 = atomic batch
//!
//! sig_hash = keccak(0x06 || rlp(...)) with VERIFY frame data replaced by
//! empty bytes so the signature signs over the frame structure but not over
//! itself. Default EOA VERIFY data is `[0x00 (type), v, r, s]` = 66 bytes.

use clap::Subcommand;
use ethrex_common::{Address, Bytes, H256, U256};
use ethrex_l2_common::utils::get_address_from_secret_key;
use ethrex_rlp::structs::Encoder;
use ethrex_rpc::EthClient;
use ethrex_rpc::clients::eth::RpcResponse;
use ethrex_rpc::utils::RpcRequest;
use keccak_hash::keccak;
use rex_sdk::sign::sign_hash;
use secp256k1::SecretKey;
use serde::Deserialize;
use std::str::FromStr;
use url::Url;

use crate::utils::{parse_hex, parse_private_key};

pub const EXEC_MODE_VERIFY: u8 = 1;
pub const EXEC_MODE_SENDER: u8 = 2;

/// Flag bitmasks (post spec-update: 0x01=PAYMENT, 0x02=EXECUTION).
pub const FLAG_PAYMENT: u8 = 0x01;
pub const FLAG_EXECUTION: u8 = 0x02;
pub const FLAG_BOTH: u8 = 0x03;
#[allow(dead_code)] // defined for future atomic batch support
pub const FLAG_ATOMIC_BATCH: u8 = 0x04;

#[derive(Debug, Clone)]
pub struct Frame {
    pub mode: u8,
    pub flags: u8,
    pub target: Address,
    pub gas_limit: u64,
    pub data: Bytes,
}

impl Frame {
    pub fn is_verify(&self) -> bool {
        self.mode == EXEC_MODE_VERIFY
    }
}

#[derive(Debug, Clone)]
pub struct FrameTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub sender: Address,
    pub frames: Vec<Frame>,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_fee_per_blob_gas: U256,
    pub blob_versioned_hashes: Vec<H256>,
}

fn encode_frame_bytes(frame: &Frame, elide_data: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let data: &[u8] = if elide_data { &[] } else { frame.data.as_ref() };
    Encoder::new(&mut out)
        .encode_field(&(frame.mode as u64))
        .encode_field(&(frame.flags as u64))
        .encode_field(&frame.target)
        .encode_field(&frame.gas_limit)
        .encode_bytes(data)
        .finish();
    out
}

fn encode_frames_list(frames: &[Frame], elide_verify_data: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    for frame in frames {
        let single = encode_frame_bytes(frame, elide_verify_data && frame.is_verify());
        enc = enc.encode_raw(&single);
    }
    enc.finish();
    out
}

impl FrameTx {
    fn encode_payload(&self, elide_verify_data: bool) -> Vec<u8> {
        let frames_rlp = encode_frames_list(&self.frames, elide_verify_data);
        let mut payload = Vec::new();
        Encoder::new(&mut payload)
            .encode_field(&self.chain_id)
            .encode_field(&self.nonce)
            .encode_field(&self.sender)
            .encode_raw(&frames_rlp)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.max_fee_per_blob_gas)
            .encode_field(&self.blob_versioned_hashes)
            .finish();
        payload
    }

    pub fn sig_hash(&self) -> H256 {
        let payload = self.encode_payload(true);
        let mut buf = Vec::with_capacity(payload.len() + 1);
        buf.push(0x06);
        buf.extend_from_slice(&payload);
        keccak(&buf)
    }

    pub fn to_raw(&self) -> Vec<u8> {
        let payload = self.encode_payload(false);
        let mut out = Vec::with_capacity(payload.len() + 1);
        out.push(0x06);
        out.extend_from_slice(&payload);
        out
    }
}

/// Sign the sig_hash with secp256k1 and return the 66-byte default EOA VERIFY
/// data: `[0x00 (secp256k1 type), v, r, s]`.
pub fn default_eoa_verify_data(sig_hash: H256, secret: &SecretKey) -> Vec<u8> {
    // sign_hash returns [r(32), s(32), v(1, already +27)] = 65 bytes.
    let sig = sign_hash(sig_hash, *secret);
    debug_assert_eq!(sig.len(), 65);
    let r = &sig[0..32];
    let s = &sig[32..64];
    let v = sig[64];
    let mut out = Vec::with_capacity(66);
    out.push(0x00);
    out.push(v);
    out.extend_from_slice(r);
    out.extend_from_slice(s);
    out
}

/// Sign the sig_hash with the paymaster owner key and return the 65-byte
/// CanonicalPaymaster VERIFY data: `r(32) || s(32) || v(1)`. No leading
/// type byte — the paymaster contract expects exactly these 65 bytes.
pub fn paymaster_owner_verify_data(sig_hash: H256, owner_secret: &SecretKey) -> Vec<u8> {
    // sign_hash already returns r||s||v = 65 bytes with v = recovery_id + 27.
    let sig = sign_hash(sig_hash, *owner_secret);
    debug_assert_eq!(sig.len(), 65);
    sig
}

/// Default SENDER frame data: `rlp([[target, value, calldata], ...])`.
pub fn encode_sender_calls(calls: &[(Address, U256, Bytes)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut outer = Encoder::new(&mut out);
    for (target, value, data) in calls {
        let mut call_buf = Vec::new();
        Encoder::new(&mut call_buf)
            .encode_field(target)
            .encode_field(value)
            .encode_bytes(data)
            .finish();
        outer = outer.encode_raw(&call_buf);
    }
    outer.finish();
    out
}

/// Parse an amount like `1ether`, `1.5gwei`, `100mwei`, `500wei`, or a plain
/// wei integer. Duplicated here so this branch stays independent of the
/// ether-units branch.
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
        #[arg(long, help = "Recipient of the inner SENDER call.")]
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
            help = "Calldata for the inner subcall. Empty for plain ETH transfer."
        )]
        data: Bytes,
        #[arg(long, help = "Optional gas-sponsor address for a sponsored tx.")]
        sponsor: Option<Address>,
        #[arg(
            long,
            default_value = "",
            value_parser = parse_hex,
            requires = "sponsor",
            conflicts_with = "sponsor_owner_key",
            help = "Static calldata passed to the sponsor's VERIFY frame (e.g. 0xfc735e99 for GasSponsor)."
        )]
        sponsor_calldata: Bytes,
        #[arg(
            long,
            value_parser = parse_private_key,
            requires = "sponsor",
            env = "SPONSOR_OWNER_KEY",
            help = "Private key that owns the sponsor contract (e.g. CanonicalPaymaster). When set, the sponsor VERIFY frame data is r(32)||s(32)||v(1) = 65 bytes, signed by this key over the sig_hash."
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
                      array of {mode, target, gasLimit, data} objects. Useful when you want \
                      to inspect the raw 0x06 bytes before sending."
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
            help = "JSON array of frames, e.g. '[{\"mode\":769,\"target\":\"0x…\",\"gasLimit\":100000,\"data\":\"0x\"}]'."
        )]
        frames: String,
        #[arg(long, default_value = "10gwei", value_parser = parse_amount)]
        max_fee: U256,
        #[arg(long, default_value = "1gwei", value_parser = parse_amount)]
        max_priority_fee: U256,
    },
    #[clap(about = "Display a frame-tx receipt including payer and per-frame status.")]
    Receipt {
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
    target: Address,
    #[serde(alias = "gasLimit", alias = "gas_limit")]
    gas_limit: u64,
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

                let sender_data = encode_sender_calls(&[(to, value, data)]);

                let mut frames = if let Some(sponsor_addr) = sponsor {
                    vec![
                        Frame {
                            mode: EXEC_MODE_VERIFY,
                            flags: FLAG_EXECUTION,
                            target: sender,
                            gas_limit: frame_gas_limit,
                            data: Bytes::new(),
                        },
                        Frame {
                            mode: EXEC_MODE_VERIFY,
                            flags: FLAG_PAYMENT,
                            target: sponsor_addr,
                            gas_limit: sponsor_gas_limit,
                            data: sponsor_calldata,
                        },
                        Frame {
                            mode: EXEC_MODE_SENDER,
                            flags: 0,
                            target: sender,
                            gas_limit: frame_gas_limit,
                            data: sender_data.into(),
                        },
                    ]
                } else {
                    vec![
                        Frame {
                            mode: EXEC_MODE_VERIFY,
                            flags: FLAG_BOTH,
                            target: sender,
                            gas_limit: frame_gas_limit,
                            data: Bytes::new(),
                        },
                        Frame {
                            mode: EXEC_MODE_SENDER,
                            flags: 0,
                            target: sender,
                            gas_limit: frame_gas_limit,
                            data: sender_data.into(),
                        },
                    ]
                };

                let chain_id_u64: u64 = chain_id
                    .try_into()
                    .map_err(|_| eyre::eyre!("chain id {chain_id} does not fit in u64"))?;

                let unsigned = FrameTx {
                    chain_id: chain_id_u64,
                    nonce,
                    sender,
                    frames: frames.clone(),
                    max_priority_fee_per_gas,
                    max_fee_per_gas: max_fee,
                    max_fee_per_blob_gas: U256::zero(),
                    blob_versioned_hashes: Vec::new(),
                };

                let sig_hash = unsigned.sig_hash();
                let verify_data = default_eoa_verify_data(sig_hash, &private_key);
                frames[0].data = verify_data.into();

                if let Some(owner_key) = sponsor_owner_key {
                    // Sponsor VERIFY is frame index 1 in the sponsored layout.
                    // Override its data with the owner's 65-byte r||s||v signature.
                    frames[1].data = paymaster_owner_verify_data(sig_hash, &owner_key).into();
                }

                let signed_tx = FrameTx { frames, ..unsigned };
                let raw = signed_tx.to_raw();

                if dry_run {
                    println!("sig_hash:  0x{sig_hash:x}");
                    println!("raw_tx:    0x{}", hex::encode(&raw));
                    println!("size:      {} bytes", raw.len());
                    return Ok(());
                }

                let tx_hash = client.send_raw_transaction(&raw).await?;
                println!("{tx_hash:#x}");
                // Standard wait_for_transaction_receipt deserializes to the typed
                // RpcReceipt which doesn't know about tx type 0x06, so we poll
                // directly via raw JSON — same path as `rex frame receipt`.
                poll_and_print_frame_receipt(&client, tx_hash, 100).await
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
                        hex::decode(s)?.into()
                    };
                    out_frames.push(Frame {
                        mode: f.mode,
                        flags: f.flags,
                        target: f.target,
                        gas_limit: f.gas_limit,
                        data: data_bytes,
                    });
                }
                let tx = FrameTx {
                    chain_id,
                    nonce,
                    sender,
                    frames: out_frames,
                    max_priority_fee_per_gas: max_priority_fee,
                    max_fee_per_gas: max_fee,
                    max_fee_per_blob_gas: U256::zero(),
                    blob_versioned_hashes: Vec::new(),
                };
                println!("0x{}", hex::encode(tx.to_raw()));
                Ok(())
            }
            Command::Receipt { tx_hash, rpc_url } => {
                let client = EthClient::new(rpc_url)?;
                fetch_and_print_frame_receipt(&client, tx_hash).await
            }
        }
    }
}

async fn fetch_and_print_frame_receipt(client: &EthClient, tx_hash: H256) -> eyre::Result<()> {
    let value = fetch_raw_receipt(client, tx_hash).await?;
    let obj = value
        .as_object()
        .ok_or_else(|| eyre::eyre!("receipt not found for {tx_hash:#x}"))?;
    print_raw_frame_receipt(obj);
    Ok(())
}

async fn fetch_raw_receipt(client: &EthClient, tx_hash: H256) -> eyre::Result<serde_json::Value> {
    let request = RpcRequest::new(
        "eth_getTransactionReceipt",
        Some(vec![serde_json::json!(format!("0x{tx_hash:x}"))]),
    );
    let response = client.send_request(request).await?;
    match response {
        RpcResponse::Success(s) => Ok(s.result),
        RpcResponse::Error(e) => Err(eyre::eyre!("rpc error: {}", e.error.message)),
    }
}

async fn poll_and_print_frame_receipt(
    client: &EthClient,
    tx_hash: H256,
    max_retries: u64,
) -> eyre::Result<()> {
    for attempt in 1..=max_retries {
        let value = fetch_raw_receipt(client, tx_hash).await?;
        if let Some(obj) = value.as_object() {
            print_raw_frame_receipt(obj);
            return Ok(());
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

fn print_raw_frame_receipt(receipt: &serde_json::Map<String, serde_json::Value>) {
    let status_str = receipt
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let status = match status_str {
        "0x1" => "SUCCESS",
        "0x0" => "FAILED",
        other => other,
    };
    let block = receipt
        .get("blockNumber")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let gas_used = receipt
        .get("gasUsed")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let payer = receipt
        .get("payer")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    println!("Status:    {status}");
    println!("Block:     {block}");
    println!("Gas used:  {gas_used}");
    println!("Payer:     {payer}");

    if let Some(frame_receipts) = receipt.get("frameReceipts").and_then(|v| v.as_array()) {
        println!("Frames:    {}", frame_receipts.len());
        for (i, fr) in frame_receipts.iter().enumerate() {
            let st = fr.get("status").and_then(|v| v.as_str()).unwrap_or("?");
            let st = match st {
                "0x1" => "OK",
                "0x0" => "FAIL",
                other => other,
            };
            let gas = fr.get("gasUsed").and_then(|v| v.as_str()).unwrap_or("?");
            let logs_count = fr
                .get("logs")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            println!("  Frame {i}: {st}, gas={gas}, logs={logs_count}");
        }
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

    #[test]
    fn encode_sender_calls_single_transfer_layout() {
        let recipient = Address::from_str("0x0000000000000000000000000000000000c0ffee").unwrap();
        let encoded = encode_sender_calls(&[(
            recipient,
            U256::from(10_000_000_000_000_000u64),
            Bytes::new(),
        )]);
        // Inner list = [address(21 RLP), uint 10^16 (8 RLP), 0x80] = 30 bytes body
        //   -> prefix 0xde (0xc0 + 30) -> 31 bytes total.
        // Outer list = the 31-byte inner -> prefix 0xdf (0xc0 + 31) -> 32 bytes.
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded[0], 0xc0 + 31);
        assert_eq!(encoded[1], 0xc0 + 30);
    }

    #[test]
    fn sig_hash_elides_verify_data() {
        let tx_a = FrameTx {
            chain_id: 1,
            nonce: 0,
            sender: sender_addr(),
            frames: vec![Frame {
                mode: EXEC_MODE_VERIFY,
                flags: FLAG_BOTH,
                target: sender_addr(),
                gas_limit: 100_000,
                data: Bytes::from(vec![0xaa; 66]),
            }],
            max_priority_fee_per_gas: U256::from(1u64),
            max_fee_per_gas: U256::from(2u64),
            max_fee_per_blob_gas: U256::zero(),
            blob_versioned_hashes: Vec::new(),
        };
        let mut tx_b = tx_a.clone();
        tx_b.frames[0].data = Bytes::from(vec![0xbb; 66]);
        assert_eq!(tx_a.sig_hash(), tx_b.sig_hash());
        assert_ne!(tx_a.to_raw(), tx_b.to_raw());
    }

    #[test]
    fn sig_hash_covers_sender_frame_data() {
        let base = FrameTx {
            chain_id: 1,
            nonce: 0,
            sender: sender_addr(),
            frames: vec![Frame {
                mode: EXEC_MODE_SENDER,
                flags: 0,
                target: sender_addr(),
                gas_limit: 100_000,
                data: Bytes::from(vec![0x11; 4]),
            }],
            max_priority_fee_per_gas: U256::from(1u64),
            max_fee_per_gas: U256::from(2u64),
            max_fee_per_blob_gas: U256::zero(),
            blob_versioned_hashes: Vec::new(),
        };
        let mut other = base.clone();
        other.frames[0].data = Bytes::from(vec![0x22; 4]);
        assert_ne!(base.sig_hash(), other.sig_hash());
    }

    #[test]
    fn default_eoa_verify_data_layout() {
        let sig_hash = H256::from_low_u64_be(42);
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let out = default_eoa_verify_data(sig_hash, &sk);
        assert_eq!(out.len(), 66);
        assert_eq!(out[0], 0x00);
        assert!(out[1] == 27 || out[1] == 28);
    }

    #[test]
    fn paymaster_owner_verify_data_layout() {
        // CanonicalPaymaster expects exactly r(32) || s(32) || v(1) = 65 bytes.
        let sig_hash = H256::from_low_u64_be(42);
        let sk = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let out = paymaster_owner_verify_data(sig_hash, &sk);
        assert_eq!(out.len(), 65);
        // v sits at the tail, already +27.
        assert!(out[64] == 27 || out[64] == 28);
        // Two different hashes should produce different signatures.
        let other = paymaster_owner_verify_data(H256::from_low_u64_be(43), &sk);
        assert_ne!(out, other);
    }

    #[test]
    fn envelope_starts_with_0x06() {
        let tx = FrameTx {
            chain_id: 1,
            nonce: 0,
            sender: sender_addr(),
            frames: vec![],
            max_priority_fee_per_gas: U256::zero(),
            max_fee_per_gas: U256::zero(),
            max_fee_per_blob_gas: U256::zero(),
            blob_versioned_hashes: Vec::new(),
        };
        assert_eq!(tx.to_raw()[0], 0x06);
    }
}
