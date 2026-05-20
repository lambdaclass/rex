use std::path::PathBuf;
use std::str::FromStr;

use crate::utils::{parse_hex, parse_private_key, parse_u256};
use clap::Parser;
use ethrex_common::{Address, Bytes, H256, Secret, U256};
use rex_sdk::client::eth::StateOverrideSet;
use secp256k1::SecretKey;

#[derive(Parser)]
pub struct BalanceArgs {
    pub account: Address,
    #[clap(
        long = "token",
        help = "ERC20 token address",
        long_help = "Specify the token address, the base token is used as default."
    )]
    pub token_address: Option<Address>,
    #[arg(
        long = "eth",
        required = false,
        default_value_t = false,
        help = "Display the balance in ETH."
    )]
    pub eth: bool,
}

#[derive(Parser)]
pub struct TransferArgs {
    #[clap(value_parser = parse_u256)]
    pub amount: U256,
    pub to: Address,
    #[clap(long = "token", required = false)]
    pub token_address: Option<Address>,
    #[clap(long = "nonce")]
    pub nonce: Option<u64>,
    #[clap(
        long,
        short = 'c',
        required = false,
        help = "Send the request asynchronously."
    )]
    pub cast: bool,
    #[clap(
        long,
        short = 's',
        required = false,
        help = "Display only the tx hash."
    )]
    pub silent: bool,
    #[clap(
        long,
        required = false,
        help = "Display transaction URL in the explorer."
    )]
    pub explorer_url: bool,
    #[clap(long, value_parser = parse_private_key, env = "PRIVATE_KEY", required = false)]
    pub private_key: SecretKey,
}

#[derive(Parser)]
pub struct SendArgs {
    pub to: Address,
    #[clap(
        long,
        value_parser = parse_u256,
        default_value = "0",
        required = false,
        help = "Value to send in wei"
    )]
    pub value: U256,
    #[clap(long = "calldata", value_parser = parse_hex, required = false, default_value = "")]
    pub calldata: Bytes,
    #[clap(long = "chain-id", required = false)]
    pub chain_id: Option<u64>,
    #[clap(long = "nonce", required = false)]
    pub nonce: Option<u64>,
    #[clap(long = "gas-limit", required = false)]
    pub gas_limit: Option<u64>,
    #[clap(long = "gas-price", required = false)]
    pub max_fee_per_gas: Option<u64>,
    #[clap(long = "priority-gas-price", required = false)]
    pub max_priority_fee_per_gas: Option<u64>,
    #[clap(
        long,
        short = 'c',
        required = false,
        help = "Send the request asynchronously."
    )]
    pub cast: bool,
    #[clap(
        long,
        short = 's',
        required = false,
        help = "Display only the tx hash."
    )]
    pub silent: bool,
    #[clap(
        long,
        required = false,
        help = "Display transaction URL in the explorer."
    )]
    pub explorer_url: bool,
    #[clap(
        long,
        required = false,
        help = "Hex encoded authorization tuple for EIP 7702 transactions"
    )]
    pub auth_tuple: Vec<String>,
    #[clap(
        long = "private-key",
        short = 'k',
        value_parser = parse_private_key,
        env = "PRIVATE_KEY",
        required = false
    )]
    pub private_key: SecretKey,
    #[clap(required = false)]
    pub _args: Vec<String>,
}

#[derive(Parser)]
pub struct CallArgs {
    pub to: Address,
    #[clap(long, value_parser = parse_hex, required = false, default_value = "")]
    pub calldata: Bytes,
    #[clap(
        long,
        value_parser = parse_u256,
        default_value = "0",
        required = false,
        help = "Value to send in wei"
    )]
    pub value: U256,
    #[clap(long, required = false)]
    pub from: Option<Address>,
    #[clap(long, required = false)]
    pub gas_limit: Option<u64>,
    #[clap(long, required = false)]
    pub max_fee_per_gas: Option<u64>,
    #[clap(
        long,
        required = false,
        help = "Display transaction URL in the explorer."
    )]
    pub explorer_url: bool,
    #[clap(flatten)]
    pub state_overrides: StateOverrideArgs,
    #[clap(required = false)]
    pub _args: Vec<String>,
}

/// State Override Set (geth-style, ethrex PR #6660). Repeatable flags scoped per
/// address. Empty by default; when no flags are passed, `eth_call` falls back
/// to the standard 2-parameter form.
#[derive(Parser, Default, Clone, Debug)]
pub struct StateOverrideArgs {
    #[clap(
        long = "override-balance",
        value_name = "ADDR:VALUE",
        help = "Override an account's balance. Format: 0xaddr:0xhex_or_dec",
        long_help = "Set the balance of ADDR for the duration of this eth_call. \
                     Value may be hex (0x…) or decimal. Repeat for multiple addresses."
    )]
    pub balance: Vec<String>,
    #[clap(
        long = "override-nonce",
        value_name = "ADDR:VALUE",
        help = "Override an account's nonce. Format: 0xaddr:NONCE"
    )]
    pub nonce: Vec<String>,
    #[clap(
        long = "override-code",
        value_name = "ADDR:HEX",
        help = "Override an account's bytecode. Format: 0xaddr:0xbytecode"
    )]
    pub code: Vec<String>,
    #[clap(
        long = "override-state",
        value_name = "ADDR:SLOT:VALUE",
        help = "Replace an account's storage slot (mutually exclusive with --override-state-diff for the same address)."
    )]
    pub state: Vec<String>,
    #[clap(
        long = "override-state-diff",
        value_name = "ADDR:SLOT:VALUE",
        help = "Overlay a single storage slot for an account (mutually exclusive with --override-state for the same address)."
    )]
    pub state_diff: Vec<String>,
    #[clap(
        long = "override-move-precompile",
        value_name = "ADDR:TARGET",
        help = "Relocate the precompile at ADDR to TARGET."
    )]
    pub move_precompile: Vec<String>,
}

impl StateOverrideArgs {
    pub fn is_empty(&self) -> bool {
        self.balance.is_empty()
            && self.nonce.is_empty()
            && self.code.is_empty()
            && self.state.is_empty()
            && self.state_diff.is_empty()
            && self.move_precompile.is_empty()
    }

    pub fn build(&self) -> eyre::Result<StateOverrideSet> {
        let mut set = StateOverrideSet::new();

        for raw in &self.balance {
            let (addr, value) = split_two(raw, "override-balance", "ADDR:VALUE")?;
            set.entry(addr).balance = Some(parse_u256(value)?);
        }
        for raw in &self.nonce {
            let (addr, value) = split_two(raw, "override-nonce", "ADDR:VALUE")?;
            set.entry(addr).nonce = Some(parse_u64_flex(value)?);
        }
        for raw in &self.code {
            let (addr, value) = split_two(raw, "override-code", "ADDR:HEX")?;
            let bytes = parse_hex(value).map_err(|e| eyre::eyre!("invalid code hex: {e}"))?;
            set.entry(addr).code = Some(bytes);
        }
        for raw in &self.state {
            let (addr, slot, value) = split_three(raw, "override-state", "ADDR:SLOT:VALUE")?;
            set.entry(addr).state.insert(slot, value);
        }
        for raw in &self.state_diff {
            let (addr, slot, value) =
                split_three(raw, "override-state-diff", "ADDR:SLOT:VALUE")?;
            set.entry(addr).state_diff.insert(slot, value);
        }
        for raw in &self.move_precompile {
            let (addr, target) = split_two(raw, "override-move-precompile", "ADDR:TARGET")?;
            set.entry(addr).move_precompile_to = Some(Address::from_str(target)?);
        }

        Ok(set)
    }
}

fn split_two<'a>(
    raw: &'a str,
    flag: &str,
    shape: &str,
) -> eyre::Result<(Address, &'a str)> {
    let (addr, rest) = raw
        .split_once(':')
        .ok_or_else(|| eyre::eyre!("--{flag} expects '{shape}', got '{raw}'"))?;
    Ok((Address::from_str(addr.trim())?, rest.trim()))
}

fn split_three(
    raw: &str,
    flag: &str,
    shape: &str,
) -> eyre::Result<(Address, H256, U256)> {
    let mut parts = raw.splitn(3, ':');
    let addr = parts
        .next()
        .ok_or_else(|| eyre::eyre!("--{flag} expects '{shape}', got '{raw}'"))?;
    let slot = parts
        .next()
        .ok_or_else(|| eyre::eyre!("--{flag} expects '{shape}', got '{raw}'"))?;
    let value = parts
        .next()
        .ok_or_else(|| eyre::eyre!("--{flag} expects '{shape}', got '{raw}'"))?;
    Ok((
        Address::from_str(addr.trim())?,
        parse_h256(slot.trim())?,
        parse_u256(value.trim())?,
    ))
}

fn parse_u64_flex(s: &str) -> eyre::Result<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x") {
        Ok(u64::from_str_radix(rest, 16)?)
    } else {
        Ok(s.parse::<u64>()?)
    }
}

fn parse_h256(s: &str) -> eyre::Result<H256> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() > 64 {
        return Err(eyre::eyre!("slot '{s}' is more than 32 bytes"));
    }
    let padded = format!("{:0>64}", stripped);
    let bytes = hex::decode(&padded)?;
    Ok(H256::from_slice(&bytes))
}

#[derive(Parser, Clone)]
#[clap(group = clap::ArgGroup::new("source").required(true))]
pub struct DeployArgs {
    #[clap(long, group = "source", value_parser = parse_hex, required = false)]
    pub bytecode: Option<Bytes>,
    #[clap(
        long,
        value_parser = parse_u256,
        default_value = "0",
        required = false,
        help = "Value to send in wei"
    )]
    pub value: U256,
    #[clap(long = "chain-id", required = false)]
    pub chain_id: Option<u64>,
    #[clap(long = "nonce", required = false)]
    pub nonce: Option<u64>,
    #[clap(long = "gas-limit", required = false)]
    pub gas_limit: Option<u64>,
    #[clap(long = "gas-price", required = false)]
    pub max_fee_per_gas: Option<u64>,
    #[clap(long = "priority-gas-price", required = false)]
    pub max_priority_fee_per_gas: Option<u64>,
    #[clap(long, required = false)]
    pub print_address: bool,
    #[clap(
        long,
        short = 'c',
        required = false,
        help = "Send the request asynchronously."
    )]
    pub cast: bool,
    #[clap(
        long,
        short = 's',
        required = false,
        help = "Display only the tx hash."
    )]
    pub silent: bool,
    #[clap(
        long,
        required = false,
        help = "Display transaction URL in the explorer."
    )]
    pub explorer_url: bool,
    #[arg(long, value_parser = parse_private_key, env = "PRIVATE_KEY", required = false)]
    pub private_key: SecretKey,
    #[arg(
        long,
        help = "Path to the Solidity file to compile and deploy",
        group = "source"
    )]
    pub contract_path: Option<PathBuf>,
    #[arg(
        long,
        required_unless_present = "bytecode",
        help = "Comma-separated remappings (e.g. '@openzeppelin/contracts=https://github.com/OpenZeppelin/openzeppelin-contracts.git,@custom=path/to/custom')"
    )]
    pub remappings: Option<String>,
    #[arg(
        long,
        help = "Remove downloaded dependencies after compilation",
        default_value_t = false,
        required = false
    )]
    pub keep_deps: bool,
    #[arg(
        long,
        help = "Salt for deploying CREATE2 contracts. If it is provided, the contract will be deployed using CREATE2.",
        required = false
    )]
    pub salt: Option<Secret>,
    #[arg(last = true, hide = true)]
    pub _args: Vec<String>,
    #[arg(
        long = "constructor-args",
        value_delimiter = ',',
        help = "Constructor arguments as typed values, comma-separated. Example: --constructor-args 'address:0xabc...,uint256:100,string:hello,bool:true'. Supported types: address, uint/uint{N}, int/int{N}, bool, string, bytes, bytes{N}, and array forms like 'uint256[]:[1,2,3]'."
    )]
    pub constructor_args: Vec<String>,
}

#[derive(Parser)]
pub struct AuthorizeArgs {
    #[arg(help = "Delegated address")]
    pub delegated_address: Address,
    #[arg(long, value_parser = parse_private_key, help = "Private key to sign the auth")]
    pub private_key: SecretKey,
    #[arg(long, required = false, help = "Nonce of the signer")]
    pub nonce: Option<u64>,
    #[arg(long, required = false, help = "Chain id of the network")]
    pub chain_id: Option<u64>,
}
