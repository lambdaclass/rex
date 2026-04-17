use std::path::PathBuf;

use crate::utils::{parse_hex, parse_private_key, parse_u256};
use clap::Parser;
use ethrex_common::{Address, Bytes, Secret, U256};
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
    #[clap(required = false)]
    pub _args: Vec<String>,
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
