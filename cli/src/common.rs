use crate::utils::{parse_hex, parse_private_key, parse_u256};
use clap::Parser;
use ethrex_common::{Address, Bytes, U256};
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
        short = 'b',
        required = false,
        help = "Send the request asynchronously."
    )]
    pub cast: bool,
    #[clap(
        long,
        required = false,
        help = "Display transaction URL in the explorer."
    )]
    pub explorer_url: bool,
    #[clap(value_parser = parse_private_key, env = "PRIVATE_KEY", required = false)]
    pub private_key: SecretKey,
}

#[derive(Parser)]
pub struct SendArgs {
    pub to: Address,
    #[clap(
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
        short = 'b',
        required = false,
        help = "Send the request asynchronously."
    )]
    pub cast: bool,
    #[clap(
        long,
        required = false,
        help = "Display transaction URL in the explorer."
    )]
    pub explorer_url: bool,
    #[clap(value_parser = parse_private_key, env = "PRIVATE_KEY", required = false)]
    pub private_key: SecretKey,
    #[arg(last = true, hide = true)]
    pub _args: Vec<String>,
}

#[derive(Parser)]
pub struct CallArgs {
    pub to: Address,
    #[clap(long, value_parser = parse_hex, required = false, default_value = "")]
    pub calldata: Bytes,
    #[clap(
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
    #[arg(last = true, hide = true)]
    pub _args: Vec<String>,
}

#[derive(Parser)]
pub struct DeployArgs {
    #[clap(value_parser = parse_hex)]
    pub bytecode: Bytes,
    #[clap(
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
    #[clap(
        short = 'b',
        required = false,
        help = "Send the request asynchronously."
    )]
    pub cast: bool,
    #[clap(
        long,
        required = false,
        help = "Display transaction URL in the explorer."
    )]
    pub explorer_url: bool,
    #[arg(value_parser = parse_private_key, env = "PRIVATE_KEY", required = false)]
    pub private_key: SecretKey,
    #[arg(last=true, hide=true)]
    pub _args: Vec<String>,
}
