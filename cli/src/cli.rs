use crate::commands::l2;
use crate::utils::parse_hex;
use crate::{
    commands::autocomplete,
    common::{CallArgs, DeployArgs, SendArgs, TransferArgs},
    utils::parse_private_key,
};
use clap::{ArgAction, Parser, Subcommand};
use ethertools_sdk::{
    balance_in_eth,
    client::{EthClient, Overrides, eth::get_address_from_secret_key},
    transfer, wait_for_transaction_receipt,
};
use ethrex_common::{Address, Bytes, H256};
use keccak_hash::keccak;
use secp256k1::SecretKey;

pub const VERSION_STRING: &str = env!("CARGO_PKG_VERSION");

pub async fn start() -> eyre::Result<()> {
    let CLI { command } = CLI::parse();
    command.run().await
}

#[allow(clippy::upper_case_acronyms)] // TODO: Find a cool name
#[derive(Parser)]
#[command(name="cli", author, version=VERSION_STRING, about, long_about = None)]
pub(crate) struct CLI {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    #[clap(subcommand, about = "Generate shell completion scripts.")]
    Autocomplete(autocomplete::Command),
    #[clap(about = "Get the current block_number.", visible_alias = "bl")]
    BlockNumber {
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Get the transaction's info.", visible_aliases = ["tx", "t"])]
    Transaction {
        tx_hash: H256,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Get the transaction's receipt.", visible_alias = "r")]
    Receipt {
        tx_hash: H256,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Get the account's balance info.", visible_aliases = ["bal", "b"])]
    Balance {
        account: Address,
        #[clap(
            long = "token",
            help = "Specify the token address, the ETH is used as default."
        )]
        token_address: Option<Address>,
        #[arg(
            long = "eth",
            required = false,
            default_value_t = false,
            help = "Display the balance in ETH."
        )]
        eth: bool,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Get the account's nonce.", visible_aliases = ["n"])]
    Nonce {
        account: Address,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(
        about = "Get the account's address from private key.",
        visible_aliases = ["addr", "a"]
    )]
    Address {
        #[arg(value_parser = parse_private_key, env = "PRIVATE_KEY")]
        private_key: SecretKey,
    },
    #[clap(
        about = "Get either the keccak for a given input, the zero hash, or a random hash",
        visible_alias = "h"
    )]
    Hash {
        #[arg(long, value_parser = parse_hex, conflicts_with_all = ["zero", "random", "string"], required_unless_present_any = ["zero", "random", "string"], env = "INPUT", help = "The input to hash.")]
        input: Option<Bytes>,
        #[arg(short, long, action = ArgAction::SetTrue, conflicts_with_all = ["input", "random", "string"], required_unless_present_any = ["input", "random", "string"], help = "The zero hash.")]
        zero: bool,
        #[arg(short, long, action = ArgAction::SetTrue, conflicts_with_all = ["input", "zero", "string"], required_unless_present_any = ["input", "zero", "string"], help = "A random hash.")]
        random: bool,
        #[arg(short, long, action = ArgAction::SetTrue, conflicts_with_all = ["input", "zero", "random"], required_unless_present_any = ["input", "zero", "random"], help = "Hash of empty string")]
        string: bool,
    },
    #[clap(about = "Transfer funds to another wallet.")]
    Transfer {
        #[clap(flatten)]
        args: TransferArgs,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Send a transaction")]
    Send {
        #[clap(flatten)]
        args: SendArgs,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Make a call to a contract")]
    Call {
        #[clap(flatten)]
        args: CallArgs,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Deploy a contract")]
    Deploy {
        #[clap(flatten)]
        args: DeployArgs,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(subcommand, about = "L2 specific commands.")]
    L2(l2::Command),
}

impl Command {
    pub async fn run(self) -> eyre::Result<()> {
        match self {
            Command::L2(cmd) => cmd.run().await?,
            Command::Autocomplete(cmd) => cmd.run()?,
            Command::Balance {
                account,
                token_address,
                eth,
                rpc_url,
            } => {
                if token_address.is_some() {
                    todo!("Handle ERC20 balances")
                }

                let eth_client = EthClient::new(&rpc_url);

                let account_balance = eth_client.get_balance(account).await?;

                println!("{}", balance_in_eth(eth, account_balance));
            }
            Command::BlockNumber { rpc_url } => {
                let eth_client = EthClient::new(&rpc_url);

                let block_number = eth_client.get_block_number().await?;

                println!("{block_number}");
            }
            Command::Transaction { tx_hash, rpc_url } => {
                let eth_client = EthClient::new(&rpc_url);

                let tx = eth_client
                    .get_transaction_by_hash(tx_hash)
                    .await?
                    .ok_or(eyre::Error::msg("Not found"))?;

                println!("{tx}");
            }
            Command::Receipt { tx_hash, rpc_url } => {
                let eth_client = EthClient::new(&rpc_url);

                let receipt = eth_client
                    .get_transaction_receipt(tx_hash)
                    .await?
                    .ok_or(eyre::Error::msg("Not found"))?;

                println!("{:x?}", receipt.tx_info);
            }
            Command::Nonce { account, rpc_url } => {
                let eth_client = EthClient::new(&rpc_url);

                let nonce = eth_client.get_nonce(account).await?;

                println!("{nonce}");
            }
            Command::Address { private_key } => {
                let address = get_address_from_secret_key(&private_key)?;

                println!("{address:#x}");
            }
            Command::Hash {
                input,
                zero,
                random,
                string,
            } => {
                let hash = if let Some(input) = input {
                    keccak(&input)
                } else if zero {
                    H256::zero()
                } else if random {
                    H256::random()
                } else if string {
                    keccak(b"")
                } else {
                    return Err(eyre::Error::msg("No option provided"));
                };

                println!("{hash:#x}");
            }
            Command::Transfer { args, rpc_url } => {
                if args.token_address.is_some() {
                    todo!("Handle ERC20 transfers")
                }

                if args.explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                let from = get_address_from_secret_key(&args.private_key)?;

                let client = EthClient::new(&rpc_url);

                let tx_hash = transfer(
                    args.amount,
                    from,
                    args.to,
                    args.private_key,
                    &client,
                    Overrides {
                        value: Some(args.amount),
                        nonce: args.nonce,
                        ..Default::default()
                    },
                )
                .await?;

                println!("{tx_hash:#x}");

                if !args.background {
                    wait_for_transaction_receipt(tx_hash, &client, 100).await?;
                }
            }
            Command::Send { args, rpc_url } => {
                if args.explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                let from = get_address_from_secret_key(&args.private_key)?;

                let client = EthClient::new(&rpc_url);

                let tx = client
                    .build_eip1559_transaction(
                        args.to,
                        from,
                        args.calldata,
                        Overrides {
                            value: Some(args.value),
                            chain_id: args.chain_id,
                            nonce: args.nonce,
                            gas_limit: args.gas_limit,
                            max_fee_per_gas: args.max_fee_per_gas,
                            max_priority_fee_per_gas: args.max_priority_fee_per_gas,
                            from: Some(from),
                            ..Default::default()
                        },
                        10,
                    )
                    .await?;

                let tx_hash = client
                    .send_eip1559_transaction(&tx, &args.private_key)
                    .await?;

                println!("{tx_hash:#x}",);

                if !args.background {
                    wait_for_transaction_receipt(tx_hash, &client, 100).await?;
                }
            }
            Command::Call { args, rpc_url } => {
                if args.explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                let client = EthClient::new(&rpc_url);

                let result = client
                    .call(
                        args.to,
                        args.calldata,
                        Overrides {
                            from: args.from,
                            value: args.value.into(),
                            gas_limit: args.gas_limit,
                            max_fee_per_gas: args.max_fee_per_gas,
                            ..Default::default()
                        },
                    )
                    .await?;

                println!("{result}");
            }
            Command::Deploy { args, rpc_url } => {
                if args.explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                let from = get_address_from_secret_key(&args.private_key)?;

                let client = EthClient::new(&rpc_url);

                let (tx_hash, deployed_contract_address) = client
                    .deploy(
                        from,
                        args.private_key,
                        args.bytecode,
                        Overrides {
                            value: args.value.into(),
                            nonce: args.nonce,
                            chain_id: args.chain_id,
                            gas_limit: args.gas_limit,
                            max_fee_per_gas: args.max_fee_per_gas,
                            max_priority_fee_per_gas: args.max_priority_fee_per_gas,
                            ..Default::default()
                        },
                    )
                    .await?;

                println!("Contract deployed in tx: {tx_hash:#x}");
                println!("Contract address: {deployed_contract_address:#x}");

                if !args.background {
                    wait_for_transaction_receipt(tx_hash, &client, 100).await?;
                }
            }
        };
        Ok(())
    }
}
