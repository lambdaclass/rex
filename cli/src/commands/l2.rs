use crate::{
    cli::Command as EthCommand,
    common::{BalanceArgs, CallArgs, DeployArgs, SendArgs, TransferArgs},
    utils::{parse_private_key, parse_u256},
};
use clap::Subcommand;
use ethrex_common::{Address, H256, U256};
use rex_sdk::{
    client::{EthClient, Overrides, eth::get_address_from_secret_key},
    l2::{
        deposit::deposit,
        withdraw::{claim_withdraw, get_withdraw_merkle_proof, withdraw},
    },
    wait_for_transaction_receipt,
};
use secp256k1::SecretKey;

#[derive(Subcommand)]
pub(crate) enum Command {
    #[clap(about = "Get the account's balance on L2.", visible_aliases = ["bal", "b"])]
    Balance {
        #[clap(flatten)]
        args: BalanceArgs,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: String,
    },
    #[clap(about = "Get the current block_number.", visible_alias = "bl")]
    BlockNumber {
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: String,
    },
    #[clap(about = "Make a call to a contract")]
    Call {
        #[clap(flatten)]
        args: CallArgs,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: String,
    },
    #[clap(about = "Get the network's chain id.")]
    ChainId {
        #[arg(
            short,
            long,
            default_value_t = false,
            help = "Display the chain id as a hex-string."
        )]
        hex: bool,
        #[arg(default_value = "http://localhost:1729", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Finalize a pending withdrawal.")]
    ClaimWithdraw {
        l2_withdrawal_tx_hash: H256,
        #[clap(
            long,
            short = 'c',
            required = false,
            help = "Send the request asynchronously."
        )]
        cast: bool,
        #[clap(
            long,
            short = 's',
            required = false,
            help = "Display only the tx hash."
        )]
        silent: bool,
        #[arg(value_parser = parse_private_key, env = "PRIVATE_KEY")]
        private_key: SecretKey,
        #[arg(env = "BRIDGE_ADDRESS")]
        bridge_address: Address,
        #[arg(env = "L1_RPC_URL", default_value = "http://localhost:8545")]
        l1_rpc_url: String,
        #[arg(env = "RPC_URL", default_value = "http://localhost:1729")]
        rpc_url: String,
    },
    #[clap(about = "Deploy a contract")]
    Deploy {
        #[clap(flatten)]
        args: DeployArgs,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: String,
    },
    #[clap(about = "Deposit funds into some wallet.")]
    Deposit {
        // TODO: Parse ether instead.
        #[clap(value_parser = parse_u256)]
        amount: U256,
        #[clap(
            long = "token",
            help = "ERC20 token address",
            long_help = "Specify the token address, the base token is used as default."
        )]
        token_address: Option<Address>,
        #[clap(
            long = "to",
            help = "Specify the wallet in which you want to deposit your funds."
        )]
        to: Option<Address>,
        #[clap(
            long,
            short = 'c',
            required = false,
            help = "Send the request asynchronously."
        )]
        cast: bool,
        #[clap(
            long,
            short = 's',
            required = false,
            help = "Display only the tx hash."
        )]
        silent: bool,
        #[clap(
            long,
            short = 'e',
            required = false,
            help = "Display transaction URL in the explorer."
        )]
        explorer_url: bool,
        #[clap(value_parser = parse_private_key, env = "PRIVATE_KEY")]
        private_key: SecretKey,
        #[arg(env = "BRIDGE_ADDRESS")]
        bridge_address: Address,
        #[arg(default_value = "http://localhost:8545", env = "L1_RPC_URL")]
        l1_rpc_url: String,
    },
    #[clap(about = "Get the account's nonce.", visible_aliases = ["n"])]
    Nonce {
        account: Address,
        #[arg(default_value = "http://localhost:1729", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Get the transaction's receipt.", visible_alias = "r")]
    Receipt {
        tx_hash: H256,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: String,
    },
    #[clap(about = "Send a transaction")]
    Send {
        #[clap(flatten)]
        args: SendArgs,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: String,
    },
    #[clap(about = "Get the transaction's info.", visible_aliases = ["tx", "t"])]
    Transaction {
        tx_hash: H256,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: String,
    },
    #[clap(about = "Transfer funds to another wallet.")]
    Transfer {
        #[clap(flatten)]
        args: TransferArgs,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: String,
    },
    #[clap(about = "Withdraw funds from the wallet.")]
    Withdraw {
        // TODO: Parse ether instead.
        #[clap(value_parser = parse_u256)]
        amount: U256,
        #[clap(long = "nonce")]
        nonce: Option<u64>,
        #[clap(
            long = "token",
            help = "ERC20 token address",
            long_help = "Specify the token address, the base token is used as default."
        )]
        token_address: Option<Address>,
        #[clap(
            long,
            short = 'c',
            required = false,
            help = "Send the request asynchronously."
        )]
        cast: bool,
        #[clap(
            long,
            short = 's',
            required = false,
            help = "Display only the tx hash."
        )]
        silent: bool,
        #[clap(
            long,
            required = false,
            help = "Display transaction URL in the explorer."
        )]
        explorer_url: bool,
        #[arg(value_parser = parse_private_key, env = "PRIVATE_KEY")]
        private_key: SecretKey,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: String,
    },
    #[clap(about = "Get the withdrawal merkle proof of a transaction.")]
    WithdrawalProof {
        l2_withdrawal_tx_hash: H256,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: String,
    },
}

impl Command {
    pub async fn run(self) -> eyre::Result<()> {
        match self {
            Command::Deposit {
                amount,
                token_address,
                to,
                cast,
                silent,
                explorer_url,
                private_key,
                l1_rpc_url,
                bridge_address,
            } => {
                if explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                if to.is_some() {
                    // There are two ways of depositing funds into the L2:
                    // 1. Directly transferring funds to the bridge.
                    // 2. Depositing through a contract call to the deposit method of the bridge.
                    // The second method is not handled in the CLI yet.
                    todo!("Handle deposits through contract")
                }

                if token_address.is_some() {
                    todo!("Handle ERC20 deposits")
                }

                let from = get_address_from_secret_key(&private_key)?;

                let eth_client = EthClient::new(&l1_rpc_url);

                let tx_hash = deposit(
                    amount,
                    from,
                    private_key,
                    &eth_client,
                    bridge_address,
                    Overrides::default(),
                )
                .await?;

                println!("Deposit sent: {tx_hash:#x}");

                if !cast {
                    wait_for_transaction_receipt(tx_hash, &eth_client, 100, silent).await?;
                }
            }
            Command::ClaimWithdraw {
                l2_withdrawal_tx_hash,
                cast,
                silent,
                private_key,
                l1_rpc_url,
                rpc_url,
                bridge_address,
            } => {
                let from = get_address_from_secret_key(&private_key)?;

                let eth_client = EthClient::new(&l1_rpc_url);

                let client = EthClient::new(&rpc_url);

                let tx_hash = claim_withdraw(
                    l2_withdrawal_tx_hash,
                    U256::default(), // TODO: Fix this
                    from,
                    private_key,
                    &client,
                    &eth_client,
                    bridge_address,
                )
                .await?;

                println!("Withdrawal claim sent: {tx_hash:#x}");

                if !cast {
                    wait_for_transaction_receipt(tx_hash, &eth_client, 100, silent).await?;
                }
            }
            Command::Withdraw {
                amount,
                nonce,
                token_address,
                cast,
                silent,
                explorer_url,
                private_key,
                rpc_url,
            } => {
                if explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                if token_address.is_some() {
                    todo!("Handle ERC20 withdrawals")
                }

                let from = get_address_from_secret_key(&private_key)?;

                let client = EthClient::new(&rpc_url)?;

                let tx_hash = withdraw(amount, from, private_key, &client, nonce).await?;

                println!("Withdrawal sent: {tx_hash:#x}");

                if !cast {
                    wait_for_transaction_receipt(tx_hash, &client, 100, silent).await?;
                }
            }
            Command::WithdrawalProof {
                l2_withdrawal_tx_hash,
                rpc_url,
            } => {
                let client = EthClient::new(&rpc_url)?;

                let (_index, path) =
                    get_withdraw_merkle_proof(&client, l2_withdrawal_tx_hash).await?;

                println!("{path:?}");
            }
            Command::BlockNumber { rpc_url } => {
                Box::pin(async { EthCommand::BlockNumber { rpc_url }.run().await }).await?
            }
            Command::Transaction { tx_hash, rpc_url } => {
                Box::pin(async { EthCommand::Transaction { tx_hash, rpc_url }.run().await }).await?
            }
            Command::Receipt { tx_hash, rpc_url } => {
                Box::pin(async { EthCommand::Receipt { tx_hash, rpc_url }.run().await }).await?
            }
            Command::Balance { args, rpc_url } => {
                Box::pin(async {
                    EthCommand::Balance {
                        account: args.account,
                        token_address: args.token_address,
                        eth: args.eth,
                        rpc_url,
                    }
                    .run()
                    .await
                })
                .await?
            }
            Command::Nonce { account, rpc_url } => {
                Box::pin(async { EthCommand::Nonce { account, rpc_url }.run().await }).await?
            }
            Command::Transfer { args, rpc_url } => {
                Box::pin(async { EthCommand::Transfer { args, rpc_url }.run().await }).await?
            }
            Command::Send { args, rpc_url } => {
                Box::pin(async { EthCommand::Send { args, rpc_url }.run().await }).await?
            }
            Command::Call { args, rpc_url } => {
                Box::pin(async { EthCommand::Call { args, rpc_url }.run().await }).await?;
            }
            Command::Deploy { args, rpc_url } => {
                Box::pin(async { EthCommand::Deploy { args, rpc_url }.run().await }).await?
            }
            Command::ChainId { hex, rpc_url } => {
                Box::pin(async { EthCommand::ChainId { hex, rpc_url }.run().await }).await?
            }
        };
        Ok(())
    }
}
