use crate::{
    cli::Command as EthCommand,
    common::{BalanceArgs, CallArgs, DeployArgs, SendArgs, TransferArgs},
    utils::{parse_private_key, parse_u256},
};
use clap::Subcommand;
use ethrex_common::{Address, H256, U256};
use ethrex_rpc::EthClient;
use ethrex_sdk::get_address_from_secret_key;
use rex_sdk::{
    deposit_through_contract_call,
    l2::{
        deposit::deposit_erc20,
        withdraw::{claim_erc20withdraw, claim_withdraw, withdraw, withdraw_erc20},
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
        #[clap(value_parser = parse_u256)]
        claimed_amount: U256,
        l2_withdrawal_tx_hash: H256,
        #[clap(
            long = "token-l1",
            help = "ERC20 token address on L1",
            long_help = "Specify the token address, the base token is used as default."
        )]
        token_l1: Option<Address>,
        #[clap(
            long = "token-l2",
            help = "ERC20 token address on L2",
            long_help = "Specify the token address, it is required if you specify a token on L1.",
            requires("token-l1")
        )]
        token_l2: Option<Address>,
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
            long = "token-l1",
            help = "ERC20 token address on L1",
            long_help = "Specify the token address, the base token is used as default."
        )]
        token_l1: Option<Address>,
        #[clap(
            long = "token-l2",
            help = "ERC20 token address on L2",
            long_help = "Specify the token address, it is required if you specify a token on L1.",
            requires("token-l1")
        )]
        token_l2: Option<Address>,
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
        #[arg(
            env = "BRIDGE_ADDRESS",
            help = "Make sure you are using the correct bridge address before submitting your deposit."
        )]
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
            long = "token-l1",
            help = "ERC20 token address on L1",
            long_help = "Specify the token address, the base token is used as default."
        )]
        token_l1: Option<Address>,
        #[clap(
            long = "token-l2",
            help = "ERC20 token address on L2",
            long_help = "Specify the token address, it is required if you specify a token on L1.",
            requires("token-l1")
        )]
        token_l2: Option<Address>,
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
    #[clap(about = "Get the merkle proof of a L1MessageProof.")]
    MessageProof {
        message_tx_hash: H256,
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
                token_l1,
                token_l2,
                to,
                cast,
                silent,
                explorer_url,
                private_key,
                l1_rpc_url,
                bridge_address,
            } => {
                let eth_client = EthClient::new(&l1_rpc_url)?;
                let to = to.unwrap_or(get_address_from_secret_key(&private_key)?);
                if explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                // Deposit through ERC20 token transfer
                let tx_hash = if let Some(token_l1) = token_l1 {
                    let token_l2 = token_l2.expect(
                        "Token address on L2 is required if token address on L1 is specified",
                    );
                    let from = get_address_from_secret_key(&private_key)?;
                    println!(
                        "Depositing {amount} from {from:#x} to L2 token {token_l2:#x} using L1 token {token_l1:#x}"
                    );
                    deposit_erc20(
                        token_l1,
                        token_l2,
                        amount,
                        from,
                        private_key,
                        &eth_client,
                        bridge_address,
                    )
                    .await?
                } else {
                    println!("Depositing {amount} from {to:#x} to bridge");
                    deposit_through_contract_call(
                        amount,
                        to,
                        &private_key,
                        bridge_address,
                        &eth_client,
                    )
                    .await?
                };

                println!("Deposit sent: {tx_hash:#x}");

                if !cast {
                    wait_for_transaction_receipt(tx_hash, &eth_client, 100, silent).await?;
                }
            }
            Command::ClaimWithdraw {
                claimed_amount,
                l2_withdrawal_tx_hash,
                token_l1,
                token_l2,
                cast,
                silent,
                private_key,
                l1_rpc_url,
                rpc_url,
                bridge_address,
            } => {
                let from = get_address_from_secret_key(&private_key)?;

                let eth_client = EthClient::new(&l1_rpc_url)?;

                let rollup_client = EthClient::new(&rpc_url)?;

                let message_proof = rollup_client
                    .wait_for_message_proof(l2_withdrawal_tx_hash, 100)
                    .await?;

                let withdrawal_proof = message_proof.into_iter().next().ok_or(eyre::eyre!(
                    "No withdrawal proof found for transaction {l2_withdrawal_tx_hash:#x}"
                ))?;

                let tx_hash = if let Some(token_l1) = token_l1 {
                    let token_l2 = token_l2.expect(
                        "Token address on L2 is required if token address on L1 is specified",
                    );
                    claim_erc20withdraw(
                        token_l1,
                        token_l2,
                        claimed_amount,
                        private_key,
                        &eth_client,
                        &withdrawal_proof,
                        bridge_address,
                    )
                    .await?
                } else {
                    claim_withdraw(
                        claimed_amount,
                        from,
                        private_key,
                        &eth_client,
                        &withdrawal_proof,
                        bridge_address,
                    )
                    .await?
                };

                println!("Withdrawal claim sent: {tx_hash:#x}");

                if !cast {
                    wait_for_transaction_receipt(tx_hash, &eth_client, 100, silent).await?;
                }
            }
            Command::Withdraw {
                amount,
                nonce,
                token_l1,
                token_l2,
                cast,
                silent,
                explorer_url,
                private_key,
                rpc_url,
            } => {
                let from = get_address_from_secret_key(&private_key)?;

                let client = EthClient::new(&rpc_url)?;

                if explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                let tx_hash = if let Some(token_l1) = token_l1 {
                    let token_l2 = token_l2.expect(
                        "Token address on L2 is required if token address on L1 is specified",
                    );
                    withdraw_erc20(amount, from, private_key, token_l1, token_l2, &client).await?
                } else {
                    withdraw(amount, from, private_key, &client, nonce).await?
                };

                println!("Withdrawal sent: {tx_hash:#x}");

                if !cast {
                    wait_for_transaction_receipt(tx_hash, &client, 100, silent).await?;
                }
            }
            Command::MessageProof {
                message_tx_hash,
                rpc_url,
            } => {
                let client = EthClient::new(&rpc_url)?;

                let message_proof = client.get_message_proof(message_tx_hash).await?;
                let Some(proof) = message_proof else {
                    println!("No message proof found for transaction {message_tx_hash:#x}");
                    return Ok(());
                };

                let proof = proof.into_iter().next().expect("proof not found");

                println!("{:?}", proof.merkle_proof);
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
