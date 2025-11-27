use crate::{
    cli::Command as EthCommand,
    common::{AuthorizeArgs, BalanceArgs, CallArgs, DeployArgs, SendArgs, TransferArgs},
    utils::{parse_hex, parse_private_key, parse_u256},
};
use clap::Subcommand;
use ethrex_common::{Address, H256, U256, types::AuthorizationTuple};
use ethrex_common::{Bytes, types::TxType};
use ethrex_l2_common::utils::get_address_from_secret_key;
use ethrex_l2_rpc::clients::{
    get_base_fee_vault_address, get_l1_blob_base_fee_per_gas, get_l1_fee_vault_address,
    get_operator_fee, get_operator_fee_vault_address, send_ethrex_transaction,
};
use ethrex_l2_rpc::clients::{get_batch_by_number, get_batch_number};
use ethrex_rlp::decode::RLPDecode;
use ethrex_rpc::clients::Overrides;
use ethrex_rpc::{
    EthClient,
    types::block_identifier::{BlockIdentifier, BlockTag},
};
use ethrex_sdk::wait_for_message_proof;
use rex_sdk::transfer;
use rex_sdk::{
    l2::{
        deposit::{deposit_erc20, deposit_through_contract_call},
        withdraw::{claim_erc20withdraw, claim_withdraw, withdraw, withdraw_erc20},
    },
    wait_for_transaction_receipt,
};
use secp256k1::SecretKey;
use url::Url;

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
        rpc_url: Url,
    },
    #[clap(about = "Get the current block_number.", visible_alias = "bl")]
    BlockNumber {
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: Url,
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
        rpc_url: Url,
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
        rpc_url: Url,
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
        l1_rpc_url: Url,
        #[arg(env = "RPC_URL", default_value = "http://localhost:1729")]
        rpc_url: Url,
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
        rpc_url: Url,
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
        l1_rpc_url: Url,
    },
    #[clap(about = "Get the account's nonce.", visible_aliases = ["n"])]
    Nonce {
        account: Address,
        #[arg(default_value = "http://localhost:1729", env = "RPC_URL")]
        rpc_url: Url,
    },
    #[clap(about = "Get the transaction's receipt.", visible_alias = "r")]
    Receipt {
        tx_hash: H256,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: Url,
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
        rpc_url: Url,
    },
    #[clap(about = "Get the transaction's info.", visible_aliases = ["tx", "t"])]
    Transaction {
        tx_hash: H256,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: Url,
    },
    #[clap(about = "Transfer funds to another wallet.")]
    Transfer {
        #[clap(flatten)]
        args: TransferArgs,
        #[arg(
            long,
            required = false,
            help = "The L2 address of a Fee Token to pay the gas fees"
        )]
        fee_token: Option<Address>,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: Url,
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
        rpc_url: Url,
    },
    #[clap(about = "Get the merkle proof of a L1MessageProof.")]
    MessageProof {
        message_tx_hash: H256,
        #[arg(
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: Url,
    },
    #[clap(about = "Get L2 fees info for a block")]
    GetFeeInfo {
        #[arg(
            long,
            required = false,
            help = "Block number to query the fees info for"
        )]
        block: Option<u64>,
        #[arg(
            long,
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: Url,
    },
    #[clap(about = "Get the latest batch number")]
    BatchNumber {
        #[arg(
            long,
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: Url,
    },
    #[clap(about = "Get the latest batch or a batch by its number")]
    BatchByNumber {
        #[arg(
            long,
            short = 'b',
            required = false,
            help = "Batch number to retrieve information"
        )]
        batch_number: Option<u64>,
        #[arg(
            long,
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: Url,
    },
    #[clap(about = "Send an ethrex sponsored transaction")]
    SponsorTx {
        #[arg(help = "Destination address of the transaction")]
        to: Address,
        #[arg(long, value_parser = parse_hex, help = "Calldata of the transaction")]
        calldata: Option<Bytes>,
        #[arg(long, help = "Authorization list")]
        auth_list: Vec<String>,
        #[arg(
            long,
            default_value = "http://localhost:1729",
            env = "RPC_URL",
            help = "L2 RPC URL"
        )]
        rpc_url: Url,
    },
    #[clap(about = "Authorize a delegated account")]
    Authorize {
        #[clap(flatten)]
        args: AuthorizeArgs,
        #[arg(long, default_value = "http://localhost:1729", env = "RPC_URL")]
        rpc_url: Url,
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
                let eth_client = EthClient::new(l1_rpc_url)?;
                let to = to.unwrap_or(
                    get_address_from_secret_key(&private_key.secret_bytes())
                        .map_err(|e| eyre::eyre!(e))?,
                );
                if explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                // Deposit through ERC20 token transfer
                let tx_hash = if let Some(token_l1) = token_l1 {
                    let token_l2 = token_l2.expect(
                        "Token address on L2 is required if token address on L1 is specified",
                    );
                    let from = get_address_from_secret_key(&private_key.secret_bytes())
                        .map_err(|e| eyre::eyre!(e))?;
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
                let from = get_address_from_secret_key(&private_key.secret_bytes())
                    .map_err(|e| eyre::eyre!(e))?;

                let eth_client = EthClient::new(l1_rpc_url)?;

                let rollup_client = EthClient::new(rpc_url)?;

                let message_proof =
                    wait_for_message_proof(&rollup_client, l2_withdrawal_tx_hash, 100).await?;

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
                let from = get_address_from_secret_key(&private_key.secret_bytes())
                    .map_err(|e| eyre::eyre!(e))?;

                let client = EthClient::new(rpc_url)?;

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
                let client = EthClient::new(rpc_url)?;

                let message_proof = wait_for_message_proof(&client, message_tx_hash, 100).await?;
                if message_proof.is_empty() {
                    println!("No message proof found for transaction {message_tx_hash:#x}");
                    return Ok(());
                };

                let proof = message_proof.into_iter().next().expect("proof not found");

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
            Command::Transfer {
                args,
                fee_token,
                rpc_url,
            } => {
                if args.token_address.is_some() {
                    todo!("Handle ERC20 transfers")
                }

                if args.explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                let from = get_address_from_secret_key(&args.private_key.secret_bytes())
                    .map_err(|e| eyre::eyre!(e))?;

                let client = EthClient::new(rpc_url)?;
                let tx_type = if fee_token.is_some() {
                    TxType::FeeToken
                } else {
                    TxType::EIP1559
                };

                let tx_hash = transfer(
                    args.amount,
                    from,
                    args.to,
                    tx_type,
                    &args.private_key,
                    &client,
                    Overrides {
                        fee_token,
                        ..Default::default()
                    },
                )
                .await?;

                println!("{tx_hash:#x}");

                if !args.cast {
                    wait_for_transaction_receipt(tx_hash, &client, 100, args.silent).await?;
                }
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
            Command::GetFeeInfo { block, rpc_url } => {
                let client: EthClient = EthClient::new(rpc_url)?;
                let (block_identifier, block_number) = match block {
                    Some(block_number) => (BlockIdentifier::Number(block_number), block_number),
                    None => {
                        let latest_block = client.get_block_number().await?.as_u64();
                        (BlockIdentifier::Tag(BlockTag::Latest), latest_block)
                    }
                };

                let base_fee_vault_address =
                    get_base_fee_vault_address(&client, block_identifier.clone()).await?;
                let operator_fee_vault_address =
                    get_operator_fee_vault_address(&client, block_identifier.clone()).await?;
                let l1_fee_vault_address =
                    get_l1_fee_vault_address(&client, block_identifier.clone()).await?;

                let operator_fee = get_operator_fee(&client, block_identifier.clone()).await?;
                let blob_base_fee = get_l1_blob_base_fee_per_gas(&client, block_number).await?;

                let base_fee_vault_address = base_fee_vault_address
                    .map(|addr| format!("{addr:#x}"))
                    .unwrap_or_else(String::new);
                let operator_fee_vault_address = operator_fee_vault_address
                    .map(|addr| format!("{addr:#x}"))
                    .unwrap_or_else(String::new);
                let l1_fee_vault_address = l1_fee_vault_address
                    .map(|addr| format!("{addr:#x}"))
                    .unwrap_or_else(String::new);

                let operator_fee = if operator_fee.is_zero() {
                    String::new()
                } else {
                    operator_fee.to_string()
                };
                let blob_base_fee = if blob_base_fee == 0 {
                    String::new()
                } else {
                    blob_base_fee.to_string()
                };

                println!("L2 fee info for block {block_number}:");
                println!("  Base fee vault:                     {base_fee_vault_address}");
                println!("  Operator fee vault:                 {operator_fee_vault_address}");
                println!("  L1 fee vault:                       {l1_fee_vault_address}");
                println!("  Operator fee (wei/gas):             {operator_fee}");
                println!("  L1 blob base fee (wei/blob-gas):    {blob_base_fee}");
            }
            Command::BatchNumber { rpc_url } => {
                let client = EthClient::new(rpc_url)?;

                let batch_number = get_batch_number(&client).await?;
                println!("{batch_number}");
            }
            Command::BatchByNumber {
                batch_number,
                rpc_url,
            } => {
                let client = EthClient::new(rpc_url)?;
                let batch_number = match batch_number {
                    Some(number) => number,
                    None => get_batch_number(&client).await?,
                };

                let batch = match get_batch_by_number(&client, batch_number).await {
                    Ok(batch) => batch.batch,
                    Err(err) => {
                        println!("Batch {batch_number} not available yet: {err}");
                        return Ok(());
                    }
                };

                let commit_tx = batch
                    .commit_tx
                    .map(|tx| format!("{tx:#x}"))
                    .unwrap_or_else(String::new);
                let verify_tx = batch
                    .verify_tx
                    .map(|tx| format!("{tx:#x}"))
                    .unwrap_or_else(String::new);

                println!("Batch info for batch {}", batch.number);
                println!("  Number:                         {}", batch.number);
                println!("  First block:                    {}", batch.first_block);
                println!("  Last block:                     {}", batch.last_block);
                println!("  State root:                     {:#x}", batch.state_root);
                println!(
                    "  Privileged transactions hash:   {:#x}",
                    batch.privileged_transactions_hash
                );
                println!("  Commit tx:                      {commit_tx}");
                println!("  Verify tx:                      {verify_tx}");
            }
            Command::SponsorTx {
                rpc_url,
                to,
                calldata,
                auth_list,
            } => {
                let client = EthClient::new(rpc_url)?;

                let mut auth_list_parsed = Vec::new();
                for auth_tuple_raw in &auth_list {
                    let auth_tuple = parse_hex(auth_tuple_raw)?;
                    let auth_tuple = AuthorizationTuple::decode(&auth_tuple)?;
                    auth_list_parsed.push(auth_tuple);
                }

                let auth_list = if auth_list_parsed.is_empty() {
                    None
                } else {
                    Some(auth_list_parsed)
                };
                let calldata = calldata.unwrap_or_else(Bytes::new);

                let tx_hash = send_ethrex_transaction(&client, to, calldata, auth_list).await?;

                println!("{tx_hash:#x}");
            }
            Command::Authorize { args, rpc_url } => {
                Box::pin(async { EthCommand::Authorize { args, rpc_url }.run().await }).await?
            }
        };
        Ok(())
    }
}
