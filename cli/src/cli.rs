use crate::commands::l2;
use crate::utils::{parse_contract_creation, parse_func_call, parse_hex, parse_hex_string};
use crate::{
    commands::autocomplete,
    common::{CallArgs, DeployArgs, SendArgs, TransferArgs},
    utils::parse_private_key,
};
use clap::{ArgAction, Parser, Subcommand};
use ethrex_common::types::TxType;
use ethrex_common::{Address, Bytes, H256, H520};
use ethrex_l2_common::calldata::Value;
use ethrex_l2_common::utils::get_address_from_secret_key;
use ethrex_l2_rpc::signer::{LocalSigner, Signer};
use ethrex_rpc::EthClient;
use ethrex_rpc::clients::Overrides;
use ethrex_rpc::types::block_identifier::{BlockIdentifier, BlockTag};
use ethrex_sdk::calldata::decode_calldata;
use ethrex_sdk::{build_generic_tx, send_generic_transaction};
use keccak_hash::keccak;
use rex_sdk::client::eth::get_token_balance;
use rex_sdk::create::{
    DETERMINISTIC_DEPLOYER, brute_force_create2, compute_create_address, compute_create2_address,
};
use rex_sdk::sign::{get_address_from_message_and_signature, sign_hash};
use rex_sdk::utils::to_checksum_address;
use rex_sdk::{balance_in_eth, deploy, transfer, wait_for_transaction_receipt};
use secp256k1::SecretKey;
use std::io::{self, Write};

pub const VERSION_STRING: &str = env!("CARGO_PKG_VERSION");

pub async fn start() -> eyre::Result<()> {
    let CLI { command } = CLI::parse();
    command.run().await
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Parser)]
#[command(name="rex", author, version=VERSION_STRING, about, long_about = None)]
pub(crate) struct CLI {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    #[clap(
        about = "Get either the account's address from private key, the zero address, or a random address",
        visible_aliases = ["addr", "a"]
    )]
    Address {
        #[arg(long, value_parser = parse_private_key, conflicts_with_all = ["zero", "random"], required_unless_present_any = ["zero", "random"], env = "PRIVATE_KEY", help = "The private key to derive the address from.")]
        from_private_key: Option<SecretKey>,
        #[arg(short, long, action = ArgAction::SetTrue, conflicts_with_all = ["from_private_key", "random"], required_unless_present_any = ["from_private_key", "random"], help = "The zero address.")]
        zero: bool,
        #[arg(short, long, action = ArgAction::SetTrue, conflicts_with_all = ["from_private_key", "zero"], required_unless_present_any = ["from_private_key", "zero"], help = "A random address.")]
        random: bool,
    },
    #[clap(subcommand, about = "Generate shell completion scripts.")]
    Autocomplete(autocomplete::Command),
    #[clap(about = "Get the account's balance info.", visible_aliases = ["bal", "b"])]
    Balance {
        account: Address,
        #[clap(
            long = "token",
            conflicts_with = "eth",
            help = "Specify the token address, the ETH is used as default."
        )]
        token_address: Option<Address>,
        #[arg(
            long = "eth",
            required = false,
            default_value_t = false,
            conflicts_with = "token_address",
            help = "Display the balance in ETH."
        )]
        eth: bool,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Get the current block_number.", visible_alias = "bl")]
    BlockNumber {
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Make a call to a contract")]
    Call {
        #[clap(flatten)]
        args: CallArgs,
        #[arg(long, default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Get the network's chain id.")]
    ChainId {
        #[arg(
            long,
            default_value_t = false,
            help = "Display the chain id as a hex-string."
        )]
        hex: bool,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Returns code at a given address")]
    Code {
        address: Address,
        #[arg(
            short = 'B',
            long = "block",
            required = false,
            default_value_t = String::from("latest"),
            help = "defaultBlock parameter: can be integer block number, 'earliest', 'finalized', 'safe', 'latest' or 'pending'"
        )]
        block: String,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Compute contract address given the deployer address and nonce.")]
    CreateAddress {
        #[arg(help = "Deployer address.")]
        deployer: Address,
        #[arg(short = 'n', long, help = "Deployer Nonce. Latest by default.")]
        nonce: Option<u64>,
        #[arg(long, default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    Create2Address {
        #[arg(
            short = 'd',
            long,
            help = "Deployer address. Default is Mainnet Deterministic Deployer",
            default_value = DETERMINISTIC_DEPLOYER
        )]
        deployer: Address,
        #[arg(
            short = 'i',
            long,
            help = "Initcode of the contract to deploy.",
            required_unless_present_any = ["init_code_hash"],
            conflicts_with_all = ["init_code_hash"]
        )]
        init_code: Option<Bytes>,
        #[arg(
            long,
            help = "Hash of the initcode (keccak256).",
            required_unless_present_any = ["init_code"],
            conflicts_with_all = ["init_code"]
        )]
        init_code_hash: Option<H256>,
        #[arg(short = 's', long, help = "Salt for CREATE2 opcode")]
        salt: Option<H256>,
        #[arg(
            long,
            required_unless_present_any = ["salt", "ends", "contains"],
            help = "Address must begin with this hex prefix.",
            value_parser = parse_hex_string,
        )]
        begins: Option<String>,
        #[arg(
            long,
            required_unless_present_any = ["salt", "begins", "contains"],
            help = "Address must end with this hex suffix.",
            value_parser = parse_hex_string,
        )]
        ends: Option<String>,
        #[arg(
            long,
            required_unless_present_any = ["salt", "begins", "ends"],
            help = "Address must contain this hex substring.",
            value_parser = parse_hex_string,
        )]
        contains: Option<String>,
        #[arg(
            long,
            help = "Make the address search case sensitive when using begins, ends, or contains.",
            default_value_t = false,
            conflicts_with_all = ["salt"],
        )]
        case_sensitive: bool,
        #[arg(
            long,
            help = "Number of threads to use for brute-forcing. Defaults to the number of logical CPUs.",
            default_value_t = rayon::current_num_threads(),
            conflicts_with_all = ["salt"],
        )]
        threads: usize,
    },
    #[clap(about = "Deploy a contract")]
    Deploy {
        #[clap(flatten)]
        args: DeployArgs,
        #[arg(long, default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(
        about = "Get either the keccak for a given input, the zero hash, the empty string, or a random hash",
        visible_alias = "h"
    )]
    Hash {
        #[arg(long, value_parser = parse_hex, conflicts_with_all = ["zero", "random", "string"], required_unless_present_any = ["zero", "random", "string"], help = "The input to hash.")]
        input: Option<Bytes>,
        #[arg(short, long, action = ArgAction::SetTrue, conflicts_with_all = ["input", "random", "string"], required_unless_present_any = ["input", "random", "string"], help = "The zero hash.")]
        zero: bool,
        #[arg(short, long, action = ArgAction::SetTrue, conflicts_with_all = ["input", "zero", "string"], required_unless_present_any = ["input", "zero", "string"], help = "A random hash.")]
        random: bool,
        #[arg(short, long, action = ArgAction::SetTrue, conflicts_with_all = ["input", "zero", "random"], required_unless_present_any = ["input", "zero", "random"], help = "Hash of empty string")]
        string: bool,
    },
    #[clap(subcommand, about = "L2 specific commands.")]
    L2(l2::Command),
    #[clap(about = "Get the account's nonce.", visible_aliases = ["n"])]
    Nonce {
        account: Address,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Get the transaction's receipt.", visible_alias = "r")]
    Receipt {
        tx_hash: H256,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Send a transaction")]
    Send {
        #[clap(flatten)]
        args: SendArgs,
        #[arg(long, default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Sign a message with a private key")]
    Sign {
        #[arg(value_parser = parse_hex, help = "Message to be signed with the private key.")]
        msg: Bytes,
        #[arg(value_parser = parse_private_key, env = "PRIVATE_KEY", help = "The private key to sign the message.")]
        private_key: SecretKey,
    },
    Signer {
        #[arg(value_parser = parse_hex)]
        message: Bytes,
        #[arg(value_parser = parse_hex)]
        signature: Bytes,
    },
    #[clap(about = "Get the transaction's info.", visible_aliases = ["tx", "t"])]
    Transaction {
        tx_hash: H256,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Transfer funds to another wallet.")]
    Transfer {
        #[clap(flatten)]
        args: TransferArgs,
        #[arg(default_value = "http://localhost:8545", env = "RPC_URL")]
        rpc_url: String,
    },
    #[clap(about = "Verify if the signature of a message was made by an account")]
    VerifySignature {
        #[arg(value_parser = parse_hex)]
        message: Bytes,
        #[arg(value_parser = parse_hex)]
        signature: Bytes,
        address: Address,
    },
    #[clap(about = "Encodes calldata")]
    EncodeCalldata {
        signature: String,
        #[clap(required = false)]
        args: Vec<String>,
    },
    #[clap(about = "Decodes calldata")]
    DecodeCalldata {
        signature: String,
        #[arg(value_parser = parse_hex)]
        data: Bytes,
    },
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
                let eth_client = EthClient::new(&rpc_url)?;
                let account_balance = if let Some(token_address) = token_address {
                    get_token_balance(&eth_client, account, token_address).await?
                } else {
                    eth_client
                        .get_balance(account, BlockIdentifier::Tag(BlockTag::Latest))
                        .await?
                };

                println!("{}", balance_in_eth(eth, account_balance));
            }
            Command::BlockNumber { rpc_url } => {
                let eth_client = EthClient::new(&rpc_url)?;

                let block_number = eth_client.get_block_number().await?;

                println!("{block_number}");
            }
            Command::CreateAddress {
                deployer,
                nonce,
                rpc_url,
            } => {
                let nonce = nonce.unwrap_or(
                    EthClient::new(&rpc_url)?
                        .get_nonce(deployer, BlockIdentifier::Tag(BlockTag::Latest))
                        .await?,
                );

                println!("Address: {:#x}", compute_create_address(deployer, nonce))
            }
            Command::Create2Address {
                deployer,
                init_code,
                salt,
                init_code_hash,
                begins,
                ends,
                contains,
                case_sensitive,
                threads,
            } => {
                let init_code_hash = init_code_hash
                    .or_else(|| init_code.as_ref().map(keccak))
                    .ok_or_else(|| eyre::eyre!("init_code_hash and init_code are both None"))?;

                let (salt, contract_address) = match salt {
                    Some(salt) => {
                        let contract_address =
                            compute_create2_address(deployer, init_code_hash, salt);
                        (salt, contract_address)
                    }
                    None => {
                        // If salt is not provided, search for a salt that matches the criteria set by the user.
                        println!("\nComputing Create2 Address with {threads} threads...");
                        io::stdout().flush().ok();

                        let start = std::time::Instant::now();
                        let (salt, contract_address) = brute_force_create2(
                            deployer,
                            init_code_hash,
                            begins,
                            ends,
                            contains,
                            case_sensitive,
                        );
                        let duration = start.elapsed();
                        println!("Generated in: {duration:.2?}.");
                        (salt, contract_address)
                    }
                };

                let contract_address = to_checksum_address(&format!("{contract_address:x}"));

                println!("\nSalt: {salt:#x}");
                println!("\nAddress: 0x{contract_address}");
            }
            Command::Transaction { tx_hash, rpc_url } => {
                let eth_client = EthClient::new(&rpc_url)?;

                let tx = eth_client
                    .get_transaction_by_hash(tx_hash)
                    .await?
                    .ok_or(eyre::Error::msg("Not found"))?;

                println!("{tx}");
            }
            Command::Receipt { tx_hash, rpc_url } => {
                let eth_client = EthClient::new(&rpc_url)?;

                let receipt = eth_client
                    .get_transaction_receipt(tx_hash)
                    .await?
                    .ok_or(eyre::Error::msg("Not found"))?;

                println!("{:x?}", receipt.tx_info);
            }
            Command::Nonce { account, rpc_url } => {
                let eth_client = EthClient::new(&rpc_url)?;

                let nonce = eth_client
                    .get_nonce(account, BlockIdentifier::Tag(BlockTag::Latest))
                    .await?;

                println!("{nonce}");
            }
            Command::Address {
                from_private_key,
                zero,
                random,
            } => {
                let address = if let Some(private_key) = from_private_key {
                    get_address_from_secret_key(&private_key).map_err(|e| eyre::eyre!(e))?
                } else if zero {
                    Address::zero()
                } else if random {
                    Address::random()
                } else {
                    return Err(eyre::Error::msg("No option provided"));
                };

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
            Command::Signer { message, signature } => {
                let signer = get_address_from_message_and_signature(message, signature)?;

                println!("{signer:x?}");
            }
            Command::Transfer { args, rpc_url } => {
                if args.token_address.is_some() {
                    todo!("Handle ERC20 transfers")
                }

                if args.explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                let from =
                    get_address_from_secret_key(&args.private_key).map_err(|e| eyre::eyre!(e))?;

                let client = EthClient::new(&rpc_url)?;

                let tx_hash = transfer(
                    args.amount,
                    from,
                    args.to,
                    &args.private_key,
                    &client,
                    Overrides::default(),
                )
                .await?;

                println!("{tx_hash:#x}");

                if !args.cast {
                    wait_for_transaction_receipt(tx_hash, &client, 100, args.silent).await?;
                }
            }
            Command::Send { args, rpc_url } => {
                if args.explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                let from =
                    get_address_from_secret_key(&args.private_key).map_err(|e| eyre::eyre!(e))?;

                let client = EthClient::new(&rpc_url)?;

                let calldata = if !args.calldata.is_empty() {
                    args.calldata
                } else {
                    parse_func_call(args._args)?
                };

                let tx = build_generic_tx(
                    &client,
                    TxType::EIP1559,
                    args.to,
                    from,
                    calldata,
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
                )
                .await?;

                let signer = Signer::Local(LocalSigner::new(args.private_key));

                let tx_hash = send_generic_transaction(&client, tx, &signer).await?;

                println!("{tx_hash:#x}");

                if !args.cast {
                    wait_for_transaction_receipt(tx_hash, &client, 100, args.silent).await?;
                }
            }
            Command::Call { args, rpc_url } => {
                if args.explorer_url {
                    todo!("Display transaction URL in the explorer")
                }

                let client = EthClient::new(&rpc_url)?;

                let calldata = if !args.calldata.is_empty() {
                    args.calldata
                } else {
                    parse_func_call(args._args)?
                };

                let result = client
                    .call(
                        args.to,
                        calldata,
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

                let deployer = Signer::Local(LocalSigner::new(args.private_key));

                let client = EthClient::new(&rpc_url)?;

                let init_code = if !args._args.is_empty() {
                    let init_args = parse_contract_creation(args._args)?;
                    [args.bytecode, init_args].concat().into()
                } else {
                    args.bytecode
                };

                let (tx_hash, deployed_contract_address) = deploy(
                    &client,
                    &deployer,
                    init_code,
                    Overrides {
                        value: args.value.into(),
                        nonce: args.nonce,
                        chain_id: args.chain_id,
                        gas_limit: args.gas_limit,
                        max_fee_per_gas: args.max_fee_per_gas,
                        max_priority_fee_per_gas: args.max_priority_fee_per_gas,
                        ..Default::default()
                    },
                    true,
                )
                .await?;

                if args.print_address {
                    println!("{deployed_contract_address:#x}");
                } else {
                    println!("Contract deployed in tx: {tx_hash:#x}");
                    println!("Contract address: {deployed_contract_address:#x}");
                }
                let silent = args.print_address;

                if !args.cast {
                    wait_for_transaction_receipt(tx_hash, &client, 100, silent).await?;
                }
            }
            Command::ChainId { hex, rpc_url } => {
                let eth_client = EthClient::new(&rpc_url)?;

                let chain_id = eth_client.get_chain_id().await?;

                if hex {
                    println!("{chain_id:#x}");
                } else {
                    println!("{chain_id}");
                }
            }
            Command::Code {
                address,
                block,
                rpc_url,
            } => {
                let eth_client = EthClient::new(&rpc_url)?;

                let block_identifier = BlockIdentifier::parse(serde_json::Value::String(block), 0)?;

                let code = eth_client.get_code(address, block_identifier).await?;

                println!("0x{}", hex::encode(code));
            }

            // Signature computed as a 0x45 signature, as described in EIP-191 (https://eips.ethereum.org/EIPS/eip-191),
            // then it has an extra byte concatenated at the end, which is a scalar value added to the signatures parity,
            // as described in the Yellow Paper Section 4.2 in the specification of a transaction's w field. (https://ethereum.github.io/yellowpaper/paper.pdf)
            Command::Sign { msg, private_key } => {
                let payload = [
                    b"\x19Ethereum Signed Message:\n",
                    msg.len().to_string().as_bytes(),
                    msg.as_ref(),
                ]
                .concat();
                let encoded_signature = sign_hash(keccak(payload), private_key);
                println!("0x{:x}", H520::from_slice(&encoded_signature));
            }
            Command::VerifySignature {
                message,
                signature,
                address,
            } => {
                println!(
                    "{}",
                    get_address_from_message_and_signature(message, signature)? == address
                );
            }
            Command::EncodeCalldata {
                signature,
                mut args,
            } => {
                args.insert(0, signature);
                println!("0x{:x}", parse_func_call(args)?);
            }
            Command::DecodeCalldata { signature, data } => {
                for elem in decode_calldata(&signature, data)? {
                    print_calldata(0, elem);
                }
            }
        };
        Ok(())
    }
}

fn print_calldata(depth: usize, data: Value) {
    print!("{}", " ".repeat(depth));
    match data {
        Value::Address(addr) => println!("{addr:#x}"),
        Value::Array(inner) => {
            println!("[");
            for elem in inner {
                print_calldata(depth + 2, elem);
            }
            println!("]");
        }
        Value::Bool(b) => println!("{b}"),
        Value::Bytes(bytes) => println!("0x{bytes:#x}"),
        Value::FixedArray(inner) => {
            println!("[");
            for elem in inner {
                print_calldata(depth + 2, elem);
            }
            println!("]");
        }
        Value::FixedBytes(bytes) => println!("{bytes:#x}"),
        Value::Int(val) => println!("{val}"),
        Value::Uint(val) => println!("{val}"),
        Value::String(str) => println!("{str}"),
        Value::Tuple(inner) => {
            println!("(");
            for elem in inner {
                print_calldata(depth + 2, elem);
            }
            println!(")");
        }
    }
}
