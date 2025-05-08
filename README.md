# Rex - Developing on Ethereum powered by Ethrex

Rex is a set of utilities for Ethereum development powered by [Ethrex](https://github.com/lambdaclass/ethrex).

With **Rex** you can
- Launch your own devnet using Ethrex
- Interact with a running L1 network
- Interact with a running Ethrex L2 network
- Execute useful functions for Ethereum development.

**Rex** can be used both as a **CLI tool** and via its **Rust SDK**, allowing seamless integration with any Rust script.

Our **CLI** is built on top of the **SDK**, ensuring a consistent and powerful developer experience.

Rex is currently a replacement for foundry's `cast` and `alloy`.

## `rex` CLI

The `rex` CLI is a command line tool that provides a set of utilities for Ethereum development.

### Installing the CLI

So far, **Rex** does not have a published release on [crates.io](https://crates.io).  
To install it, you need to clone the repository and run the following command to install the CLI as the binary `rex`:

```Shell
make cli
```

### Using the CLI

After installing the CLI with `make cli`, run `rex` to display the help message and see the available commands.

```Shell
➜  ~ rex
Usage: rex <COMMAND>

Commands:
  address       Get either the account's address from private key, the zero address, or a random address [aliases: addr, a]
  autocomplete  Generate shell completion scripts.
  balance       Get the account's balance info. [aliases: bal, b]
  block-number  Get the current block_number. [aliases: bl]
  call          Make a call to a contract
  chain-id      Get the network's chain id.
  deploy        Deploy a contract
  code          Returns code at a given address
  hash          Get either the keccak for a given input, the zero hash, the empty string, or a random hash [aliases: h, h]
  l2            L2 specific commands.
  nonce         Get the account's nonce. [aliases: n]
  receipt       Get the transaction's receipt. [aliases: r]
  send          Send a transaction
  signer        
  transaction   Get the transaction's info. [aliases: tx, t]
  transfer      Transfer funds to another wallet.
  sign          Sign a message with a private key.
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

#### Helpful operations

![ops](./assets/operations_demo.gif)

#### Interacting with an Ethereum node

> [!NOTE]
> Before running the following commands, make sure you have an Ethereum node running or override the default RPC URL with the `--rpc-url` flag to point to a public node.

![eth](./assets/chain_demo.gif)

#### Interacting with an ethrex L2 node

TODO

You can find the CLI documentation [here](cli/README.md).

## `rex` SDK

The `rex` SDK provides a set of utilities for Ethereum and ethrex L2 development. With it, you can write Rust scripts to interact with Ethereum and ethrex L2 networks as well as deploy and interact with smart contracts, transferring funds between accounts, and more. 

### Getting Started with the SDK

#### Adding the SDK to your project

For the moment, `rex-sdk` is not yet published on crates.io. You can add the SDK to your project by adding the following to your `Cargo.toml` file:

```toml
[dependencies]
rex-sdk = { git = "https://github.com/lambdaclass/rex", package = "rex-sdk", branch = "main" }
ethrex-common = { git = "https://github.com/lambdaclass/ethrex", package = "ethrex-common", branch = "main" }
```

> [!TIP]
> Maybe consider adding tokio as dependency since we are using a lot of async/await functions. If this example is meant to be done in the main function the #[tokio::main] annotation is needed.

<!-- Uncomment the following after crates.io publishing -->
<!-- Add the following to your `Cargo.toml` file:

```toml
[dependencies]
rex-sdk = "0.1.0"
ethrex-common = { git = "https://github.com/lambdaclass/ethrex", package = "ethrex-common", branch = "main" }
```

Or, via the command line:

```Shell
cargo add rex-sdk
``` -->

#### First Steps

In the following example we will show simple interactions with an Ethereum node similar to the CLI example but using the SDK (as a matter of fact, the CLI uses the SDK as backend).

As pre-requisites for running this example you need to have an Ethereum node running locally or have access to a public node. And you need to have an account with some funds (these must be the values of `account` and `from_private_key` in the following example).

*Importing the dependencies*

```Rust
use ethrex_common::{Address, U256};
use rex_sdk::{
    client::{EthClient, Overrides},
    transfer, wait_for_transaction_receipt,
};
use std::str::FromStr;
```

The following should be either part of a function or the main function.

*Connecting to the node*

```Rust
let rpc_url = "http://localhost:8545";

let eth_client = EthClient::new(rpc_url);
```

*Doing simple interactions (balance and nonce of an account and chain-id)*

```Rust
let account_balance = eth_client.get_balance(account).await.unwrap();

let account_nonce = eth_client.get_nonce(account).await.unwrap();

let chain_id = eth_client.get_chain_id().await.unwrap();

println!("Account balance: {account_balance}");
println!("Account nonce: {account_nonce}");
println!("Chain id: {chain_id}");
```

*Transferring funds*

```Rust
let amount = U256::from_dec_str("1000000000000000000").unwrap(); // 1 ETH in wei
let from = account;
let to = Address::from_str("0x4852f44fd706e34cb906b399b729798665f64a83").unwrap();

let tx_hash = transfer(
    amount,
    from,
    to,
    from_private_key,
    &eth_client,
    Overrides {
        value: Some(amount),
        ..Default::default()
    },
)
.await
.unwrap();

// Wait for the transaction to be finalized
wait_for_transaction_receipt(tx_hash, &eth_client, 100)
    .await
    .unwrap();
```

*Getting transfer tx hash details and receipt*

```Rust
let tx_receipt = eth_client.get_transaction_receipt(tx_hash).await.unwrap();

println!("transfer tx receipt: {tx_receipt:?}");

let tx_details = eth_client.get_transaction_by_hash(tx_hash).await.unwrap();

println!("transfer tx details: {tx_details:?}");
```

#### Full Example

```Rust
use ethrex_common::{Address, U256};
use rex_sdk::{
    client::{EthClient, Overrides},
    transfer, wait_for_transaction_receipt,
};
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let rpc_url = "http://localhost:8545";

    let eth_client = EthClient::new(&rpc_url);

    let account_balance = eth_client.get_balance(account).await.unwrap();

    let account_nonce = eth_client.get_nonce(account).await.unwrap();

    let chain_id = eth_client.get_chain_id().await.unwrap();

    println!("Account balance: {account_balance}");
    println!("Account nonce: {account_nonce}");
    println!("Chain id: {chain_id}");

    let amount = U256::from(1000000000000000000); // 1 ETH in wei
    let from = account;
    let to = Address::from_str("0x4852f44fd706e34cb906b399b729798665f64a83").unwrap();

    let tx_hash = transfer(
        amount,
        from,
        to,
        from_private_key,
        &eth_client,
        Overrides {
            value: Some(amount),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Wait for the transaction to be finalized
    wait_for_transaction_receipt(tx_hash, &eth_client, 100)
        .await
        .unwrap();

    let tx_receipt = eth_client.get_transaction_receipt(tx_hash).await.unwrap();

    println!("transfer tx receipt: {tx_receipt:?}");

    let tx_details = eth_client.get_transaction_by_hash(tx_hash).await.unwrap();

    println!("transfer tx details: {tx_details:?}");
}
```

#### Running the example

> [!WARNING]
> Before running the example, make sure you have an Ethereum node running or override the default RPC URL with the `--rpc-url` flag to point to a public node.
> The account associated to the private key must have some funds in the network you are connecting to.

```Shell
cd sdk
cargo run --release --example simple_usage -- --private-key <PRIVATE_KEY> --rpc-url <RPC_URL>
```

> [!NOTE]
> You can find the code for this example in `sdk/examples/simple_usage.rs`.

You can find the SDK documentation [here](sdk/README.md).


# Security

We take security seriously. If you discover a vulnerability in this project, please report it responsibly. 

- You can report vulnerabilities directly via the **[GitHub "Report a Vulnerability" feature](../../security/advisories/new)**.
- Alternatively, send an email to **[security@lambdaclass.com](mailto:security@lambdaclass.com)**.

For more details, please refer to our [Security Policy](./.github/SECURITY.md).

 
