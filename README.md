# Rex - Developing on Ethereum powered by Ethrex

`rex` is a set of utilities for Ethereum development.

With **Rex** you can
- Launch your own devnet using ethrex
- Interact with a running L1 network
- Interact with a running Ethrex L2 network
- Execute useful functions for Ethereum development.

**Rex** can be used both as a **CLI tool** and via its **Rust SDK**, allowing seamless integration with any Rust script.

Our **CLI** is built on top of the **SDK**, ensuring a consistent and powerful developer experience.

## `rex` CLI

The `rex` CLI is a command line tool that provides a set of utilities for Ethereum development.

### Installing the CLI

Running the following command will install the CLI as the binary `rex`.

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
  hash          Get either the keccak for a given input, the zero hash, the empty string, or a random hash [aliases: h, h]
  l2            L2 specific commands.
  nonce         Get the account's nonce. [aliases: n]
  receipt       Get the transaction's receipt. [aliases: r]
  send          Send a transaction
  signer        
  transaction   Get the transaction's info. [aliases: tx, t]
  transfer      Transfer funds to another wallet.
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

You can find the CLI documentation [here](cli/README.md).

## `rex` SDK

The `rex` SDK provides a set of utilities for Ethereum development.
<TODO: Explain basic usage>
<TODO: Explain client>
<TODO: Explain l2?

### Using the SDK
<TODO: basic usage, kind of help, how to add the sdk to a project>

You can find the SDK documentation [here](sdk/README.md).



 
