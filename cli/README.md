# CLI

- [How to install](#how-to-install)
- [How to run](#how-to-run)
- [Commands](#commands)
  - [`rex address`](#rex-address)
  - [`rex hash`](#rex-hash)
  - [`rex receipt`](#rex-receipt)
  - [`rex transaction`](#rex-transaction)
  - [`rex balance`](#rex-balance)
  - [`rex nonce`](#rex-nonce)
  - [`rex block-number`](#rex-block-number)
  - [`rex signer`](#rex-signer)
  - [`rex chain-id`](#rex-chain-id)
  - [`rex transfer`](#rex-transfer)
  - [`rex send`](#rex-send)
  - [`rex call`](#rex-call)
  - [`rex deploy`](#rex-deploy)
- [Examples](#examples)


## How to install

Running the following command will install the CLI as the binary `rex`.

```Shell
make cli
```

## How to run

After installing the CLI with `make cli`, run `rex` to display the help message.

```Shell
> rex

Usage: rex <COMMAND>

Commands:
  address           Get either the account's address from private key, the zero address, or a random address [aliases: addr, a]
  autocomplete      Generate shell completion scripts.
  balance           Get the account's balance info. [aliases: bal, b]
  block-number      Get the current block_number. [aliases: bl]
  call              Make a call to a contract
  chain-id          Get the network's chain id.
  code              Returns code at a given address
  create-address    Compute contract address given the deployer address and nonce.
  create2-address   Compute contract address with CREATE2 opcode.
  deploy            Deploy a contract
  hash              Get either the keccak for a given input, the zero hash, the empty string, or a random hash [aliases: h]
  l2                L2 specific commands.
  nonce             Get the account's nonce. [aliases: n]
  receipt           Get the transaction's receipt. [aliases: r]
  send              Send a transaction
  sign              Sign a message with a private key
  signer
  transaction       Get the transaction's info. [aliases: tx, t]
  transfer          Transfer funds to another wallet.
  verify-signature  Verify if the signature of a message was made by an account
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Commands

### `rex address`

```Shell
Get either the account's address from private key, the zero address, or a random address

Usage: rex address [OPTIONS]

Options:
      --from-private-key <FROM_PRIVATE_KEY>
          The private key to derive the address from. [env: PRIVATE_KEY=]
  -z, --zero
          The zero address.
  -r, --random
          A random address.
  -h, --help
          Print help
```

### `rex hash`

```Shell
Get either the keccak for a given input, the zero hash, the empty string, or a random hash

Usage: rex hash [OPTIONS]

Options:
      --input <INPUT>  The input to hash.
  -z, --zero           The zero hash.
  -r, --random         A random hash.
  -s, --string         Hash of empty string
  -h, --help           Print help
```

### `rex receipt`

```Shell
Get the transaction's receipt.

Usage: rex receipt <TX_HASH> [RPC_URL]

Arguments:
  <TX_HASH>
  [RPC_URL]  [env: RPC_URL=] [default: http://localhost:8545]

Options:
  -h, --help  Print help
```

### `rex transaction`

```Shell
Get the transaction's info.

Usage: rex transaction <TX_HASH> [RPC_URL]

Arguments:
  <TX_HASH>
  [RPC_URL]  [env: RPC_URL=] [default: http://localhost:8545]

Options:
  -h, --help  Print help
```

### `rex balance`

```Shell
Get the account's balance info.

Usage: rex balance [OPTIONS] <ACCOUNT> [RPC_URL]

Arguments:
  <ACCOUNT>
  [RPC_URL]  [env: RPC_URL=] [default: http://localhost:8545]

Options:
      --token <TOKEN_ADDRESS>  Specify the token address, the ETH is used as default.
      --eth                    Display the balance in ETH.
  -h, --help                   Print help
```

### `rex nonce`

```Shell
Get the account's nonce.

Usage: rex nonce <ACCOUNT> [RPC_URL]

Arguments:
  <ACCOUNT>
  [RPC_URL]  [env: RPC_URL=] [default: http://localhost:8545]

Options:
  -h, --help  Print help
```

### `rex block-number`

```Shell
Get the current block_number.

Usage: rex block-number [RPC_URL]

Arguments:
  [RPC_URL]  [env: RPC_URL=] [default: http://localhost:8545]

Options:
  -h, --help  Print help
```

### `rex signer`

```Shell
Usage: rex signer <MESSAGE> <SIGNATURE>

Arguments:
  <MESSAGE>
  <SIGNATURE>

Options:
  -h, --help  Print help
```

### `rex chain-id`

```Shell
Get the network's chain id.

Usage: rex chain-id [OPTIONS] [RPC_URL]

Arguments:
  [RPC_URL]  [env: RPC_URL=] [default: http://localhost:8545]

Options:
  -h, --hex   Display the chain id as a hex-string.
  -h, --help  Print help
```

### `rex transfer`

```Shell
Transfer funds to another wallet.

Usage: rex transfer [OPTIONS] <AMOUNT> <TO> <PRIVATE_KEY> [RPC_URL]

Arguments:
  <AMOUNT>
  <TO>
  <PRIVATE_KEY>  [env: PRIVATE_KEY=]
  [RPC_URL]      [env: RPC_URL=] [default: http://localhost:8545]

Options:
      --token <TOKEN_ADDRESS>
      --nonce <NONCE>
  -b                           Do not wait for the transaction receipt
      --explorer-url           Display transaction URL in the explorer.
  -h, --help                   Print help
```

### `rex send`

```Shell
Send a transaction

Usage: rex send [OPTIONS] <TO> [ARGS]...

Arguments:
  <TO>
  [ARGS]...

Options:
      --value <VALUE>
          Value to send in wei [default: 0]
      --calldata <CALLDATA>
          [default: ]
      --chain-id <CHAIN_ID>

      --nonce <NONCE>

      --gas-limit <GAS_LIMIT>

      --gas-price <MAX_FEE_PER_GAS>

      --priority-gas-price <MAX_PRIORITY_FEE_PER_GAS>

  -c, --cast
          Send the request asynchronously.
  -s, --silent
          Display only the tx hash.
      --explorer-url
          Display transaction URL in the explorer.
  -k, --private-key <PRIVATE_KEY>
          [env: PRIVATE_KEY=]
      --rpc-url <RPC_URL>
          [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help
          Print help
```

### `rex call`

```Shell
Make a call to a contract

Usage: rex call [OPTIONS] <TO> [ARGS]...

Arguments:
  <TO>
  [ARGS]...

Options:
      --calldata <CALLDATA>                [default: ]
      --value <VALUE>                      Value to send in wei [default: 0]
      --from <FROM>
      --gas-limit <GAS_LIMIT>
      --max-fee-per-gas <MAX_FEE_PER_GAS>
      --explorer-url                       Display transaction URL in the explorer.
      --rpc-url <RPC_URL>                  [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help                               Print help
```

### `rex deploy`

```Shell
Deploy a contract

Usage: rex deploy [OPTIONS] <BYTECODE> [VALUE] <PRIVATE_KEY> -- [SIGNATURE [ARGS]]

Arguments:
  <BYTECODE>
  [VALUE]        Value to send in wei [default: 0]
  <PRIVATE_KEY>  [env: PRIVATE_KEY=]
  

Options:
      --chain-id <CHAIN_ID>
      --nonce <NONCE>
      --gas-limit <GAS_LIMIT>
      --gas-price <MAX_FEE_PER_GAS>
      --priority-gas-price <MAX_PRIORITY_FEE_PER_GAS>
      --print-address                                  Only print the contract address
      --rpc-url                                        [env: RPC_URL=] [default: http://localhost:8545]
  -b                                                   Do not wait for the transaction receipt
      --explorer-url                                   Display transaction URL in the explorer.
  -h, --help                                           Print help
```

### `rex encode-calldata`

```Shell
Encodes calldata

Usage: rex encode-calldata <SIGNATURE> [ARGS]...

Arguments:
  <SIGNATURE>
  [ARGS]...

Options:
  -h, --help  Print help
```

### `rex decode-calldata`

```Shell
Usage: rex decode-calldata <SIGNATURE> <CALLDATA>

Arguments:
  <SIGNATURE>
  <CALLDATA>

Options:
  -h, --help  Print help
```

## Examples

A curated list of examples as GIFs.

TODO
