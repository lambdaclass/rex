# CLI

- [CLI](#cli)
  - [How to install](#how-to-install)
  - [How to run](#how-to-run)
  - [Commands](#commands)
    - [`rex address`](#rex-address)
    - [`rex autocomplete`](#rex-autocomplete)
    - [`rex balance`](#rex-balance)
    - [`rex block-number`](#rex-block-number)
    - [`rex call`](#rex-call)
      - [State overrides](#state-overrides)
        - [Stacking multiple overrides](#stacking-multiple-overrides)
    - [`rex chain-id`](#rex-chain-id)
    - [`rex code`](#rex-code)
    - [`rex create-address`](#rex-create-address)
    - [`rex create2-address`](#rex-create2-address)
    - [`rex decode-calldata`](#rex-decode-calldata)
    - [`rex deploy`](#rex-deploy)
    - [`rex encode-calldata`](#rex-encode-calldata)
    - [`rex hash`](#rex-hash)
    - [`rex help`](#rex-help)
    - [`rex l2`](#rex-l2)
    - [`rex nonce`](#rex-nonce)
    - [`rex receipt`](#rex-receipt)
    - [`rex send`](#rex-send)
    - [`rex sign`](#rex-sign)
    - [`rex signer`](#rex-signer)
    - [`rex transaction`](#rex-transaction)
    - [`rex transfer`](#rex-transfer)
    - [`rex verify-signature`](#rex-verify-signature)
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
  encode-calldata   Encodes calldata
  decode-calldata   Decodes calldata
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
      --private-key <PRIVATE_KEY>  The private key to derive the address from. [env: PRIVATE_KEY=]
  -z, --zero                       The zero address.
  -r, --random                     A random address.
  -h, --help                       Print help
```

### `rex autocomplete`

```Shell
Generate shell completion scripts.

Usage: rex autocomplete <COMMAND>

Commands:
  generate  Generate autocomplete shell script.
  install   Generate and install autocomplete shell script.
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `rex balance`

```Shell
Get the account's balance info.

Usage: rex balance [OPTIONS] <ACCOUNT>

Arguments:
  <ACCOUNT>

Options:
      --token <TOKEN_ADDRESS>                       Specify the token address, the ETH is used as default.
      --eth                                         Display the balance in ETH.
      --rpc-url <RPC_URL>                           [env: RPC_URL=] [default: http://localhost:8545]
      --override-balance <ADDR:VALUE>               Override an account's balance for this call (see [State overrides](#state-overrides)).
      --override-nonce <ADDR:VALUE>                 Override an account's nonce for this call.
      --override-code <ADDR:HEX>                    Override an account's bytecode for this call.
      --override-state <ADDR:SLOT:VALUE>            Replace a storage slot for this call.
      --override-state-diff <ADDR:SLOT:VALUE>       Overlay a storage slot for this call.
      --override-move-precompile <ADDR:TARGET>      Relocate a precompile to a different address.
  -h, --help                                        Print help
```

State overrides require the token form (`--token`); plain ETH balance reads use `eth_getBalance`, which does not accept overrides.

### `rex block-number`

```Shell
Get the current block_number.

Usage: rex block-number [OPTIONS]

Options:
      --rpc-url <RPC_URL>  [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help               Print help
```

### `rex call`

```Shell
Make a call to a contract

Usage: rex call [OPTIONS] <TO> [ARGS]...

Arguments:
  <TO>
  [ARGS]...

Options:
      --calldata <CALLDATA>                         [default: ]
      --value <VALUE>                               Value to send in wei [default: 0]
      --from <FROM>
      --gas-limit <GAS_LIMIT>
      --max-fee-per-gas <MAX_FEE_PER_GAS>
      --explorer-url                                Display transaction URL in the explorer.
      --rpc-url <RPC_URL>                           [env: RPC_URL=] [default: http://localhost:8545]
      --override-balance <ADDR:VALUE>               Override an account's balance for this call (see [State overrides](#state-overrides)).
      --override-nonce <ADDR:VALUE>                 Override an account's nonce for this call.
      --override-code <ADDR:HEX>                    Override an account's bytecode for this call.
      --override-state <ADDR:SLOT:VALUE>            Replace a storage slot for this call.
      --override-state-diff <ADDR:SLOT:VALUE>       Overlay a storage slot for this call.
      --override-move-precompile <ADDR:TARGET>      Relocate a precompile to a different address.
  -h, --help                                        Print help
```

#### State overrides

`rex call` and `rex balance --token …` accept a State Override Set as the 3rd `eth_call` parameter, matching the format documented at <https://geth.ethereum.org/docs/interacting-with-geth/rpc/objects#state-override-set> (also implemented in ethrex as of
[lambdaclass/ethrex#6660](https://github.com/lambdaclass/ethrex/pull/6660)).

The node must support that parameter; if no override flags are passed, the 2-parameter form is used so older nodes keep working.

Each flag is repeatable and scoped per address:

| Flag | Format | Meaning |
|---|---|---|
| `--override-balance` | `ADDR:VALUE` | Set the account balance (hex `0x…` or decimal). |
| `--override-nonce` | `ADDR:VALUE` | Set the account nonce. |
| `--override-code` | `ADDR:HEX` | Replace the account's bytecode. |
| `--override-state` | `ADDR:SLOT:VALUE` | Replace a storage slot, dropping every other slot for that account. |
| `--override-state-diff` | `ADDR:SLOT:VALUE` | Overlay a single storage slot, leaving the rest unchanged. |
| `--override-move-precompile` | `ADDR:TARGET` | Move the precompile at `ADDR` to `TARGET`. |

`--override-state` and `--override-state-diff` are mutually exclusive **for the
same address** — supplying both for one account is rejected by the node.

##### Stacking multiple overrides

Every flag in the table above can be passed multiple times in a single invocation, and different flag types can be mixed freely. All entries are merged into one State Override Set sent as the 3rd `eth_call` parameter:

- Multiple addresses: repeat the same flag with different `ADDR` values
  (`--override-balance 0xAAA…:0x1 --override-balance 0xBBB…:0x2`).
- Multiple fields on one address: stack different flags sharing an `ADDR`
  (`--override-balance 0xAAA…:0x1 --override-nonce 0xAAA…:0x7 --override-code 0xAAA…:0x…`).
- Multiple storage slots on one address: repeat `--override-state-diff` (or
  `--override-state`) with the same `ADDR` and different `SLOT:VALUE` pairs.
  Don't mix `--override-state` with `--override-state-diff` for the same
  address — the node rejects that combination.

Examples:

```bash
# Pin the USDC balance of an address to 0xdeadbeef by overriding the contract's bytecode
rex balance --token 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 \
            0x37305b1cd40574e4c5ce33f8e8306be057fd7341 \
            --override-code 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48:0x63deadbeef60005260206000f3

# Or override the storage slot for that account's balance entry directly
# (slot = keccak256(abi.encode(addr, uint256(9))) — slot 9 holds USDC's balances mapping)
rex balance --token 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 \
            0x37305b1cd40574e4c5ce33f8e8306be057fd7341 \
            --override-state-diff 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48:0x9254cb65314db3d2d7ca17f753f1d9c7f1b6fa05111d18d10ed5b9519d1b247c:0x0123456789

# Stack overrides across addresses:
# - override USDC's balance slot for the target account
# - fabricate a balance + nonce on an unrelated address
rex call 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 \
         --calldata 0x70a0823100000000000000000000000037305b1cd40574e4c5ce33f8e8306be057fd7341 \
         --rpc-url http://my-node:8545 \
         --override-state-diff 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48:0x9254cb65314db3d2d7ca17f753f1d9c7f1b6fa05111d18d10ed5b9519d1b247c:0x42 \
         --override-balance 0x0000000000000000000000000000000000000bad:0x100 \
         --override-nonce   0x0000000000000000000000000000000000000bad:0x7
```

### `rex chain-id`

```Shell
Get the network's chain id.

Usage: rex chain-id [OPTIONS]

Options:
      --hex                Display the chain id as a hex-string.
      --rpc-url <RPC_URL>  [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help               Print help
```

### `rex code`

```Shell
Returns code at a given address

Usage: rex code [OPTIONS] <ADDRESS>

Arguments:
  <ADDRESS>

Options:
  -B, --block <BLOCK>      defaultBlock parameter: can be integer block number, 'earliest', 'finalized', 'safe', 'latest' or 'pending' [default: latest]
      --rpc-url <RPC_URL>  [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help               Print help
```

### `rex create-address`

```Shell
Compute contract address given the deployer address and nonce.

Usage: rex create-address [OPTIONS] <DEPLOYER>

Arguments:
  <DEPLOYER>  Deployer address.

Options:
  -n, --nonce <NONCE>      Deployer Nonce. Latest by default.
      --rpc-url <RPC_URL>  [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help               Print help
```

### `rex create2-address`

```Shell
Usage: rex create2-address [OPTIONS]

Options:
  -d, --deployer <DEPLOYER>
          Deployer address. Default is Mainnet Deterministic Deployer [default: 0x4e59b44847b379578588920cA78FbF26c0B4956C]
  -i, --init-code <INIT_CODE>
          Initcode of the contract to deploy.
      --init-code-hash <INIT_CODE_HASH>
          Hash of the initcode (keccak256).
  -s, --salt <SALT>
          Salt for CREATE2 opcode
      --begins <BEGINS>
          Address must begin with this hex prefix.
      --ends <ENDS>
          Address must end with this hex suffix.
      --contains <CONTAINS>
          Address must contain this hex substring.
      --case-sensitive
          Make the address search case sensitive when using begins, ends, or contains.
      --threads <THREADS>
          Number of threads to use for brute-forcing. Defaults to the number of logical CPUs. [default: 8]
  -h, --help
          Print help
```

### `rex decode-calldata`

```Shell
Decodes calldata

Usage: rex decode-calldata <SIGNATURE> <DATA>

Arguments:
  <SIGNATURE>
  <DATA>

Options:
  -h, --help  Print help
```

### `rex deploy`

```Shell
Deploy a contract

Usage: rex deploy [OPTIONS] <--bytecode <BYTECODE>|--contract-path <CONTRACT_PATH>>

Options:
      --bytecode <BYTECODE>

      --value <VALUE>
          Value to send in wei [default: 0]
      --chain-id <CHAIN_ID>

      --nonce <NONCE>

      --gas-limit <GAS_LIMIT>

      --gas-price <MAX_FEE_PER_GAS>

      --priority-gas-price <MAX_PRIORITY_FEE_PER_GAS>

      --print-address

  -c, --cast
          Send the request asynchronously.
  -s, --silent
          Display only the tx hash.
      --explorer-url
          Display transaction URL in the explorer.
      --private-key <PRIVATE_KEY>
          [env: PRIVATE_KEY=]
      --contract-path <CONTRACT_PATH>
          Path to the Solidity file to compile and deploy
      --remappings <REMAPPINGS>
          Comma-separated remappings (e.g. '@openzeppelin/contracts=https://github.com/OpenZeppelin/openzeppelin-contracts.git,@custom=path/to/custom')
      --keep-deps
          Remove downloaded dependencies after compilation
      --salt <SALT>
          Salt for deploying CREATE2 contracts. If it is provided, the contract will be deployed using CREATE2.
      --rpc-url <RPC_URL>
          [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help
          Print help
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

### `rex help`

```Shell
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
  encode-calldata   Encodes calldata
  decode-calldata   Decodes calldata
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `rex l2`

```Shell
L2 specific commands.

Usage: rex l2 <COMMAND>

Commands:
  balance         Get the account's balance on L2. [aliases: bal, b]
  block-number    Get the current block_number. [aliases: bl]
  call            Make a call to a contract
  chain-id        Get the network's chain id.
  claim-withdraw  Finalize a pending withdrawal.
  deploy          Deploy a contract
  deposit         Deposit funds into some wallet.
  nonce           Get the account's nonce. [aliases: n]
  receipt         Get the transaction's receipt. [aliases: r]
  send            Send a transaction
  transaction     Get the transaction's info. [aliases: tx, t]
  transfer        Transfer funds to another wallet.
  withdraw        Withdraw funds from the wallet.
  message-proof   Get the merkle proof of a L1MessageProof.
  help            Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### `rex nonce`

```Shell
Get the account's nonce.

Usage: rex nonce [OPTIONS] <ACCOUNT>

Arguments:
  <ACCOUNT>

Options:
      --rpc-url <RPC_URL>  [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help               Print help
```

### `rex receipt`

```Shell
Get the transaction's receipt.

Usage: rex receipt [OPTIONS] <TX_HASH>

Arguments:
  <TX_HASH>

Options:
      --rpc-url <RPC_URL>  [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help               Print help
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

### `rex sign`

```Shell
Sign a message with a private key

Usage: rex sign --private-key <PRIVATE_KEY> <MSG>

Arguments:
  <MSG>  Message to be signed with the private key.

Options:
      --private-key <PRIVATE_KEY>  The private key to sign the message. [env: PRIVATE_KEY=]
  -h, --help                       Print help
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

### `rex transaction`

```Shell
Get the transaction's info.

Usage: rex transaction [OPTIONS] <TX_HASH>

Arguments:
  <TX_HASH>

Options:
      --rpc-url <RPC_URL>  [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help               Print help
```

### `rex transfer`

```Shell
Transfer funds to another wallet.

Usage: rex transfer [OPTIONS] <AMOUNT> <TO>

Arguments:
  <AMOUNT>
  <TO>

Options:
      --token <TOKEN_ADDRESS>
      --nonce <NONCE>
  -c, --cast                       Send the request asynchronously.
  -s, --silent                     Display only the tx hash.
      --explorer-url               Display transaction URL in the explorer.
      --private-key <PRIVATE_KEY>  [env: PRIVATE_KEY=]
      --rpc-url <RPC_URL>          [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help                       Print help
```

### `rex verify-signature`

```Shell
Verify if the signature of a message was made by an account

Usage: rex verify-signature <MESSAGE> <SIGNATURE> <ADDRESS>

Arguments:
  <MESSAGE>
  <SIGNATURE>
  <ADDRESS>

Options:
  -h, --help  Print help
```

## Examples

A curated list of examples as GIFs.

TODO
