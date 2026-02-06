# CLI

- [How to install](#how-to-install)
- [How to run](#how-to-run)
- [Commands](#commands)
  - [`rex address`](#rex-address)
  - [`rex autocomplete`](#rex-autocomplete)
  - [`rex balance`](#rex-balance)
  - [`rex block-number`](#rex-block-number)
  - [`rex call`](#rex-call)
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
      --token <TOKEN_ADDRESS>  Specify the token address, the ETH is used as default.
      --eth                    Display the balance in ETH.
      --rpc-url <RPC_URL>      [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help                   Print help
```

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
      --calldata <CALLDATA>                [default: ]
      --value <VALUE>                      Value to send in wei [default: 0]
      --from <FROM>
      --gas-limit <GAS_LIMIT>
      --max-fee-per-gas <MAX_FEE_PER_GAS>
      --explorer-url                       Display transaction URL in the explorer.
      --rpc-url <RPC_URL>                  [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help                               Print help
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
      --optimizations <OPTIMIZATIONS>
          Number of optimization runs for the Solidity compiler
      --verify-contract
          Verify the contract on Etherscan after deployment
      --etherscan-api-key <ETHERSCAN_API_KEY>
          Etherscan API key for contract verification [env: ETHERSCAN_API_KEY=]
      --contract-name <CONTRACT_NAME>
          Contract name (defaults to filename stem). Required when file contains multiple contracts.
      --rpc-url <RPC_URL>
          [env: RPC_URL=] [default: http://localhost:8545]
  -h, --help
          Print help
```

#### Contract verification

The `--verify-contract` flag automatically verifies the contract source code on Etherscan after deployment. This makes the contract's source code publicly readable and its ABI available on Etherscan.

**Requirements:**
- Must use `--contract-path` (not `--bytecode`)
- Requires an Etherscan API key via `--etherscan-api-key` or the `ETHERSCAN_API_KEY` environment variable
- Incompatible with `--cast` (verification needs to wait for the transaction receipt)
- Requires `solc` installed locally (the same version used to compile will be reported to Etherscan)

**Supported networks:** Ethereum Mainnet, Sepolia, and Holesky (uses [Etherscan API V2](https://docs.etherscan.io/etherscan-v2)).

**Basic example:**

```shell
rex deploy \
  --contract-path MyContract.sol \
  --remappings "" \
  --verify-contract \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  --private-key $PRIVATE_KEY \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

**With optimizer enabled:**

```shell
rex deploy \
  --contract-path MyContract.sol \
  --remappings "" \
  --optimizations 200 \
  --verify-contract \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  --private-key $PRIVATE_KEY \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

**With imports and remappings:**

```shell
rex deploy \
  --contract-path MyToken.sol \
  --remappings "@openzeppelin/contracts=https://github.com/OpenZeppelin/openzeppelin-contracts.git" \
  --verify-contract \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  --private-key $PRIVATE_KEY \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

**With constructor arguments:**

```shell
rex deploy \
  --contract-path MyToken.sol \
  --remappings "" \
  --verify-contract \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  --private-key $PRIVATE_KEY \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
  -- "constructor(string,uint256)" "MyToken" 1000000
```

**Output:**

```
Compiler run successful. Artifact(s) can be found in directory "./solc_out".
Contract deployed in tx: 0x1234...
Contract address: 0x5678...

Verifying contract on Etherscan...
  Compiler version: v0.8.31+commit.fd3a2265
  Contract name: MyContract
  Submitting verification request...
  Verification submitted (GUID: abc123...)
  [1/60] Checking verification status...
  Contract verified successfully!
  https://sepolia.etherscan.io/address/0x5678...#code
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
