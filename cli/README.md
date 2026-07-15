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
      - [Block overrides](#block-overrides)
    - [`rex chain-id`](#rex-chain-id)
    - [`rex code`](#rex-code)
    - [`rex create-address`](#rex-create-address)
    - [`rex create2-address`](#rex-create2-address)
    - [`rex decode-calldata`](#rex-decode-calldata)
    - [`rex deploy`](#rex-deploy)
    - [`rex encode-calldata`](#rex-encode-calldata)
    - [`rex frame`](#rex-frame)
      - [`rex frame send`](#rex-frame-send)
      - [`rex frame build`](#rex-frame-build)
      - [`rex frame inspect`](#rex-frame-inspect)
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
      --override-block-number <NUMBER>              Override the block number for this call (see [Block overrides](#block-overrides)).
      --override-block-time <TIMESTAMP>             Override the block timestamp.
      --override-block-gas-limit <GAS>              Override the block gas limit.
      --override-block-coinbase <ADDR>              Override the block coinbase (fee recipient).
      --override-block-prev-randao <HASH>           Override PREVRANDAO.
      --override-block-base-fee <VALUE>             Override the block base fee per gas.
      --override-block-blob-base-fee <VALUE>        Override the blob base fee per gas.
      --override-block-difficulty <VALUE>           Override the block difficulty.
  -h, --help                                        Print help
```

State and block overrides require the token form (`--token`); plain ETH balance reads use `eth_getBalance`, which does not accept overrides.

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
      --override-block-number <NUMBER>              Override the block number for this call (see [Block overrides](#block-overrides)).
      --override-block-time <TIMESTAMP>             Override the block timestamp.
      --override-block-gas-limit <GAS>              Override the block gas limit.
      --override-block-coinbase <ADDR>              Override the block coinbase (fee recipient).
      --override-block-prev-randao <HASH>           Override PREVRANDAO.
      --override-block-base-fee <VALUE>             Override the block base fee per gas.
      --override-block-blob-base-fee <VALUE>        Override the blob base fee per gas.
      --override-block-difficulty <VALUE>           Override the block difficulty.
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

#### Block overrides

`rex call` and `rex balance --token …` also accept a Block Override Set as the 4th `eth_call` parameter, matching the format documented at <https://geth.ethereum.org/docs/interacting-with-geth/rpc/objects#block-overrides> (also implemented in ethrex as of
[lambdaclass/ethrex#6660](https://github.com/lambdaclass/ethrex/pull/6660)).

Each flag replaces one field of the block header the call is simulated against; omitted fields keep the real header values. Unlike state override flags, each flag takes a single value — there is only one block context per call. Numeric values accept hex (`0x…`) or decimal.

| Flag | Format | JSON field | Meaning |
|---|---|---|---|
| `--override-block-number` | `NUMBER` | `number` | Block number (`block.number`). |
| `--override-block-time` | `TIMESTAMP` | `time` | Block timestamp in unix seconds (`block.timestamp`). |
| `--override-block-gas-limit` | `GAS` | `gasLimit` | Block gas limit. |
| `--override-block-coinbase` | `ADDR` | `coinbase` | Fee recipient (`block.coinbase`). Alias: `--override-block-fee-recipient`. |
| `--override-block-prev-randao` | `HASH` | `random` | PREVRANDAO value (`block.prevrandao`). Alias: `--override-block-random`. |
| `--override-block-base-fee` | `VALUE` | `baseFeePerGas` | Base fee per gas (EIP-1559). |
| `--override-block-blob-base-fee` | `VALUE` | `blobBaseFeePerGas` | Blob base fee per gas (EIP-4844). |
| `--override-block-difficulty` | `VALUE` | `difficulty` | Block difficulty; a no-op on post-merge blocks. |

Block and state overrides compose freely in one invocation. When only block override flags are passed, an empty state override object (a no-op) is sent as the 3rd parameter to keep the block override set in 4th position; when neither is passed, the 2-parameter `eth_call` form is used so older nodes keep working.

> [!NOTE]
> The JSON field names follow ethrex and reth (`coinbase`, `random`, `blobBaseFeePerGas`). Recent geth releases renamed these three to `feeRecipient`, `prevRandao` and `blobBaseFee` and silently ignore the older spellings, so against a current geth node those three overrides won't take effect.

Examples:

```bash
# Simulate a call one year in the future, e.g. to check that a vesting
# contract releases funds after its cliff
rex call 0x00000000000000000000000000000000000ce11a \
         --calldata 0x86d1a69f \
         --override-block-time 1812837600 \
         --override-block-number 25000000

# Query an ERC-20 balance under a synthetic block context
rex balance --token 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 \
            0x37305b1cd40574e4c5ce33f8e8306be057fd7341 \
            --override-block-number 0x1312d00

# Combine state and block overrides in one call
rex call 0x00000000000000000000000000000000000ce11a \
         --calldata 0x86d1a69f \
         --override-balance 0x0000000000000000000000000000000000000bad:0x100 \
         --override-block-coinbase 0x000000000000000000000000000000000000cafe
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

### `rex frame`

Send, build, and inspect **frame transactions** (EIP-8141, transaction type `0x06`).
A frame transaction has no ECDSA signature in the usual sense: the sender is
explicit and authentication/gas payment happen through `APPROVE` inside its
*frames*. Each frame runs in a mode — `VERIFY` (authenticate / approve, run as
`ENTRY_POINT`), `SENDER` (execute as the sender), `POST_TX` (post-execution
assertion, EIP-7906) — and the outer `signatures` list carries the secp256k1/P256
signatures the `VERIFY` frames check.

This command uses ethrex's canonical frame-transaction types directly (pinned to
ethrex's `hegota-devnet` branch), so the wire format stays in lockstep with the
deployed EIP-8141/8250/8272/7906 chain.

```Shell
Usage: rex frame <COMMAND>

Commands:
  send     Send a frame (EIP-8141, tx type 0x06) transaction.
  build    Build a raw frame tx from explicit frames (no RPC calls).
  inspect  Inspect a frame tx: decode its frames and pair them with their per-frame results.
```

#### `rex frame send`

Sends a frame transaction. With no `--sponsor`, it builds a self-verified transfer:
a `VERIFY` frame in which the sender approves both execution and payment, then a
`SENDER` frame that transfers `--value` (and optional `--data`) to `--to`. The
sender's secp256k1 signature over the `sig_hash` is placed in the outer
signatures list automatically.

```Shell
Usage: rex frame send [OPTIONS] --to <TO> --private-key <PRIVATE_KEY>

Options:
      --to <TO>                     Recipient of the SENDER frame.
      --value <VALUE>               Amount to transfer (1ether, 1.5gwei, or wei) [default: 0]
      --data <DATA>                 Calldata for the SENDER frame [default: ]
      --sponsor <SPONSOR>           Optional gas-sponsor (paymaster) address for a sponsored tx.
      --sponsor-calldata <..>       Static calldata for the sponsor's VERIFY frame [default: ]
      --sponsor-owner-key <..>      Owner key of the sponsor; adds a second outer signature [env: SPONSOR_OWNER_KEY=]
      --frame-gas-limit <..>        [default: 100000]
      --sponsor-gas-limit <..>      [default: 200000]
      --max-fee-per-gas <..>
      --max-priority-fee-per-gas <..>  maxPriorityFeePerGas [default: 1gwei]
      --private-key <PRIVATE_KEY>   [env: PRIVATE_KEY=]
      --rpc-url <RPC_URL>           [env: RPC_URL=] [default: http://localhost:8545]
      --dry-run                     Print the raw tx hex instead of sending it.
```

Send a self-verified transfer and (after it mines) print the decoded frames:

```Shell
rex frame send \
  --to 0xE25583099BA105D9ec0A67f5Ae86D90e50036425 \
  --value 1gwei \
  --private-key $PRIVATE_KEY \
  --rpc-url https://rpc1.hegota.ethrex.xyz
```

Preview the raw `0x06` bytes without sending (useful for debugging encoding):

```Shell
rex frame send --to 0x… --value 1gwei --private-key $PRIVATE_KEY --dry-run
```

Sponsored (a paymaster pays): the sender approves execution, the sponsor approves
payment. `--sponsor-owner-key` adds the sponsor owner's signature to the outer
signatures list.

```Shell
rex frame send \
  --to 0xRecipient --value 0.01ether \
  --sponsor 0xPaymaster --sponsor-owner-key $SPONSOR_OWNER_KEY \
  --private-key $PRIVATE_KEY --rpc-url https://rpc1.hegota.ethrex.xyz
```

#### `rex frame build`

Builds a raw, **unsigned** frame-tx envelope from explicit frames (no RPC calls).
`--frames` is a JSON array of `{mode, flags, target, gasLimit, value, data}`.
Handy for inspecting the exact `0x06` encoding.

```Shell
Usage: rex frame build --chain-id <CHAIN_ID> --nonce <NONCE> --sender <SENDER> --frames <FRAMES> [OPTIONS]

Options:
      --chain-id <CHAIN_ID>
      --nonce <NONCE>            nonce_seq for key 0 (the account's linear nonce)
      --sender <SENDER>
      --frames <FRAMES>          JSON array of {mode, flags, target, gasLimit, value, data}
      --max-fee <MAX_FEE>        [default: 10gwei]
      --max-priority-fee <..>    [default: 1gwei]
```

```Shell
rex frame build --chain-id 3151908 --nonce 0 --sender 0x… \
  --frames '[{"mode":1,"flags":3,"gasLimit":100000,"value":"0","data":"0x"},
             {"mode":2,"flags":0,"target":"0xRecipient","gasLimit":30000,"value":"1","data":"0x"}]'
```

#### `rex frame inspect`

Fetches both the transaction and its receipt and prints a **unified, decoded**
view: each frame (mode name, decoded `APPROVE` scope / atomic-batch flags, target,
value, data size) paired with its per-frame result (status, gas, log count), under
a header with the sender, resolved payer, keyed nonces, fees and signature count.
(Aliased as `rex frame receipt`.)

```Shell
Usage: rex frame inspect [OPTIONS] <TX_HASH>

Arguments:
  <TX_HASH>
Options:
      --rpc-url <RPC_URL>  [env: RPC_URL=] [default: http://localhost:8545]
```

```Shell
➜ rex frame inspect 0x02e6…0c0a --rpc-url https://rpc1.hegota.ethrex.xyz
Frame transaction (type 0x06)
  status:    SUCCESS
  block:     0x2f6b6
  gas used:  0x52fe
  payer:     0xe25583099ba105d9ec0a67f5ae86d90e50036425 (self)
  sender:    0xe25583099ba105d9ec0a67f5ae86d90e50036425
  nonceKeys: [0x0]  seq: 0xe
  maxFee:    0x2540be400  maxPriorityFee: 0x3b9aca00
  signatures: 1
  frames:    2
    [0] VERIFY [APPROVE execution+payment] -> 0xe255…6425  value 0x0  data 0B
        ✓ gas 0x0, 0 logs
    [1] SENDER [APPROVE none] -> 0xe255…6425  value 0x1  data 0B
        ✓ gas 0x0, 0 logs
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
