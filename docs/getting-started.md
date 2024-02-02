## Getting Started

Follow the steps below to get started with Madara :hammer_and_wrench:

### Rust Setup

First, Install rust using the [rustup](https://rustup.rs/) toolchain installer,
then run:

```bash
rustup show
```

### Single-Node Development Chain

Use Rust's native `cargo` command to build and launch the template node:

You first need to setup up the node, which means you need to load the genesis
state into your file system.

```sh
cargo run --release -- setup --chain=dev --from-remote
```

Now, you can start the node in development mode

```sh
cargo run --release -- --dev
```

### Interacting with the node

Madara is compatible with the Starknet
[spec](https://github.com/starkware-libs/starknet-specs) which means all tooling
around Starknet (starknet-js, starknet-rs, wallets, etc.) can be used out of the
box by just changing the RPC url to point to your node. By default, this would
be `http://localhost:9944`.

### Common chain flags

You can check all the available using the `--help` flag. Some common points to
know about have been mentioned below.

Madara overrides the default `dev` flag in substrate to meet its requirements.
The following flags are automatically enabled with the `--dev` argument:

`--chain=dev`, `--force-authoring`, `--alice`, `--tmp`, `--rpc-external`,
`--rpc-methods=unsafe`

The `--tmp` flag stores the chain database in a temporary folder. You can
specify a custom folder to store the chain state by using the `--base-path`
flag. You cannot combine the `base-path` command with `--dev` as `--dev`
enforces `--tmp` which will store the db at a temporary folder. You can,
however, manually specify all flags that the dev flag adds automatically. Keep
in mind, the path must be the same as the one you used in the setup command.

The node also supports to use manual seal (to produce block manually through
RPC).

```sh
cargo run --release -- --dev --sealing=manual
# Or
cargo run --release -- --dev --sealing=instant
```

Log level can be specified with `-l` flag. For example, `-ldebug` will show
debug logs. It can also be specified via the `RUST_LOG` environment variable.
For example:

```sh
RUSTLOG=runtime=info cargo run --release -- --dev
```

### Encrypted Mempool (additional feature)

Madara now includes an encrypted mempool feature, enhancing the privacy and security of transaction handling. This feature allows transactions to be encrypted before being added to the block, providing an additional layer of security.

#### Key Features

- Encrypt Transactions: Encrypts raw transactions before they are broadcasted.
- Decrypt and Process: Decrypts encrypted transactions and processes them for block inclusion.
- Maintain Transaction Order: Ensures the order of transactions is maintained during encryption and decryption.

#### Running Madara with Encrypted Mempool

To use the encrypted mempool feature, you need to start Madara with the `--encrypted-mempool` flag.
This activates the encrypted mempool functionality, allowing the node to handle encrypted transactions.

```sh
# Start the node in development mode with encrypted mempool
cargo run --release -- --dev --encrypted-mempool
```

When running with this flag, Madara will process transactions through the encrypted mempool,
ensuring that they are encrypted and decrypted as required.

#### Encrypted mempool examples

The encrypted mempool introduces three additional APIs, offering a brief overview of their usage as follows:

1. `starknet_encryptInvokeTransaction`: This API encrypts an InvokeTransaction, store it into the encrypted mempool, and prepares it for submission.
```bash
curl -H "Content-Type: application/json" --data '{"jsonrpc":"2.0", "method":"starknet_encryptInvokeTransaction", "params":{
        "invoke_transaction": {
            "sender_address":"0x0000000000000000000000000000000000000000000000000000000000000001",
            "calldata": [
                "0x0000000000000000000000000000000000000000000000000000000000001111",
                "0x36fa6de2810d05c3e1a0ebe23f60b9c2f4629bbead09e5a9704e1c5632630d5",
                "0x0"
            ],
            "type": "INVOKE",
            "max_fee": "0xbc614e",
            "version":"0x1",
            "signature":[
                "0x0",
                "0x0"
            ],
            "nonce":"0x0",
            "offset_version": "0x0"
        },
        "t": 21
    }, "id":1}' http://localhost:9944
```

2. starknet_addEncryptedInvokeTransaction: This API decrypts an encrypted `InvokeTransaction`(`encryptedInvokeTransaction`).
Internally, it converts it to an `InvokeTransaction`, but externally it ensures the confidentiality of the transaction until the block-proposer is executed for submission.
```bash
curl -H "Content-Type: application/json" --data '{"jsonrpc":"2.0", "method":"starknet_addEncryptedInvokeTransaction", "params":{
        "encrypted_invoke_transaction": {
            "encrypted_data": [
                "38ed7151ec73bfab66329e942a8f73894d37959bf249657b33c4f997f8ff716be90da9268a3ab574fbe347865998d6ad375f5649fbf72ea8f41e07bb36a4832aabea97331e68e5fed3177a18d9481685fe5949ad7d9fad9b39378528afad492a35504ba655cdd9f1909f4bab5c6ffb54cbfc4c5653a45ad7293d7ec6bd438e438d4aedcd7b82d09b976d98adec42209fc83d9927eed123f58ec48592f5b1140add48385ebeea26be089bca07bfd0e32122139b8c1228e6452fd9a10515cee0376e2f67d825c4ceca516337d268a4fc677471113632d7e9609ccbd5b95d9fcd5bd8812a200cb172982efa547bf1d262bae014b09b431a6bcbeba18f25751bde6e134ad0b28ecda7d41a68d21371e7c6bbe97b26966c53b5a12b434a2cb422703d27f3859b0c4e9839cdef154f99d4625356e85df85f62b06fb8a1af045a08f222cf5bdd750cca98ef66adf584dd58e11e7d0dfd24259377419716978a5f25e5329540d4597740517200e1f754d01781f7f8963ff551666570de4a32ddf576a75250c4719f3b0e826c90bb83bf42aae5433b376e4daf63a649b9e373ac5086e173c89ccb132bdb24d49c4e03685c1e38b325ad048f69a049de133fcc67604ec7428ec4513a803eab057672050f5478e7bda9550642325988521bf0c692f78f2e28ba9e44aa07f8f33752ab0833da872ef950f064d5406fc036baefb21732530d2d"
            ],
            "nonce": "b6fc5414f5d840407634125a164b829d07fab68c65e445d811d0e5747c8f7b2c",
            "t": 21,
            "g": "382050312305592825275638071519082809123314586421603966245918330320565386947189362537042566359900465745756796222333843463258127509350883957404923512162726572427100423628537017599195391268622565942002029755085933238994019446944971348480458536665640676388242255291606596404874975216479394636640208795858726794957992174507593972794610110344730066272020737129489406809778853709284271571861059524799330201454851967898626826454271906638935119605086096266941103128912750328529076850600133166971864899891267773425556764853409932887861178039474089869642553970378636992210186260740904184077939641268683497743609506050708015380",
            "n": "625759200465258705356572421693925323556086799529081781449298661638763787690898175613664915514646655883097527442780074460020495364179629386109119548884721632772146255526253778178954164346555794556534375589445216499096025920398002021282560646095796082868834236691804564600529385746409792551324847608421832366095631372475412608877289133797255375236469231312544403490031287284029596871573739927797699040565314000327958226215014395200378065886996725281876689888032170308715493156690754124916012752697105590541940952448726172947639444751566850535289955954097224323749158260168220512633739357115412682852716685827459574361"
        }
    }, "id":1}' http://localhost:9944
```

3. starknet_decryptEncryptedInvokeTransaction: API for decrypt test that decrypts an `encryptedInvokeTransaction`, and return the decrypted `InvokeTransaction` as result.
```bash
curl -H "Content-Type: application/json" --data '{"jsonrpc":"2.0", "method":"starknet_decryptEncryptedInvokeTransaction", "params":{
        "encrypted_invoke_transaction": {
            "encrypted_data": [
                "38ed7151ec73bfab66329e942a8f73894d37959bf249657b33c4f997f8ff716be90da9268a3ab574fbe347865998d6ad375f5649fbf72ea8f41e07bb36a4832aabea97331e68e5fed3177a18d9481685fe5949ad7d9fad9b39378528afad492a35504ba655cdd9f1909f4bab5c6ffb54cbfc4c5653a45ad7293d7ec6bd438e438d4aedcd7b82d09b976d98adec42209fc83d9927eed123f58ec48592f5b1140add48385ebeea26be089bca07bfd0e32122139b8c1228e6452fd9a10515cee0376e2f67d825c4ceca516337d268a4fc677471113632d7e9609ccbd5b95d9fcd5bd8812a200cb172982efa547bf1d262bae014b09b431a6bcbeba18f25751bde6e134ad0b28ecda7d41a68d21371e7c6bbe97b26966c53b5a12b434a2cb422703d27f3859b0c4e9839cdef154f99d4625356e85df85f62b06fb8a1af045a08f222cf5bdd750cca98ef66adf584dd58e11e7d0dfd24259377419716978a5f25e5329540d4597740517200e1f754d01781f7f8963ff551666570de4a32ddf576a75250c4719f3b0e826c90bb83bf42aae5433b376e4daf63a649b9e373ac5086e173c89ccb132bdb24d49c4e03685c1e38b325ad048f69a049de133fcc67604ec7428ec4513a803eab057672050f5478e7bda9550642325988521bf0c692f78f2e28ba9e44aa07f8f33752ab0833da872ef950f064d5406fc036baefb21732530d2d"
            ],
            "nonce": "b6fc5414f5d840407634125a164b829d07fab68c65e445d811d0e5747c8f7b2c",
            "t": 21,
            "g": "382050312305592825275638071519082809123314586421603966245918330320565386947189362537042566359900465745756796222333843463258127509350883957404923512162726572427100423628537017599195391268622565942002029755085933238994019446944971348480458536665640676388242255291606596404874975216479394636640208795858726794957992174507593972794610110344730066272020737129489406809778853709284271571861059524799330201454851967898626826454271906638935119605086096266941103128912750328529076850600133166971864899891267773425556764853409932887861178039474089869642553970378636992210186260740904184077939641268683497743609506050708015380",
            "n": "625759200465258705356572421693925323556086799529081781449298661638763787690898175613664915514646655883097527442780074460020495364179629386109119548884721632772146255526253778178954164346555794556534375589445216499096025920398002021282560646095796082868834236691804564600529385746409792551324847608421832366095631372475412608877289133797255375236469231312544403490031287284029596871573739927797699040565314000327958226215014395200378065886996725281876689888032170308715493156690754124916012752697105590541940952448726172947639444751566850535289955954097224323749158260168220512633739357115412682852716685827459574361"
        }
    }, "id":1}' http://localhost:9944
```

Using the `starknet_getBlockWithTxs`, we can see that the `encryptedInvokeTransaction` has been added to the block.
```bash
curl -H "Content-Type: application/json" --data '{"jsonrpc":"2.0", "method":"starknet_getBlockWithTxs", "params":{
        "block_id": {
            "block_number": 3
        }
    }, "id":1}' http://localhost:9944
```

### Using Nix (optional, only for degens)

Install [nix](https://nixos.org/) and optionally
[direnv](https://github.com/direnv/direnv) and
[lorri](https://github.com/nix-community/lorri) for a fully plug and play
experience for setting up the development environment. To get all the correct
dependencies activate direnv `direnv allow` and lorri `lorri shell`.

### Embedded Docs

Once the project has been built, the following command can be used to explore
all parameters and subcommands:

```sh
./target/release/madara -h
```

### Connect with Polkadot-JS Apps Front-end

Once the node template is running locally, you can connect it with **Polkadot-JS
Apps** front-end to interact with your chain.
[Click here](https://polkadot.js.org/apps/#/explorer?rpc=ws://localhost:9944)
connecting the Apps to your local node template.

### Multi-Node Local Testnet

Build custom chain spec:

```bash
# Build plain chain spec
cargo run --release -- build-spec --chain local > chain-specs/madara-local-testnet-plain.json
# Build final raw chain spec
cargo run --release -- build-spec --chain chain-specs/madara-local-testnet-plain.json --raw > chain-specs/madara-local-testnet.json
```

See more details about
[custom chain specs](https://docs.substrate.io/reference/how-to-guides/basics/customize-a-chain-specification/).

### Testing Madara RPC Endpoints

To test the Madara RPC endpoints, follow the steps below:

Run Madara locally (by default, it runs on port 9944):

```bash
cargo run --release -- --dev
# Alternatively, use other methods to run Madara
```

Execute hurl tests sequentially:

```bash
hurl --variables-file examples/rpc/hurl.config  --test examples/rpc/**/*.hurl
```

The output should be similar to the image provided:

![Hurl Test Output](./images/hurl-test-output.png)

### Set Ethereum Node URL for offchain worker

In order for the offchain worker to access an Ethereum RPC node, we need to set
the URL for that in offchain local storage. We can do that by making use of the
default
[`offchain` rpc calls](https://polkadot.js.org/docs/substrate/rpc/#offchain)
provided by Substrate.

In the polkadot explorer, navigate to Developer > RPC calls and choose the
`offchain` endpoint. In there, you can set the value for
`ETHEREUM_EXECUTION_RPC` by using the `localStorageSet` function. You need to
select the type of storage, in this case `PERSISTENT`, and use the
`starknet::ETHEREUM_EXECUTION_RPC` as the `key`. The value is the RPC URL you
intend to use.

![](./images/madara-set-rpc-url-in-local-storage.png)

You can check that the value was properly set by using the `localStorageGet`
function

![](./images/madara-get-rpc-url-from-local-storage.png)

### Run in Docker

First, install [Docker](https://docs.docker.com/get-docker/) and
[Docker Compose](https://docs.docker.com/compose/install/).

Then run the following command to start a single node development chain.

```bash
docker run --rm [TAG] --dev
```

This command will firstly compile your code, and then start a local development
network. The TAGS are available
[here](https://github.com/keep-starknet-strange/madara/pkgs/container/madara).

You can also use the command appending your own options. A few useful ones are
as follow.

```bash
# Run Substrate node without re-compiling
docker run --rm [TAG] --dev --ws-external

# Purge the local dev chain
docker run --rm [TAG] purge-chain --dev
```
