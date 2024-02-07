## Getting Started With Encrypted Mempool

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

Now, you can start the node in development mode with encrypted mempool

To use the encrypted mempool feature, you need to start Madara with the `--encrypted-mempool` flag.
This activates the encrypted mempool functionality, allowing the node to handle encrypted transactions.

```sh
# Start the node in development mode with encrypted mempool
cargo run --release -- --dev --encrypted-mempool
```

### Encrypted Mempool

Madara now has an encrypted mempool feature providing censorship /
MEV resistance through trustless environment where users don’t have to trust sequencers. Sequencers don’t have any knowledge on the contents of transactions until the block is determined, making the process trustless. 

#### Concepts
Encrypted mempool determines the transaction order and provides the function to decrypt the encrypted transaction using a time-lock puzzle. As transactions are encrypted, it prevents censorship and MEV attacks. Additionally, users can simplify the decryption process by providing a decryption key(currently being implemented). Even without the decryption key, it's still possible to decrypt the transaction through additional computations.

#### Key Features
1. Encrypt: Transactions are encrypted with timelock-puzzle before broadcasting
2. Commit: Sequencer creates order commitment of encrypted transactions
3. Decrypt: Sequencer solves Timelock puzzle to decrypt transactions
4. Sequencing: Sequencer builds block as promised in order commitment

#### Encrypted mempool examples
The encrypted mempool introduces three additional APIs
- starknet_encrypteInvokeTransaction (for testing)
- starknet_decryptEncryptedInvokeTransaction (for testing)
- starknet_addEncryptedInvokeTransaction

Other functions (for DeclareTransaction & DeployTransaction and provideDecryptionKey..) are currently under development.

Offering a brief overview of usage as follows:

1. `starknet_encryptInvokeTransaction`: The transaction as `EncryptedInvokeTransaction` should be provided on the client side, and there should not be need to manually encrypt the `InvokeTrasaction` to `EncryptedInvokeTrasaction`. Currently, as a workaround, you can manually convert an `InvokeTransaction` into an `EncryptedInvokeTransaction` and submit it via the `starknet_addInvokeTransaction` API. Below is an example of how to encrypt the `InvokedTransaction`.

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

2. `starknet_decryptEncryptedInvokeTransaction`: API for test that decrypts an `EncryptedInvokeTransaction`, and return the decrypted `InvokeTransaction` as result.

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

    Above, `t`, `encrypted_data`, `nonce`, `g`, and `n` are parameters used for encryption and decryption through VDF(time-lock puzzle).

    - `t`  
    `t` represents the time parameter used in a `VDF`. It determines the amount of time required for the computation. The larger the value of t, the longer the computation takes.

    - `encrypted_data`  
    The encrypted data is generated with the following steps:
    By using a `VDF` setup, the `decryption key` is created based on the `t` value. `decryption key` is then used to generate a `Poseidon secret key` with Poseidon encryption.
    `InvokeTransaction`(as a string) is encrypted with `Poseidon secret key`, resulting in hex-encoded data.

    - `nonce`  
    The nonce is a random value for the permutation operation required for Poseidon encryption.
    To ensure proper decryption, it is necessary to have a nonce identical to the encrypted nonce to set the initial state.

    - `g` and `n`  
    Parameters generated during the `VDF` setup. `g` is a RSA group generator, and `n` is the modulus.

3. `starknet_addEncryptedInvokeTransaction`: This API adds an `EncryptedInvokeTransaction` to the `Encrypted Mempool`, and generates an transaction order and signature.  
(If added into the `Encrypted mempool`, the `EncryptedInvokeTransaction` is decrypted and submitted when the `block-proposer` applies extrinsic.)

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

    Using the `starknet_getBlockWithTxs`, we can see that the transaction has been added to the block.

    ```bash
    curl -H "Content-Type: application/json" --data '{"jsonrpc":"2.0", "method":"starknet_getBlockWithTxs", "params":{
            "block_id": {
                "block_number": 3
            }
        }, "id":1}' http://localhost:9944
    ```