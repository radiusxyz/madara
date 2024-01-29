//! Substrate transaction pool implementation.
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

use std::collections::HashMap;

use mc_sync_block::get_sync_db;
use mp_transactions::EncryptedInvokeTransaction;

use crate::error::{Error, Result};

/// Store decryption keys and encrypted transactions
/// to process transactions in order.
#[derive(Debug, Clone, Default)]
pub struct BlockEncryptedTransactionPool {
    /// store encrypted transactions. key:value = order:EncryptedInvokeTransaction
    encrypted_transaction_pool: HashMap<u64, EncryptedInvokeTransaction>,

    /// store decryption keys.
    decryption_keys: HashMap<u64, String>,

    /// current order
    order: u64, // decrypted_tx_count + raw_tx_count

    /// decrypted tx count
    decrypted_tx_count: u64,

    /// not encrypted tx count
    raw_tx_count: u64,

    /// close flag
    closed: bool,
}

impl BlockEncryptedTransactionPool {
    /// new
    pub fn new() -> Self {
        Self {
            encrypted_transaction_pool: HashMap::default(),
            decryption_keys: HashMap::default(),
            order: 0,
            decrypted_tx_count: 0,
            raw_tx_count: 0,

            closed: false,
        }
    }

    /// add encrypted tx to EncryptedTransactionBlock
    pub fn add_encrypted_invoke_tx(&mut self, encrypted_invoke_transaction: EncryptedInvokeTransaction) -> u64 {
        let order = self.order;

        self.encrypted_transaction_pool.insert(self.order, encrypted_invoke_transaction);
        self.order += 1;

        order
    }

    /// get encrypted tx for order
    pub fn get_encrypted_invoke_tx(&self, order: u64) -> Result<&EncryptedInvokeTransaction> {
        self.encrypted_transaction_pool
            .get(&order)
            .ok_or(Error::Retrieval(format!("Failed to get tx - order: {}", order)))
    }

    /// increase not encrypted count
    pub fn increase_raw_tx_count(&mut self) -> u64 {
        self.raw_tx_count += 1;
        self.order += 1;
        self.raw_tx_count
    }

    /// encrypted txs orders
    pub fn encrypted_transaction_pool_orders(&self) -> impl Iterator<Item = &u64> {
        self.encrypted_transaction_pool.keys()
    }

    /// encrypted txs len
    pub fn encrypted_txs_len(&self) -> usize {
        self.encrypted_transaction_pool.values().len()
    }

    /// is close
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// close
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// order getter
    pub fn get_order(&self) -> u64 {
        self.order
    }

    /// get encrypted tx count
    /// it's not order
    pub fn get_tx_cnt(&self) -> u64 {
        self.encrypted_transaction_pool.len() as u64 + self.raw_tx_count
    }

    /// increase decrypted tx count
    pub fn increase_decrypted_tx_count(&mut self) {
        self.decrypted_tx_count += 1;
    }

    /// get decrypted tx count
    pub fn get_submitted_tx_count(&self) -> u64 {
        self.decrypted_tx_count + self.raw_tx_count
    }

    /// update key received information
    pub fn update_decryption_keys(&mut self, order: u64, decryption_key: &str) {
        self.decryption_keys.insert(order, decryption_key.to_string());
    }

    /// delete invalid encrypted tx
    pub fn delete_invalid_encrypted_tx(&mut self, order: u64) {
        let Some(_) = self.encrypted_transaction_pool.remove(&order) else {
            return log::info!("Not exist encrypted tx on {order:?}.");
        };

        self.decryption_keys.remove(&order);

        self.order -= 1;

        log::info!("Delete encrypted tx on {order:?}.");
    }

    /// get key received information
    pub fn get_decryption_key(&self, order: u64) -> Option<&String> {
        self.decryption_keys.get(&order)
    }
}

/// encrypted_mempool
#[derive(Debug, Clone, Default)]
/// EncryptedPool struct
/// 1 encrypted_mempool for node
/// * `txs`: Map of Txs, key:value = block_height:Txs
/// * `enabled`: encrypted_mempool enabler. if whole part is splitted by package. it have to be
///   removed.
pub struct EncryptedMemPool {
    /// Map of Txs, key:value = block_height:Txs
    encrypted_transaction_pool_blocks: HashMap<u64, BlockEncryptedTransactionPool>,

    /// encrypted_mempool enabler. if whole part is splitted by package. it have to be removed.
    enabled: bool,

    /// using external decryptor
    using_external_decryptor: bool,
}

impl EncryptedMemPool {
    /// check encrypted_mempool is enabled
    pub fn is_using_encrypted_mempool(&self) -> bool {
        self.enabled
    }

    /// check encrypted_mempool is using external decryptor
    pub fn is_using_external_decryptor(&self) -> bool {
        self.using_external_decryptor
    }

    /// new encrypted_mempool
    pub fn new(is_enabled_encrypted_mempool: bool, using_external_decryptor: bool) -> Self {
        Self {
            encrypted_transaction_pool_blocks: HashMap::default(),
            enabled: is_enabled_encrypted_mempool,
            using_external_decryptor,
        }
    }

    /// add new Txs for block_height
    pub fn new_block(&mut self, block_height: u64) {
        log::info!("insert new tx on {}.", block_height);

        self.encrypted_transaction_pool_blocks.insert(block_height, BlockEncryptedTransactionPool::new());
    }

    /// txs exist
    pub fn exist(&self, block_height: u64) -> bool {
        self.encrypted_transaction_pool_blocks.contains_key(&block_height)
    }

    /// get txs
    pub fn get_txs(&self, block_height: u64) -> Result<&BlockEncryptedTransactionPool> {
        self.encrypted_transaction_pool_blocks
            .get(&block_height)
            .ok_or(Error::Retrieval(format!("Failed to get txs - block height: {}", block_height)))
    }

    /// Closes the block transaction pool for a given block height.
    ///
    /// This function performs the following steps:
    /// 1. Retrieves the `BlockTransactionPool` for the given block height.
    /// 2. If the `BlockTransactionPool` contains encrypted transactions, it serializes them into a
    ///    JSON string.
    /// 3. Retrieves the sync database instance.
    /// 4. Writes the block height as the sync target to the database.
    /// 5. Writes the serialized encrypted transactions to the database using the block height as
    ///    the key.
    /// 6. Closes the `BlockTransactionPool`.
    pub fn close(&mut self, block_height: u64) -> Result<bool> {
        let block_transaction_pool = self
            .encrypted_transaction_pool_blocks
            .get_mut(&block_height)
            .ok_or(Error::Retrieval(format!("Failed to find block height: {}", block_height)))?;

        if !block_transaction_pool.encrypted_transaction_pool.is_empty() {
            let txs_string = serde_json::to_string(
                &block_transaction_pool.encrypted_transaction_pool.values().cloned().collect::<Vec<_>>(),
            )?;
            let db = get_sync_db().map_err(|e| {
                Error::SyncBlock(format!("Failed to get sync db - block height: {block_height}, error: {e:?}"))
            })?;

            db.write("sync_target".to_string(), block_height.to_string()).map_err(|e| {
                Error::SyncBlock(format!("Failed to write sync target - block height: {block_height}, error: {e:?}"))
            })?;
            db.write(block_height.to_string(), txs_string).map_err(|e| {
                Error::SyncBlock(format!("Failed to write encrypted txs - block height: {block_height}, error: {e:?}"))
            })?;
        }

        block_transaction_pool.close();

        Ok(true)
    }

    /// Get or init block transaction pool(if not exist)
    pub fn get_or_init_block_encrypted_transaction_pool(
        &mut self,
        block_height: u64,
    ) -> &mut BlockEncryptedTransactionPool {
        log::info!("insert new tx on {}, if not exist.", block_height);
        self.encrypted_transaction_pool_blocks.entry(block_height).or_default()
    }

    /// Get encrypted transaction block
    pub fn get_block_encrypted_transaction_pool(&self, block_height: &u64) -> Option<&BlockEncryptedTransactionPool> {
        self.encrypted_transaction_pool_blocks.get(block_height)
    }

    /// Get mut encrypted transaction block
    pub fn get_mut_block_encrypted_transaction_pool(
        &mut self,
        block_height: &u64,
    ) -> Option<&mut BlockEncryptedTransactionPool> {
        self.encrypted_transaction_pool_blocks.get_mut(block_height)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use encryptor::SequencerPoseidonEncryption;
    use jsonrpsee::tracing::field::Field;
    use lazy_static::lazy_static;
    use mp_felt::Felt252Wrapper;
    use mp_hashers::vdf::{ReturnData, Vdf};
    use mp_transactions::{InvokeTransaction, InvokeTransactionV1, UserTransaction};
    use sp_runtime::transaction_validity::TransactionSource as Source;
    use starknet_core::types::BroadcastedInvokeTransaction;
    use starknet_crypto::FieldElement;

    use super::super::base_pool;
    use super::*;

    type Hash = u64;

    fn pool() -> base_pool::BasePool<Hash, Vec<u8>> {
        base_pool::BasePool::default()
    }

    fn default_broadcasted_invoke_tx() -> BroadcastedInvokeTransaction {
        let invoke_transaction = default_invoke_transaction();

        let x =
            FieldElement::from_hex_be("0x024d1e355f6b9d27a5a420c8f4b50cea9154a8e34ad30fc39d7c98d3c177d0d7").unwrap();
        BroadcastedInvokeTransaction {
            sender_address: FieldElement::from(invoke_transaction.sender_address().clone()),
            calldata: vec![
                Felt252Wrapper::from_hex_be("0x024d1e355f6b9d27a5a420c8f4b50cea9154a8e34ad30fc39d7c98d3c177d0d7")
                    .unwrap(), // contract_address
                Felt252Wrapper::from_hex_be("0x00e7def693d16806ca2a2f398d8de5951344663ba77f340ed7a958da731872fc")
                    .unwrap(), // selector for the `with_arg` external
                Felt252Wrapper::from_hex_be("0x0000000000000000000000000000000000000000000000000000000000000001")
                    .unwrap(), // calldata_len
                Felt252Wrapper::from_hex_be("0x0000000000000000000000000000000000000000000000000000000000000019")
                    .unwrap(), // calldata[0]
            ],
            max_fee: 0xbc614e,
            signature: vec![Felt252Wrapper::from_hex_be("0x0").unwrap(), Felt252Wrapper::from_hex_be("0x0").unwrap()],
            nonce: Felt252Wrapper::from_hex_be("0x0").unwrap(),
            is_query: false,
        }
    }

    fn encrypted_mempool() -> EncryptedMemPool {
        EncryptedMemPool::new(true, false)
    }

    const DEFAULT_TIME: u64 = 21;

    const DEFAULT_TX: base_pool::Transaction<Hash, Vec<u8>> = base_pool::Transaction {
        data: vec![],
        bytes: 1,
        hash: 1u64,
        priority: 5u64,
        valid_till: 64u64,
        requires: vec![],
        provides: vec![],
        propagate: true,
        source: Source::External,
    };

    fn default_decryption_key() -> String {
        "0x00000000".to_string()
    }

    fn default_invoke_transaction() -> UserTransaction {
        UserTransaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
            max_fee: 0xbc614e,
            signature: vec![Felt252Wrapper::from_hex_be("0x0").unwrap(), Felt252Wrapper::from_hex_be("0x0").unwrap()],
            calldata: vec![
                Felt252Wrapper::from_hex_be("0x024d1e355f6b9d27a5a420c8f4b50cea9154a8e34ad30fc39d7c98d3c177d0d7")
                    .unwrap(), // contract_address
                Felt252Wrapper::from_hex_be("0x00e7def693d16806ca2a2f398d8de5951344663ba77f340ed7a958da731872fc")
                    .unwrap(), // selector for the `with_arg` external
                Felt252Wrapper::from_hex_be("0x0000000000000000000000000000000000000000000000000000000000000001")
                    .unwrap(), // calldata_len
                Felt252Wrapper::from_hex_be("0x0000000000000000000000000000000000000000000000000000000000000019")
                    .unwrap(), // calldata[0]
            ],
            nonce: Felt252Wrapper::from_hex_be("0x0").unwrap(),
            sender_address: Felt252Wrapper::from_hex_be(
                "0x0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
        }))
    }

    fn default_encrypted_invoke_tx() -> EncryptedInvokeTransaction {
        EncryptedInvokeTransaction {
            encrypted_data: vec!["5e5786c7c7fd0cd6de2e1c70fbda5a71800553d1eadf5c0405db7747980f69111382aa8c73c4a2fea2cd7561f07af4b4775b1426f6fb07d29bfd6abfc7b1e428a71a47a9c85c0d095d6624a98342f93b3597abf0bb48b2b4d3b3974562fbc168f9103237bf55a7cb798b7f84ae304e9bba24c2aad1284f6512699d915bc9201b5ed4f03168d6cf9f944d50d26baf813670a0b52cd51fd19b82e96c1cbb36f66537d972754b68aa2169a0184c647f867ae824c321b90d1657dc590632ec968909f2f600c6a96039be71ca7adbd3d03ac93ca01cb9b8a6866f90724c0fe8db541bc150c74a8aca647c4f781bcbec6cdee38592cf446114e09559f27c5b7ac620004d098d2b9d06a66f24b1b128854a98f5dadf1b00e4468a4674e84bafd7a1b418772da78394e895fccf39f9833c386e6ef0b1e7dbaae47bc01859b43c715a3810cdfa881827af36d3333eef3a1ae80170caac88239017455acfc1d089aebd6032baf1be960bef4f7e419c896d99b19583db7b9f3778348b0662454fb2866df2697f6b399b261b1e692d992bdc4792008c2eebc614546b9f8cb9d07a83cd259516ba2033db0313f3f8a46e8c566216a388be2b55b812f5101fa14412204bb3cd48da10c6c79ef7887b5d3e4bfe8b6a5c74c91f11b32a235d92e5a41090f4ee795f747010e25e2737b0786755e1536cbfea2c5d9fcdd8b746fd7c7fbe2885d5985c".to_string()],
            nonce: "37f8084c55afbbc57449592cb1bbbdcb5c6e7e32915450668d706e73ff2ce616".to_string(),
            t: DEFAULT_TIME,
            g: "451677984939420157299126886509548189790888991277748885983880148600301042861971232110930905452414884954950497362648006421883085908110705124858160713918712498240515855258037462325330168086961497962811434578541833357681103870593466111949488243744958815912501471456901411834163805621213209156203969590989281133532221704731610061657055797799646876792607358146023331892393047405124180941403730863209884065697322941896332163049749622008771122557714714225315826091733313647592088619860179360027096759450018379019013202459707220086189478216962038340576800804488087359225172517336476165344524742267011618307991762428984373168".to_string(),
            n: "3258919453951479295335433598690837405240779005883735978816419008323219375373411170496628452563568494345961076232311416820857700849588248503029557289181808703203118469605105843199398703610294812730578233513506094863851030975663400835458332347173884550435708589252615045964561921778596770377353515052767274626956529507215194124455769636419709341915247812831727688022414099152090879221715761589151369869259229768930741014296092794930594884912101288528130548484795664647565862602513303836575583653900598256643194517471862994268338269785499323240778972855894214863203785799646357566116503769953249494471176608616793542199".to_string(),
        }
    }

    #[test]
    fn decrypt_encrypted_invoke_transaction() {
        let vdf = Vdf::new(10, 2048);
        let default_encrypted_invoke_tx = default_encrypted_invoke_tx();

        let decryption_key = {
            vdf.evaluate(
                default_encrypted_invoke_tx.t,
                default_encrypted_invoke_tx.g.clone(),
                default_encrypted_invoke_tx.n.clone(),
            )
        };

        assert_eq!(default_decryption_key(), decryption_key);

        let symmetric_key = SequencerPoseidonEncryption::calculate_secret_key(decryption_key.as_bytes());

        let decrypted_invoke_tx = SequencerPoseidonEncryption::new().decrypt(
            default_encrypted_invoke_tx.encrypted_data.clone(),
            &symmetric_key,
            default_encrypted_invoke_tx.nonce,
        );

        let decrypted_invoke_tx = String::from_utf8(decrypted_invoke_tx).unwrap();
        let trimmed_decrypted_invoke_tx = decrypted_invoke_tx.trim_end_matches('\0');
        // assert_eq!(
        //     serde_json::from_str::<InvokeTransaction>(trimmed_decrypted_invoke_tx).unwrap(),
        //     default_invoke_transaction()
        // );
    }

    fn encrypt_invoke_transaction() {
        let vdf: Vdf = Vdf::new(10, 2048);

        let param = vdf.setup(DEFAULT_TIME); // Generate parameters (it returns value as json string)
        let params: ReturnData = serde_json::from_str(param.as_str()).unwrap(); // Parsing parameters

        // 1. Use trapdoor
        let y = vdf.evaluate_with_trapdoor(params.t, params.g.clone(), params.n.clone(), params.remainder.clone());

        let invoke_tx = UserTransaction::try_from(invoke_transaction).map_err(|e| {
            error!("Failed to convert BroadcastedInvokeTransaction to UserTransaction: {e:?}");
            StarknetRpcApiError::InternalServerError
        })?;
        let invoke_tx_str: String = match invoke_tx {
            UserTransaction::Invoke(invoke_tx) => serde_json::to_string(&invoke_tx)?,
            _ => {
                log::error!("Try to encrypt not invoke transaction");
                return Err(StarknetRpcApiError::InternalServerError.into());
            }
        };

        if !check_message_validity(invoke_tx_str.as_bytes()) {
            log::error!("Invalid invoke transaction");
            return Err(StarknetRpcApiError::InternalServerError.into());
        }

        let encryption_key = SequencerPoseidonEncryption::calculate_secret_key(y.as_bytes());
        let (encrypted_data, nonce, _, _) = SequencerPoseidonEncryption::new().encrypt(invoke_tx_str, encryption_key);
        Ok(EncryptedInvokeTransactionResult {
            encrypted_invoke_transaction: EncryptedInvokeTransaction {
                encrypted_data,
                nonce: format!("{nonce:x}"),
                t,
                g: params.g.clone(),
                n: params.n.clone(),
            },
            decryption_key: y,
        })
    }

    // #[test]
    // fn should_import_transaction_to_ready() {
    //     // given
    //     let mut pool = pool();

    //     // when
    //     pool.import(Transaction { data: vec![1u8], provides: vec![vec![1]], ..DEFAULT_TX
    // }).unwrap();

    //     // then
    //     assert_eq!(pool.ready().count(), 1);
    //     assert_eq!(pool.ready.len(), 1);
    // }

    // #[test]
    // fn should_not_import_same_transaction_twice() {
    //     // given
    //     let mut pool = pool();

    //     // when
    //     pool.import(Transaction { data: vec![1u8], provides: vec![vec![1]], ..DEFAULT_TX
    // }).unwrap();     pool.import(Transaction { data: vec![1u8], provides: vec![vec![1]],
    // ..DEFAULT_TX }).unwrap_err();

    //     // then
    //     assert_eq!(pool.ready().count(), 1);
    //     assert_eq!(pool.ready.len(), 1);
    // }

    // #[test]
    // fn should_import_transaction_to_future_and_promote_it_later() {
    //     // given
    //     let mut pool = pool();

    //     // when
    //     pool.import(Transaction { data: vec![1u8], requires: vec![vec![0]], provides:
    // vec![vec![1]], ..DEFAULT_TX })         .unwrap();
    //     assert_eq!(pool.ready().count(), 0);
    //     assert_eq!(pool.ready.len(), 0);
    //     pool.import(Transaction { data: vec![2u8], hash: 2, provides: vec![vec![0]], ..DEFAULT_TX
    // }).unwrap();

    //     // then
    //     assert_eq!(pool.ready().count(), 2);
    //     assert_eq!(pool.ready.len(), 2);
    // }

    // #[test]
    // fn should_promote_a_subgraph() {
    //     // given
    //     let mut pool = pool();

    //     // when
    //     pool.import(Transaction { data: vec![1u8], requires: vec![vec![0]], provides:
    // vec![vec![1]], ..DEFAULT_TX })         .unwrap();
    //     pool.import(Transaction { data: vec![3u8], hash: 3, requires: vec![vec![2]], ..DEFAULT_TX
    // }).unwrap();     pool.import(Transaction {
    //         data: vec![2u8],
    //         hash: 2,
    //         requires: vec![vec![1]],
    //         provides: vec![vec![3], vec![2]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();
    //     pool.import(Transaction {
    //         data: vec![4u8],
    //         hash: 4,
    //         priority: 1_000u64,
    //         requires: vec![vec![3], vec![4]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();
    //     assert_eq!(pool.ready().count(), 0);
    //     assert_eq!(pool.ready.len(), 0);

    //     let res = pool
    //         .import(Transaction { data: vec![5u8], hash: 5, provides: vec![vec![0], vec![4]],
    // ..DEFAULT_TX })         .unwrap();

    //     // then
    //     let mut it = pool.ready().map(|tx| tx.data[0]);

    //     assert_eq!(it.next(), Some(5));
    //     assert_eq!(it.next(), Some(1));
    //     assert_eq!(it.next(), Some(2));
    //     assert_eq!(it.next(), Some(4));
    //     assert_eq!(it.next(), Some(3));
    //     assert_eq!(it.next(), None);
    //     assert_eq!(res, Imported::Ready { hash: 5, promoted: vec![1, 2, 3, 4], failed: vec![],
    // removed: vec![] }); }

    // #[test]
    // fn should_handle_a_cycle() {
    //     // given
    //     let mut pool = pool();
    //     pool.import(Transaction { data: vec![1u8], requires: vec![vec![0]], provides:
    // vec![vec![1]], ..DEFAULT_TX })         .unwrap();
    //     pool.import(Transaction {
    //         data: vec![3u8],
    //         hash: 3,
    //         requires: vec![vec![1]],
    //         provides: vec![vec![2]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();
    //     assert_eq!(pool.ready().count(), 0);
    //     assert_eq!(pool.ready.len(), 0);

    //     // when
    //     pool.import(Transaction {
    //         data: vec![2u8],
    //         hash: 2,
    //         requires: vec![vec![2]],
    //         provides: vec![vec![0]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();

    //     // then
    //     {
    //         let mut it = pool.ready().map(|tx| tx.data[0]);
    //         assert_eq!(it.next(), None);
    //     }
    //     // all transactions occupy the Future queue - it's fine
    //     assert_eq!(pool.future.len(), 3);

    //     // let's close the cycle with one additional transaction
    //     let res = pool
    //         .import(Transaction { data: vec![4u8], hash: 4, priority: 50u64, provides:
    // vec![vec![0]], ..DEFAULT_TX })         .unwrap();
    //     let mut it = pool.ready().map(|tx| tx.data[0]);
    //     assert_eq!(it.next(), Some(4));
    //     assert_eq!(it.next(), Some(1));
    //     assert_eq!(it.next(), Some(3));
    //     assert_eq!(it.next(), None);
    //     assert_eq!(res, Imported::Ready { hash: 4, promoted: vec![1, 3], failed: vec![2],
    // removed: vec![] });     assert_eq!(pool.future.len(), 0);
    // }

    // #[test]
    // fn should_handle_a_cycle_with_low_priority() {
    //     // given
    //     let mut pool = pool();
    //     pool.import(Transaction { data: vec![1u8], requires: vec![vec![0]], provides:
    // vec![vec![1]], ..DEFAULT_TX })         .unwrap();
    //     pool.import(Transaction {
    //         data: vec![3u8],
    //         hash: 3,
    //         requires: vec![vec![1]],
    //         provides: vec![vec![2]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();
    //     assert_eq!(pool.ready().count(), 0);
    //     assert_eq!(pool.ready.len(), 0);

    //     // when
    //     pool.import(Transaction {
    //         data: vec![2u8],
    //         hash: 2,
    //         requires: vec![vec![2]],
    //         provides: vec![vec![0]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();

    //     // then
    //     {
    //         let mut it = pool.ready().map(|tx| tx.data[0]);
    //         assert_eq!(it.next(), None);
    //     }
    //     // all transactions occupy the Future queue - it's fine
    //     assert_eq!(pool.future.len(), 3);

    //     // let's close the cycle with one additional transaction
    //     let err = pool
    //         .import(Transaction {
    //             data: vec![4u8],
    //             hash: 4,
    //             priority: 1u64, // lower priority than Tx(2)
    //             provides: vec![vec![0]],
    //             ..DEFAULT_TX
    //         })
    //         .unwrap_err();
    //     let mut it = pool.ready().map(|tx| tx.data[0]);
    //     assert_eq!(it.next(), None);
    //     assert_eq!(pool.ready.len(), 0);
    //     assert_eq!(pool.future.len(), 0);
    //     if let error::Error::CycleDetected = err {
    //     } else {
    //         unreachable!("Invalid error kind: {:?}", err);
    //     }
    // }

    // #[test]
    // fn should_remove_invalid_transactions() {
    //     // given
    //     let mut pool = pool();
    //     pool.import(Transaction { data: vec![5u8], hash: 5, provides: vec![vec![0], vec![4]],
    // ..DEFAULT_TX }).unwrap();     pool.import(Transaction { data: vec![1u8], requires:
    // vec![vec![0]], provides: vec![vec![1]], ..DEFAULT_TX })         .unwrap();
    //     pool.import(Transaction { data: vec![3u8], hash: 3, requires: vec![vec![2]], ..DEFAULT_TX
    // }).unwrap();     pool.import(Transaction {
    //         data: vec![2u8],
    //         hash: 2,
    //         requires: vec![vec![1]],
    //         provides: vec![vec![3], vec![2]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();
    //     pool.import(Transaction {
    //         data: vec![4u8],
    //         hash: 4,
    //         priority: 1_000u64,
    //         requires: vec![vec![3], vec![4]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();
    //     // future
    //     pool.import(Transaction {
    //         data: vec![6u8],
    //         hash: 6,
    //         priority: 1_000u64,
    //         requires: vec![vec![11]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();
    //     assert_eq!(pool.ready().count(), 5);
    //     assert_eq!(pool.future.len(), 1);

    //     // when
    //     pool.remove_subtree(&[6, 1]);

    //     // then
    //     assert_eq!(pool.ready().count(), 1);
    //     assert_eq!(pool.future.len(), 0);
    // }

    // #[test]
    // fn should_prune_ready_transactions() {
    //     // given
    //     let mut pool = pool();
    //     // future (waiting for 0)
    //     pool.import(Transaction {
    //         data: vec![5u8],
    //         hash: 5,
    //         requires: vec![vec![0]],
    //         provides: vec![vec![100]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();
    //     // ready
    //     pool.import(Transaction { data: vec![1u8], provides: vec![vec![1]], ..DEFAULT_TX
    // }).unwrap();     pool.import(Transaction {
    //         data: vec![2u8],
    //         hash: 2,
    //         requires: vec![vec![2]],
    //         provides: vec![vec![3]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();
    //     pool.import(Transaction {
    //         data: vec![3u8],
    //         hash: 3,
    //         requires: vec![vec![1]],
    //         provides: vec![vec![2]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();
    //     pool.import(Transaction {
    //         data: vec![4u8],
    //         hash: 4,
    //         priority: 1_000u64,
    //         requires: vec![vec![3], vec![2]],
    //         provides: vec![vec![4]],
    //         ..DEFAULT_TX
    //     })
    //     .unwrap();

    //     assert_eq!(pool.ready().count(), 4);
    //     assert_eq!(pool.future.len(), 1);

    //     // when
    //     let result = pool.prune_tags(vec![vec![0], vec![2]]);

    //     // then
    //     assert_eq!(result.pruned.len(), 2);
    //     assert_eq!(result.failed.len(), 0);
    //     assert_eq!(result.promoted[0], Imported::Ready { hash: 5, promoted: vec![], failed:
    // vec![], removed: vec![] });     assert_eq!(result.promoted.len(), 1);
    //     assert_eq!(pool.future.len(), 0);
    //     assert_eq!(pool.ready.len(), 3);
    //     assert_eq!(pool.ready().count(), 3);
    // }

    // #[test]
    // fn transaction_debug() {
    //     assert_eq!(
    //         format!(
    //             "{:?}",
    //             Transaction {
    //                 data: vec![4u8],
    //                 hash: 4,
    //                 priority: 1_000u64,
    //                 requires: vec![vec![3], vec![2]],
    //                 provides: vec![vec![4]],
    //                 ..DEFAULT_TX
    //             }
    //         ),
    //         "Transaction { hash: 4, priority: 1000, valid_till: 64, bytes: 1, propagate: true,
    // source: \          TransactionSource::External, requires: [03, 02], provides: [04], data:
    // [4]}"             .to_owned()
    //     );
    // }

    // #[test]
    // fn transaction_propagation() {
    //     assert!(
    //         Transaction {
    //             data: vec![4u8],
    //             hash: 4,
    //             priority: 1_000u64,
    //             requires: vec![vec![3], vec![2]],
    //             provides: vec![vec![4]],
    //             ..DEFAULT_TX
    //         }
    //         .is_propagable(),
    //     );

    //     assert!(
    //         !Transaction {
    //             data: vec![4u8],
    //             hash: 4,
    //             priority: 1_000u64,
    //             requires: vec![vec![3], vec![2]],
    //             provides: vec![vec![4]],
    //             propagate: false,
    //             ..DEFAULT_TX
    //         }
    //         .is_propagable(),
    //     );
    // }

    // #[test]
    // fn should_reject_future_transactions() {
    //     // given
    //     let mut pool = pool();

    //     // when
    //     pool.reject_future_transactions = true;

    //     // then
    //     let err = pool.import(Transaction { data: vec![5u8], hash: 5, requires: vec![vec![0]],
    // ..DEFAULT_TX });

    //     if let Err(error::Error::RejectedFutureTransaction) = err {
    //     } else {
    //         unreachable!("Invalid error kind: {:?}", err);
    //     }
    // }

    // #[test]
    // fn should_clear_future_queue() {
    //     // given
    //     let mut pool = pool();

    //     // when
    //     pool.import(Transaction { data: vec![5u8], hash: 5, requires: vec![vec![0]], ..DEFAULT_TX
    // }).unwrap();

    //     // then
    //     assert_eq!(pool.future.len(), 1);

    //     // and then when
    //     assert_eq!(pool.clear_future().len(), 1);

    //     // then
    //     assert_eq!(pool.future.len(), 0);
    // }

    // #[test]
    // fn should_accept_future_transactions_when_explicitly_asked_to() {
    //     // given
    //     let mut pool = pool();
    //     pool.reject_future_transactions = true;

    //     // when
    //     let flag_value = pool.with_futures_enabled(|pool, flag| {
    //         pool.import(Transaction { data: vec![5u8], hash: 5, requires: vec![vec![0]],
    // ..DEFAULT_TX }).unwrap();

    //         flag
    //     });

    //     // then
    //     assert!(flag_value);
    //     assert!(pool.reject_future_transactions);
    //     assert_eq!(pool.future.len(), 1);
    // }
}
