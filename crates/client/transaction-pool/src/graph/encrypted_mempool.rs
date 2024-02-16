//! Substrate transaction pool implementation.
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

use std::collections::{HashMap, HashSet};

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
    decryption_keys: HashSet<u64>,

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
            decryption_keys: HashSet::default(),
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

    /// increase order
    pub fn increase_order(&mut self) -> u64 {
        self.order += 1;
        self.order
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

    /// provide decryption key
    pub fn provide_decryption_key(&mut self, order: u64) -> bool {
        self.decryption_keys.insert(order)
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

    /// is provided decryption key
    pub fn is_provided_decryption_key(&self, order: u64) -> bool {
        self.decryption_keys.contains(&order)
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
