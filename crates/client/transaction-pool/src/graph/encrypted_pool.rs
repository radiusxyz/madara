//! Substrate transaction pool implementation.
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

use std::collections::HashMap;

use mc_sync_block::SYNC_DB;
use mp_transactions::EncryptedInvokeTransaction;

use crate::error::{Error, Result};

/// Store decryption keys and encrypted transactions
/// to process transactions in order.
#[derive(Debug, Clone, Default)]
pub struct BlockTransactionPool {
    /// store encrypted tx
    encrypted_pool: HashMap<u64, EncryptedInvokeTransaction>,

    /// store .
    decryption_keys: HashMap<u64, bool>,

    /// current order
    order: u64, // decrypted_tx_count + raw_tx_count

    /// decrypted tx count
    decrypted_tx_count: u64,

    /// not encrypted tx count
    raw_tx_count: u64,

    /// close flag
    closed: bool,
}

impl BlockTransactionPool {
    /// new
    pub fn new() -> Self {
        Self {
            encrypted_pool: HashMap::default(),
            decryption_keys: HashMap::default(),

            order: 0,
            decrypted_tx_count: 0,
            raw_tx_count: 0,

            closed: false,
        }
    }

    /// add encrypted tx on Txs
    pub fn add_encrypted_invoke_tx(&mut self, encrypted_invoke_transaction: EncryptedInvokeTransaction) -> u64 {
        let order = self.order;

        self.encrypted_pool.insert(self.order, encrypted_invoke_transaction);
        self.order += 1;

        order
    }

    /// get encrypted tx for order
    pub fn get_encrypted_invoke_tx(&self, order: u64) -> Result<&EncryptedInvokeTransaction> {
        self.encrypted_pool.get(&order).ok_or(Error::Retrieval(format!("Failed to get tx - order: {}", order)))
    }

    /// increase not encrypted count
    pub fn increase_raw_tx_count(&mut self) -> u64 {
        self.raw_tx_count += 1;
        self.order += 1;
        self.raw_tx_count
    }

    /// encrypted txs len
    pub fn encrypted_txs_len(&self) -> usize {
        self.encrypted_pool.values().len()
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
        self.encrypted_pool.len() as u64 + self.raw_tx_count
    }

    /// increase decrypted tx count
    pub fn increase_decrypted_tx_count(&mut self) {
        self.decrypted_tx_count += 1;
    }

    /// get decrypted tx count
    pub fn get_decrypted_tx_count(&self) -> u64 {
        self.decrypted_tx_count + self.raw_tx_count
    }

    /// update key received information
    pub fn update_decryption_keys(&mut self, order: u64) {
        self.decryption_keys.insert(order, true);
    }

    /// get key received information
    pub fn is_key_received(&self, order: u64) -> bool {
        self.decryption_keys.contains_key(&order)
    }
}

/// encrypted_pool
#[derive(Debug, Clone, Default)]
/// EncryptedPool struct
/// 1 encrypted_pool for node
/// * `txs`: Map of Txs, key:value = block_height:Txs
/// * `enabled`: encrypted_pool enabler. if whole part is splitted by package. it have to be
///   removed.
pub struct EncryptedPool {
    /// Map of Txs, key:value = block_height:Txs
    block_transaction_pools: HashMap<u64, BlockTransactionPool>,

    /// encrypted_pool enabler. if whole part is splitted by package. it have to be removed.
    enabled: bool,

    /// using external decryptor
    using_external_decryptor: bool,
}

impl EncryptedPool {
    /// check encrypted_pool is enabled
    pub fn is_using_encrypted_pool(&self) -> bool {
        self.enabled
    }

    /// check encrypted_pool is using external decryptor
    pub fn is_using_external_decryptor(&self) -> bool {
        self.using_external_decryptor
    }

    /// new encrypted_pool
    pub fn new(is_enabled_encrypted_mempool: bool, using_external_decryptor: bool) -> Self {
        Self {
            block_transaction_pools: HashMap::default(),
            enabled: is_enabled_encrypted_mempool,
            using_external_decryptor,
        }
    }

    /// add new Txs for block_height
    pub fn new_block(&mut self, block_height: u64) {
        log::info!("insert new tx on {}.", block_height);

        self.block_transaction_pools.insert(block_height, BlockTransactionPool::new());
    }

    /// txs exist
    pub fn exist(&self, block_height: u64) -> bool {
        self.block_transaction_pools.contains_key(&block_height)
    }

    /// get txs
    pub fn get_txs(&self, block_height: u64) -> Result<&BlockTransactionPool> {
        self.block_transaction_pools
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
            .block_transaction_pools
            .get_mut(&block_height)
            .ok_or(Error::Retrieval(format!("Failed to find block height: {}", block_height)))?;

        if !block_transaction_pool.encrypted_pool.is_empty() {
            let txs_string =
                serde_json::to_string(&block_transaction_pool.encrypted_pool.values().cloned().collect::<Vec<_>>())?;
            let db = SYNC_DB
                .get()
                .ok_or(Error::SyncBlock("Failed to get sync db".to_string()))?
                .as_ref()
                .map_err(|e| Error::SyncBlock(format!("Failed to get sync db: {e:?}")))?;
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
    pub fn get_or_init_block_tx_pool(&mut self, block_height: u64) -> &mut BlockTransactionPool {
        log::info!("insert new tx on {}, if not exist.", block_height);
        self.block_transaction_pools.entry(block_height).or_default()
    }

    /// Get block transaction pool
    pub fn get_block_tx_pool(&self, block_height: &u64) -> Option<&BlockTransactionPool> {
        self.block_transaction_pools.get(block_height)
    }

    /// Get mut block transaction pool
    pub fn get_mut_block_tx_pool(&mut self, block_height: &u64) -> Option<&mut BlockTransactionPool> {
        self.block_transaction_pools.get_mut(block_height)
    }
}
