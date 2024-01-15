//! Substrate transaction pool implementation.
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

use std::collections::HashMap;

use mc_sync_block::SYNC_DB;
use mp_starknet::transaction::types::{EncryptedInvokeTransaction, Transaction};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
/// Txs struct
/// 1 Txs for 1 block
/// * `encrypted_pool`: Map store encrypted tx
/// * `key_received`: Map store specific order's key receivement.
/// * `decrypted_cnt`: decrypted tx count
/// * `order`: current order
pub struct Txs {
    /// store encrypted tx
    encrypted_pool: HashMap<u64, EncryptedInvokeTransaction>,
    /// store temporary encrypted tx
    temporary_pool: Vec<(u64, Transaction)>,
    /// store specific order's key receivement.
    received_keys: HashMap<u64, bool>,
    /// decrypted tx count
    decrypted_cnt: u64,
    /// current order
    order: u64,
    /// not encrypted tx count
    not_encrypted_cnt: u64,
    /// close flag
    closed: bool,
}

impl Txs {
    /// new
    pub fn new() -> Self {
        Self {
            encrypted_pool: HashMap::default(),
            temporary_pool: Vec::default(),
            received_keys: HashMap::default(),
            decrypted_cnt: 0,
            order: 0,
            not_encrypted_cnt: 0,
            closed: false,
        }
    }

    /// add encrypted tx on Txs
    pub fn invoke_encrypted_tx(&mut self, encrypted_invoke_transaction: EncryptedInvokeTransaction) -> u64 {
        self.encrypted_pool.insert(self.order, encrypted_invoke_transaction);
        self.received_keys.insert(self.order, false);
        self.increase_order();
        self.order - 1
    }

    /// get encrypted tx for order
    pub fn get_invoked_encrypted_tx(&self, order: u64) -> Result<&EncryptedInvokeTransaction> {
        self.encrypted_pool.get(&order).ok_or(Error::Retrieval(format!("Failed to get tx - order: {}", order)))
    }

    /// increase not encrypted count
    pub fn increase_not_encrypted_cnt(&mut self) -> u64 {
        self.increase_order();
        self.not_encrypted_cnt += 1;
        self.not_encrypted_cnt
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

    /// add tx to temporary pool
    pub fn add_tx_to_temporary_pool(&mut self, order: u64, tx: Transaction) {
        self.temporary_pool.push((order, tx));
    }

    /// get tx from temporary pool
    pub fn get_tx_from_temporary_pool(&mut self, index: usize) -> Result<&(u64, Transaction)> {
        self.temporary_pool
            .get(index)
            .ok_or(Error::Retrieval(format!("Failed to get tx from the temporary pool- index: {}", index)))
    }

    /// get temporary pool
    pub fn get_temporary_pool(&self) -> &[(u64, Transaction)] {
        &self.temporary_pool
    }

    /// increase order
    /// not only for set new encrypted tx
    /// but also for declare tx, deploy account tx
    pub fn increase_order(&mut self) {
        self.order += 1;
    }

    /// order getter
    pub fn get_order(&self) -> u64 {
        self.order
    }

    /// get encrypted tx count
    /// it's not order
    pub fn get_tx_cnt(&self) -> u64 {
        self.encrypted_pool.len() as u64 + self.not_encrypted_cnt
    }

    /// increase decrypted tx count
    pub fn increase_decrypted_cnt(&mut self) {
        self.decrypted_cnt += 1;
    }

    /// get decrypted tx count
    pub fn get_decrypted_cnt(&self) -> u64 {
        self.decrypted_cnt + self.not_encrypted_cnt
    }

    /// update key received information
    pub fn update_received_keys(&mut self, order: u64) {
        self.received_keys.insert(order, true);
    }

    /// get key received information
    pub fn is_key_received(&self, order: u64) -> bool {
        self.received_keys.contains_key(&order)
    }
}

/// epool
#[derive(Debug, Clone, Default)]
/// EncryptedPool struct
/// 1 epool for node
/// * `txs`: Map of Txs, key:value = block_height:Txs
/// * `enabled`: epool enabler. if whole part is splitted by package. it have to be removed.
pub struct EncryptedPool {
    /// Map of Txs, key:value = block_height:Txs
    pub txs: HashMap<u64, Txs>,
    /// epool enabler. if whole part is splitted by package. it have to be removed.
    enabled: bool,

    /// using external decryptor
    using_external_decryptor: bool,
}

impl EncryptedPool {
    /// enable epool
    pub fn enable_encrypted_mempool(&mut self) {
        self.enabled = true;
    }

    /// disable epool
    pub fn disable_encrypted_mempool(&mut self) {
        self.enabled = false;
    }

    /// check epool is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// check epool is using external decryptor
    pub fn is_using_external_decryptor(&self) -> bool {
        self.using_external_decryptor
    }

    /// new epool
    pub fn new(is_enabled_encrypted_mempool: bool, using_external_decryptor: bool) -> Self {
        Self { txs: HashMap::default(), enabled: is_enabled_encrypted_mempool, using_external_decryptor }
    }

    /// add new Txs for block_height
    pub fn new_block(&mut self, block_height: u64) -> &mut Txs {
        log::info!("insert new tx on {}, if not exist.", block_height);
        self.txs.entry(block_height).or_insert_with(Txs::new)
    }

    /// txs exist
    pub fn exist(&self, block_height: u64) -> bool {
        self.txs.contains_key(&block_height)
    }

    /// get txs
    pub fn get_txs(&self, block_height: u64) -> Result<&Txs> {
        self.txs
            .get(&block_height)
            .ok_or(Error::Retrieval(format!("Failed to get txs - block height: {}", block_height)))
    }

    /// close
    pub fn close(&mut self, block_height: u64) -> Result<bool> {
        let txs = self
            .txs
            .get_mut(&block_height)
            .ok_or(Error::Retrieval(format!("Failed to find block height: {}", block_height)))?;
        if !txs.encrypted_pool.is_empty() {
            let txs_string = serde_json::to_string(&txs.encrypted_pool.values().cloned().collect::<Vec<_>>())?;
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

        txs.close();

        Ok(true)
    }

    ///
    pub fn initialize_if_not_exist(&mut self, block_height: u64) -> &mut Txs {
        self.new_block(block_height)
    }
}

#[cfg(test)]
mod tests {
    use super::{EncryptedPool, Txs};

    #[test]
    fn first_test() {
        let _epool = EncryptedPool::default();

        // assert_eq!(ready.get().count(), 1);
    }

    ///////////////
    // Txs test
    ///////////////
    #[test]
    fn new_() {
        let txs = Txs::new();
        println!("{:?}", txs);
    }

    // /// add encrypted tx on Txs
    // pub fn set(&mut self, encrypted_invoke_transaction: EncryptedInvokeTransaction) -> u64;

    // /// get encrypted tx for order
    // pub fn get(&self, order: u64) -> Result<EncryptedInvokeTransaction, &str>;

    // /// increase not encrypted count
    // pub fn increase_not_encrypted_cnt(&mut self) -> u64;

    // /// len
    // pub fn len(&self) -> usize;

    // /// is close
    // pub fn is_closed(&self) -> bool;

    // /// close
    // pub fn close(&mut self) -> bool;

    // /// add tx to temporary pool
    // pub fn add_tx_to_temporary_pool(&mut self, order: u64, tx: Transaction);

    // /// get tx from temporary pool
    // pub fn get_tx_from_temporary_pool(&mut self, index: usize) -> (u64, Transaction);

    // /// get temporary pool length
    // pub fn temporary_pool_len(&mut self) -> usize;

    // /// get temporary pool
    // pub fn get_temporary_pool(&self) -> Vec<(u64, Transaction)>;

    // /// increase order
    // /// not only for set new encrypted tx
    // /// but also for declare tx, deploy account tx
    // pub fn increase_order(&mut self) -> u64;

    // /// order getter
    // pub fn get_order(&self) -> u64;

    // /// get encrypted tx count
    // /// it's not order
    // pub fn get_tx_cnt(&self) -> u64;

    // /// increase decrypted tx count
    // pub fn increase_decrypted_cnt(&mut self) -> u64;

    // /// get decrypted tx count
    // pub fn get_decrypted_cnt(&self) -> u64;

    // /// update key received information
    // pub fn update_key_received(&mut self, order: u64);

    // /// get key received information
    // pub fn get_key_received(&self, order: u64) -> bool;
}
