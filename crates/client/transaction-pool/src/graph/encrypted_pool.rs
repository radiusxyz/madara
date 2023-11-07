//! Substrate transaction pool implementation.
#![warn(missing_docs)]
#![warn(unused_extern_crates)]

use std::collections::HashMap;

use mc_sync_block::SYNC_DB;
use mp_transactions::{EncryptedInvokeTransaction, UserTransaction};

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
    temporary_pool: Vec<(u64, UserTransaction)>,
    /// store specific order's key receivement.
    key_received: HashMap<u64, bool>,
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
            key_received: HashMap::default(),
            decrypted_cnt: 0,
            order: 0,
            not_encrypted_cnt: 0,
            closed: false,
        }
    }

    /// add encrypted tx on Txs
    pub fn set(&mut self, encrypted_invoke_transaction: EncryptedInvokeTransaction) -> u64 {
        self.encrypted_pool.insert(self.order, encrypted_invoke_transaction);
        self.key_received.insert(self.order, false);
        self.increase_order();
        self.order - 1
    }

    /// get encrypted tx for order
    pub fn get(&self, order: u64) -> Result<EncryptedInvokeTransaction, &str> {
        match self.encrypted_pool.get(&order) {
            Some(item) => Ok(item.clone()),
            None => Err("get not exist tx from vector"),
        }
    }

    /// increase not encrypted count
    pub fn increase_not_encrypted_cnt(&mut self) -> u64 {
        self.not_encrypted_cnt = self.not_encrypted_cnt + 1;
        // println!("{}", self.not_encrypted_cnt);
        self.increase_order();
        self.not_encrypted_cnt
    }

    /// len
    pub fn len(&self) -> usize {
        self.encrypted_pool.values().collect::<Vec<_>>().len()
    }

    /// is close
    pub fn is_closed(&self) -> bool {
        // println!("is closed {}", self.closed);
        self.closed
    }

    /// close
    pub fn close(&mut self) -> bool {
        self.closed = true;
        self.closed
    }

    /// add tx to temporary pool
    pub fn add_tx_to_temporary_pool(&mut self, order: u64, tx: UserTransaction) {
        self.temporary_pool.push((order, tx));
    }

    /// get tx from temporary pool
    pub fn get_tx_from_temporary_pool(&mut self, index: usize) -> (u64, UserTransaction) {
        match self.temporary_pool.get(index) {
            Some(tx) => tx.clone(),
            None => panic!("aaaaaaak"),
        }
    }

    /// get temporary pool length
    pub fn temporary_pool_len(&mut self) -> usize {
        self.temporary_pool.len()
    }

    /// get temporary pool
    pub fn get_temporary_pool(&self) -> Vec<(u64, UserTransaction)> {
        self.temporary_pool.clone()
    }

    /// increase order
    /// not only for set new encrypted tx
    /// but also for declare tx, deploy account tx
    pub fn increase_order(&mut self) -> u64 {
        self.order = self.order + 1;
        self.order
    }

    /// order getter
    pub fn get_order(&self) -> u64 {
        self.order
    }

    /// get encrypted tx count
    /// it's not order
    pub fn get_tx_cnt(&self) -> u64 {
        // println!("{}, {}", self.encrypted_pool.len() as u64, self.not_encrypted_cnt);
        let tmp = self.encrypted_pool.len() as u64 + self.not_encrypted_cnt;
        tmp
    }

    /// increase decrypted tx count
    pub fn increase_decrypted_cnt(&mut self) -> u64 {
        self.decrypted_cnt = self.decrypted_cnt + 1;
        self.decrypted_cnt
    }

    /// get decrypted tx count
    pub fn get_decrypted_cnt(&self) -> u64 {
        // println!("{}, {}", self.decrypted_cnt as u64, self.not_encrypted_cnt);
        self.decrypted_cnt + self.not_encrypted_cnt
    }

    /// update key received information
    pub fn update_key_received(&mut self, order: u64) {
        self.key_received.insert(order, true);
    }

    /// get key received information
    pub fn get_key_received(&self, order: u64) -> bool {
        match self.key_received.get(&order) {
            Some(received) => received.clone(),
            None => false,
        }
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

    /// check epool is disabled
    pub fn is_disabled(&self) -> bool {
        !self.enabled
    }

    /// check epool is using external decryptor
    pub fn is_using_external_decryptor(&self) -> bool {
        self.using_external_decryptor
    }

    /// new epool
    pub fn new(encrypted_mempool: bool, using_external_decryptor: bool) -> Self {
        Self { txs: HashMap::default(), enabled: encrypted_mempool, using_external_decryptor }
    }

    /// add new Txs for block_height
    pub fn new_block(&mut self, block_height: u64) -> Txs {
        println!("insert on {}", block_height);
        self.txs.insert(block_height, Txs::new());
        self.txs.get(&block_height).unwrap().clone()
    }

    /// txs exist
    pub fn exist(&self, block_height: u64) -> bool {
        match self.txs.get(&block_height) {
            Some(_) => true,
            None => false,
        }
    }

    /// get txs
    pub fn get_txs(&self, block_height: u64) -> Result<Txs, &str> {
        match self.txs.get(&block_height) {
            Some(txs) => Ok(txs.clone()),
            None => Err("get not exist tx from map"),
        }
    }

    /// close
    pub fn close(&mut self, block_height: u64) -> Result<bool, &str> {
        match self.txs.get_mut(&block_height) {
            Some(txs) => {
                let raw_txs: Vec<_> = txs.encrypted_pool.values().cloned().collect();
                println!("raw_txs: {:?}", raw_txs);
                if raw_txs.len() != 0 {
                    let txs_string = serde_json::to_string(&raw_txs).expect("serde_json failed to serialize txs");
                    SYNC_DB.write("sync_target".to_string(), block_height.to_string());
                    SYNC_DB.write(block_height.to_string(), txs_string);
                }
                txs.close();
                Ok(true)
            }
            None => Err("not exist? cannot close"),
        }
    }

    ///
    pub fn initialize_if_not_exist(&mut self, block_height: u64) {
        match self.txs.get(&block_height) {
            Some(_) => {
                println!("txs exist {}", block_height);
            }
            None => {
                self.new_block(block_height);
                println!("txs not exist create new one for {}", block_height);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EncryptedPool, Txs};

    #[test]
    fn first_test() {
        let mut epool = EncryptedPool::default();

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
