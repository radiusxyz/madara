// This file is part of Encrypted mempool.

use std::sync::atomic::{AtomicUsize, Ordering};

use blockifier::transaction::transactions::InvokeTransaction;
use encryptor::SequencerPoseidonEncryption;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::params::ObjectParams;
use jsonrpsee::ws_client::WsClientBuilder;
use madara_runtime::error_impl::Error as MadaraRuntimeError;
use madara_runtime::subprocess::SubProcess;
use mc_config::config_map;
use mp_transactions::EncryptedInvokeTransaction;
use reqwest::header::{self, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use starknet_api::transaction::TransactionHash;

use crate::error::{Error, Result};
use crate::vdf::Vdf;

/// Decryptor has delay function for calculate decryption key and
/// decrypt function for decryption with poseidon algorithm

static CURRENT_INDEX: AtomicUsize = AtomicUsize::new(0);

/// Decrypted invoke transaction
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptorInvokeTransaction {
    /// Starknet invoke transaction
    pub tx: starknet_api::transaction::InvokeTransaction,
    /// Transaction hash
    pub tx_hash: TransactionHash,
    /// Indicates the presence of the only_query bit in the version.
    pub only_query: bool,
}

impl From<EncryptorInvokeTransaction> for InvokeTransaction {
    fn from(transaction: EncryptorInvokeTransaction) -> Self {
        Self { tx: transaction.tx, tx_hash: transaction.tx_hash, only_query: transaction.only_query }
    }
}

/// `DecryptTx` is a structure that holds the encrypted transaction data and the decryption
/// parameters.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct DecryptEncryptedTransaction {
    /// block heihgt
    pub block_height: u64,
    /// order
    pub order: u64,
    /// Encrypted invoke transaction
    pub encrypted_invoke_transaction: EncryptedInvokeTransaction,
}

impl DecryptEncryptedTransaction {
    /// Create a new `DecryptTx` with the given `EncryptedInvokeTransaction` with order.
    pub fn new(block_height: u64, order: u64, encrypted_invoke_transaction: EncryptedInvokeTransaction) -> Self {
        Self { block_height, order, encrypted_invoke_transaction }
    }
}

impl SubProcess for DecryptEncryptedTransaction {
    fn run(self) -> core::result::Result<(), MadaraRuntimeError> {
        let block_height = self.block_height;
        let order = self.order;
        let decryptor = Decryptor::new(self.encrypted_invoke_transaction);
        let invoke_transaction = decryptor.decrypt_encrypted_invoke_transaction(None).unwrap();

        #[derive(Serialize, Debug)]
        struct RpcParameter {
            jsonrpc: String,
            method: String,
            params: Params,
            id: u64,
        }

        #[derive(Serialize, Debug)]
        struct Params {
            decrypted_tx: DecryptedInvokeTransaction,
        }

        let params = Params { decrypted_tx: DecryptedInvokeTransaction::new(block_height, order, invoke_transaction) };

        let rpc_parameter = RpcParameter {
            jsonrpc: "2.0".to_string(),
            method: "starknet_addDecryptedInvokeTransaction".to_string(),
            params,
            id: 1,
        };

        let client = reqwest::blocking::Client::new();
        client
            .post("http://localhost:9944")
            .header(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .json(&rpc_parameter)
            .send()
            .unwrap()
            .text()
            .unwrap();

        Ok(())
    }
}

/// Decrypted Encrypted Transaction with block height and order
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecryptedInvokeTransaction {
    /// block height
    pub block_height: u64,
    /// order
    pub order: u64,
    /// Invoke transaction
    pub invoke_transaction: EncryptorInvokeTransaction,
}

impl DecryptedInvokeTransaction {
    /// Create a new `DecryptedTx` with the given `InvokeTransaction` with block height and order.
    pub fn new(block_height: u64, order: u64, invoke_transaction: EncryptorInvokeTransaction) -> Self {
        Self { block_height, order, invoke_transaction }
    }
}

/// `Decryptor` is a structure that holds the decryption and delay functions.
/// It is used to decrypt encrypted invoke transactions using the Poseidon algorithm.
/// The decryption process involves a delay function to calculate the decryption key.
/// This structure is also capable of delegating the decryption process to an external decryptor.
#[derive(Clone)]
pub struct Decryptor {
    decrypt_function: SequencerPoseidonEncryption,
    delay_function: Vdf,
    encrypted_invoke_transaction: EncryptedInvokeTransaction,
}

impl Default for Decryptor {
    fn default() -> Self {
        let base = 10; // Expression base (e.g. 10 == decimal / 16 == hex)
        let lambda = 2048; // N's bits (ex. RSA-2048 => lambda = 2048)

        Self {
            decrypt_function: SequencerPoseidonEncryption::new(),
            delay_function: Vdf::new(lambda, base),
            encrypted_invoke_transaction: EncryptedInvokeTransaction::default(),
        }
    }
}

impl Decryptor {
    /// Create a new `Decryptor` with the given `EncryptedInvokeTransaction`.
    pub fn new(encrypted_invoke_transaction: EncryptedInvokeTransaction) -> Self {
        Self {
            decrypt_function: SequencerPoseidonEncryption::new(),
            delay_function: Vdf::new(2048, 10),
            encrypted_invoke_transaction,
        }
    }

    /// Decrypt encrypted invoke transaction
    pub fn decrypt_encrypted_invoke_transaction(
        &self,
        decryption_key: Option<String>,
    ) -> Result<EncryptorInvokeTransaction> {
        let is_key_none = decryption_key.is_none();
        log::debug!(
            "Decrypting encrypted invoke transaction... using internal decryptor, is recieved decryption key? {:?}",
            !is_key_none
        );
        let decryption_key = decryption_key.unwrap_or_else(|| {
            // 2. Use naive
            log::debug!("Decryption key is not provided. Using naive decryption key");
            self.delay_function.evaluate(
                self.encrypted_invoke_transaction.t,
                self.encrypted_invoke_transaction.g.clone(),
                self.encrypted_invoke_transaction.n.clone(),
            )
        });

        let symmetric_key = SequencerPoseidonEncryption::calculate_secret_key(decryption_key.as_bytes());

        let decrypted_invoke_tx = self.decrypt_function.decrypt(
            self.encrypted_invoke_transaction.encrypted_data.clone(),
            &symmetric_key,
            self.encrypted_invoke_transaction.nonce.clone(),
        );
        let decrypted_invoke_tx_string =
            String::from_utf8(decrypted_invoke_tx).map_err(|e| Error::RuntimeApi(e.to_string()))?;
        let trimmed_decrypted_invoke_tx_str = decrypted_invoke_tx_string.trim_end_matches('\0');

        serde_json::from_str::<EncryptorInvokeTransaction>(trimmed_decrypted_invoke_tx_str)
            .map_err(Error::Serialization)
    }

    /// Delegate to decrypt encrypted invoke transaction
    pub async fn delegate_to_decrypt_encrypted_invoke_transaction(self) -> Result<EncryptorInvokeTransaction> {
        let index = CURRENT_INDEX.load(Ordering::SeqCst);

        let config_map = config_map();
        let external_decryptor_hosts =
            config_map.get_array("external_decryptor_hosts").map_err(Error::Configuration)?;

        let external_decryptor_host = external_decryptor_hosts
            .get(index)
            .ok_or({
                log::error!("No external decryptor [{}] host found", index);
                Error::Retrieval(format!("Retrieving external decryptor host failed. index: {index}"))
            })?
            .to_string();

        log::debug!(
            "Decrypting encrypted invoke transaction... using external decryptor - host: {}",
            external_decryptor_host
        );

        CURRENT_INDEX.fetch_add(1, Ordering::SeqCst);
        if CURRENT_INDEX.load(Ordering::SeqCst) == external_decryptor_hosts.len() {
            CURRENT_INDEX.store(0, Ordering::SeqCst);
        }

        let url = format!("ws://{}", external_decryptor_host);
        let client = WsClientBuilder::default().build(&url).await.map_err(|e| Error::RuntimeApi(e.to_string()))?;

        let encrypted_invoke_transaction_json = json!(self.encrypted_invoke_transaction);

        let mut params = ObjectParams::new();
        encrypted_invoke_transaction_json
            .as_object()
            .map(|obj| obj.iter().try_for_each(|(key, value)| params.insert(key, value)))
            .transpose()?;

        let response: String =
            client.request("decrypt_transaction", params).await.map_err(|e| Error::RuntimeApi(e.to_string()))?;

        serde_json::from_str::<EncryptorInvokeTransaction>(response.as_str()).map_err(Error::Serialization)
    }
}
