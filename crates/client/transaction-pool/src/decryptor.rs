// This file is part of Encrypted mempool.

use std::sync::atomic::{AtomicUsize, Ordering};

use encryptor::SequencerPoseidonEncryption;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::params::ObjectParams;
use jsonrpsee::ws_client::WsClientBuilder;
use mc_config::config_map;
use mp_crypto::vdf::Vdf;
use mp_transactions::{EncryptedInvokeTransaction, InvokeTransaction};
use serde_json::json;

use crate::error::{Error, Result};

/// Decryptor has delay function for calculate decryption key and
/// decrypt function for decryption with poseidon algorithm

static CURRENT_INDEX: AtomicUsize = AtomicUsize::new(0);

/// `Decryptor` is a structure that holds the decryption and delay functions.
/// It is used to decrypt encrypted invoke transactions using the Poseidon algorithm.
/// The decryption process involves a delay function to calculate the decryption key.
/// This structure is also capable of delegating the decryption process to an external decryptor.
#[derive(Clone)]
pub struct Decryptor {
    decrypt_function: SequencerPoseidonEncryption,
    delay_function: Vdf,
}

impl Default for Decryptor {
    fn default() -> Self {
        let base = 10; // Expression base (e.g. 10 == decimal / 16 == hex)
        let lambda = 2048; // N's bits (ex. RSA-2048 => lambda = 2048)

        Self { decrypt_function: SequencerPoseidonEncryption::new(), delay_function: Vdf::new(lambda, base) }
    }
}

impl Decryptor {
    /// Decrypt encrypted invoke transaction
    pub async fn decrypt_encrypted_invoke_transaction(
        &self,
        encrypted_invoke_transaction: EncryptedInvokeTransaction,
        decryption_key: Option<String>,
    ) -> Result<InvokeTransaction> {
        log::info!("Decrypting encrypted invoke transaction... using internal decryptor");
        let decryption_key = decryption_key.unwrap_or_else(|| {
            // 2. Use naive
            self.delay_function.evaluate(
                encrypted_invoke_transaction.t,
                encrypted_invoke_transaction.g.clone(),
                encrypted_invoke_transaction.n.clone(),
            )
        });

        let symmetric_key = SequencerPoseidonEncryption::calculate_secret_key(decryption_key.as_bytes());

        let decrypted_invoke_tx = self.decrypt_function.decrypt(
            encrypted_invoke_transaction.encrypted_data.clone(),
            &symmetric_key,
            encrypted_invoke_transaction.nonce,
        );
        let decrypted_invoke_tx =
            String::from_utf8(decrypted_invoke_tx).map_err(|e| Error::RuntimeApi(e.to_string()))?;
        let trimmed_decrypted_invoke_tx = decrypted_invoke_tx.trim_end_matches('\0');

        serde_json::from_str(trimmed_decrypted_invoke_tx).map_err(Error::Serialization)
    }

    /// Delegate to decrypt encrypted invoke transaction
    pub async fn delegate_to_decrypt_encrypted_invoke_transaction(
        self,
        encrypted_invoke_transaction: EncryptedInvokeTransaction,
    ) -> Result<InvokeTransaction> {
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

        log::info!(
            "Decrypting encrypted invoke transaction... using external decryptor - host: {}",
            external_decryptor_host
        );

        CURRENT_INDEX.fetch_add(1, Ordering::SeqCst);
        if CURRENT_INDEX.load(Ordering::SeqCst) == external_decryptor_hosts.len() {
            CURRENT_INDEX.store(0, Ordering::SeqCst);
        }

        let url = format!("ws://{}", external_decryptor_host);
        let client = WsClientBuilder::default().build(&url).await.map_err(|e| Error::RuntimeApi(e.to_string()))?;

        let encrypted_invoke_transaction_json = json!(encrypted_invoke_transaction);

        let mut params = ObjectParams::new();
        encrypted_invoke_transaction_json
            .as_object()
            .map(|obj| obj.iter().try_for_each(|(key, value)| params.insert(key, value)))
            .transpose()?;

        let response: String =
            client.request("decrypt_transaction", params).await.map_err(|e| Error::RuntimeApi(e.to_string()))?;

        serde_json::from_str(response.as_str()).map_err(Error::Serialization)
    }
}
