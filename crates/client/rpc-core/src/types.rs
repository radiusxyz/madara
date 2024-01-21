use mp_felt::Felt252Wrapper;
use mp_transactions::EncryptedInvokeTransaction;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sp_core::ConstU32;
use sp_runtime::BoundedVec;
use starknet_core::serde::unsigned_field_element::UfeHex;
use starknet_core::types::FieldElement;

pub type MaxArraySize = ConstU32<100>;

#[derive(Debug, Serialize)]
pub struct EncryptedMempoolTransactionResult {
    pub block_number: u64,
    pub order: u64,
    pub signature: BoundedVec<Felt252Wrapper, MaxArraySize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptionInfo {
    pub block_number: u64,
    pub order: u64,
    pub signature: BoundedVec<Felt252Wrapper, MaxArraySize>,
    pub decryption_key: String,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvideDecryptionKeyResult {
    /// The hash of the invoke transaction
    #[serde_as(as = "UfeHex")]
    pub transaction_hash: FieldElement,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedInvokeTransactionResult {
    pub decryption_key: String,
    pub encrypted_invoke_transaction: EncryptedInvokeTransaction,
}
