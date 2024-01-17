use mp_felt::Felt252Wrapper;
use mp_transactions::EncryptedInvokeTransaction;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sp_core::ConstU32;
use sp_runtime::BoundedVec;
use starknet_core::serde::unsigned_field_element::UfeHex;
use starknet_core::types::{BlockId, FieldElement};

pub type MaxArraySize = ConstU32<100>;

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct RpcGetProofInput {
    /// Block to prove
    pub block_id: BlockId,
    /// Address of the contract to prove the storage of
    pub contract_address: FieldElement,
    /// Storage keys to be proven
    /// More info can be found [here](https://docs.starknet.io/documentation/architecture_and_concepts/Contracts/contract-storage/)
    /// storage_var address is the sn_keccak of the name hashed with the pedersen hash of the keys
    ///
    /// e.g balance_of(key1: felt, key2: felt) -> pedersen("balance_of", pedersen("key1",
    /// pedersen("key2")))
    pub keys: Vec<FieldElement>,
}

#[derive(Debug, Serialize)]
pub struct EncryptedMempoolTransactionResponse {
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
pub struct ProvideDecryptionKeyResponse {
    /// The hash of the invoke transaction
    #[serde_as(as = "UfeHex")]
    pub transaction_hash: FieldElement,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedInvokeTransactionResponse {
    pub decryption_key: String,

    pub encrypted_invoke_transaction: EncryptedInvokeTransaction,
}
