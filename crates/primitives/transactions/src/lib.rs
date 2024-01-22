//! Starknet transaction related functionality.
#![cfg_attr(not(feature = "std"), no_std)]

#[doc(hidden)]
pub extern crate alloc;

pub mod compute_hash;
pub mod conversions;
pub mod execution;
#[cfg(feature = "client")]
pub mod from_broadcasted_transactions;
pub mod getters;
#[cfg(feature = "client")]
pub mod to_starknet_core_transaction;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use avail_subxt::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use blockifier::block_context::BlockContext;
use blockifier::execution::contract_class::ContractClass;
use blockifier::execution::entry_point::{
    CallEntryPoint, CallInfo, CallType, EntryPointExecutionContext, ExecutionResources,
};
use blockifier::execution::errors::EntryPointExecutionError;
use blockifier::state::state_api::State;
use blockifier::transaction::objects::AccountTransactionContext;
use blockifier::transaction::transaction_types::TransactionType;
use cairo_vm::felt::Felt252;
use derive_more::From;
use mp_hashers::pedersen::PedersenHasher;
use mp_hashers::HasherT;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use serde::{Deserialize, Serialize};
use sp_core::U256;
use starknet_api::api_core::{ClassHash, ContractAddress, EntryPointSelector};
use starknet_api::deprecated_contract_class::{EntryPoint, EntryPointOffset, EntryPointType};
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{Calldata, Fee};
use starknet_api::StarknetApiError;
use starknet_core::types::{TransactionExecutionStatus, TransactionFinalityStatus};
use starknet_ff::FieldElement;

const SIMULATE_TX_VERSION_OFFSET: FieldElement =
    FieldElement::from_mont([18446744073700081665, 17407, 18446744073709551584, 576460752142434320]);

/// Functions related to transaction conversions
// pub mod utils;
use mp_felt::Felt252Wrapper;
use thiserror::Error;

// TODO(antiyro): remove this when released: https://github.com/xJonathanLEI/starknet-rs/blame/fec81d126c58ff3dff6cbfd4b9e714913298e54e/starknet-core/src/types/serde_impls.rs#L175
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransactionStatus {
    pub finality_status: TransactionFinalityStatus,
    pub execution_status: TransactionExecutionStatus,
}

/// Wrapper type for transaction execution error.
/// Different tx types.
/// See `https://docs.starknet.io/documentation/architecture_and_concepts/Blocks/transactions/` for more details.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub enum TxType {
    /// Regular invoke transaction.
    Invoke,
    /// Declare transaction.
    Declare,
    /// Deploy account transaction.
    DeployAccount,
    /// Message sent from ethereum.
    L1Handler,
}

impl From<TxType> for TransactionType {
    fn from(value: TxType) -> Self {
        match value {
            TxType::Invoke => TransactionType::InvokeFunction,
            TxType::Declare => TransactionType::Declare,
            TxType::DeployAccount => TransactionType::DeployAccount,
            TxType::L1Handler => TransactionType::L1Handler,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub enum UserTransaction {
    Declare(DeclareTransaction, ContractClass),
    DeployAccount(DeployAccountTransaction),
    Invoke(InvokeTransaction),
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub enum Transaction {
    Declare(DeclareTransaction),
    DeployAccount(DeployAccountTransaction),
    Invoke(InvokeTransaction),
    L1Handler(HandleL1MessageTransaction),
}

/// A trait for querying a single value from a type defined in the trait.
///
/// It is not required that the value is constant.
pub trait TypedGet {
    /// The type which is returned.
    type Type;
    /// Return the current value.
    fn get() -> Self::Type;
}

/// A trait for querying a single value from a type.
///
/// It is not required that the value is constant.
pub trait Get<T> {
    /// Return the current value.
    fn get() -> T;
}

pub struct GetDefault;
impl<T: Default> Get<T> for GetDefault {
    fn get() -> T {
        T::default()
    }
}

macro_rules! impl_const_get {
    ($name:ident, $t:ty) => {
        /// Const getter for a basic type.
        #[derive(Default, Clone)]
        pub struct $name<const T: $t>;

        #[cfg(feature = "std")]
        impl<const T: $t> core::fmt::Debug for $name<T> {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                fmt.write_str(&format!("{}<{}>", stringify!($name), T))
            }
        }
        #[cfg(not(feature = "std"))]
        impl<const T: $t> core::fmt::Debug for $name<T> {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                fmt.write_str("<wasm:stripped>")
            }
        }
        impl<const T: $t> Get<$t> for $name<T> {
            fn get() -> $t {
                T
            }
        }
        impl<const T: $t> Get<Option<$t>> for $name<T> {
            fn get() -> Option<$t> {
                Some(T)
            }
        }
        impl<const T: $t> TypedGet for $name<T> {
            type Type = $t;
            fn get() -> $t {
                T
            }
        }
    };
}

impl_const_get!(ConstU32, u32);

pub type MaxArraySize = ConstU32<10000>;
/// Max number of calldata / tx.

pub type MaxCalldataSize = ConstU32<{ u32::MAX }>;

/// Representation of a Starknet transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize))]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct OldTransaction {
    /// The type of the transaction.
    pub tx_type: TxType,
    /// The version of the transaction.
    pub version: u8,
    /// Transaction hash.
    pub hash: Felt252Wrapper,
    /// Signature.
    pub signature: BoundedVec<Felt252Wrapper>,
    /// Sender Address
    pub sender_address: Felt252Wrapper,
    /// Nonce
    pub nonce: Felt252Wrapper,
    /// Call entrypoint
    pub call_entrypoint: CallEntryPointWrapper,
    /// Contract Class
    pub contract_class: Option<ContractClass>,
    /// Contract Address Salt
    pub contract_address_salt: Option<U256>,
    /// Max fee.
    pub max_fee: Felt252Wrapper,
    /// If set to `true`, uses a query-only transaction version that's invalid for execution
    pub is_query: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub enum UserAndL1HandlerTransaction {
    User(UserTransaction),
    L1Handler(HandleL1MessageTransaction, Fee),
}

#[derive(Debug, Clone, Eq, PartialEq, From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub enum InvokeTransaction {
    V0(InvokeTransactionV0),
    V1(InvokeTransactionV1),
}

/// Invoke transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct OldInvokeTransaction {
    /// Transaction version.
    pub version: u8,
    /// Transaction sender address.
    pub sender_address: Felt252Wrapper,
    /// Transaction calldata.
    pub calldata: BoundedVec<Felt252Wrapper>,
    /// Account contract nonce.
    pub nonce: Felt252Wrapper,
    /// Transaction signature.
    pub signature: BoundedVec<Felt252Wrapper>,
    /// Max fee.
    pub max_fee: Felt252Wrapper,
    /// If set to `true`, uses a query-only transaction version that's invalid for execution
    pub is_query: bool,
}

impl From<OldTransaction> for OldInvokeTransaction {
    fn from(value: OldTransaction) -> Self {
        Self {
            version: value.version,
            signature: value.signature,
            sender_address: value.sender_address,
            nonce: value.nonce,
            calldata: value.call_entrypoint.calldata,
            max_fee: value.max_fee,
            is_query: value.is_query,
        }
    }
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct TransactionVersion(pub StarkFelt);

/// Computes the transaction hash using a hash function of type T
#[allow(clippy::too_many_arguments)]
pub fn calculate_transaction_hash_common<T>(
    sender_address: Felt252Wrapper,
    calldata: &[Felt252Wrapper],
    max_fee: Felt252Wrapper,
    nonce: Felt252Wrapper,
    version: TransactionVersion,
    tx_prefix: &[u8],
    chain_id: Felt252Wrapper,
    compiled_class_hash: Option<Felt252Wrapper>,
) -> Felt252Wrapper
where
    T: HasherT + Default,
{
    // All the values are validated before going through this function so it's safe to unwrap.
    let sender_address = FieldElement::from_bytes_be(&sender_address.into()).unwrap();
    let calldata_hash = T::compute_hash_on_elements(
        &calldata.iter().map(|&val| FieldElement::from(val)).collect::<Vec<FieldElement>>(),
    );
    let max_fee = FieldElement::from_bytes_be(&max_fee.into()).unwrap();
    let nonce = FieldElement::from_bytes_be(&nonce.into()).unwrap();
    let version = FieldElement::from(version.0);
    let tx_prefix = FieldElement::from_byte_slice_be(tx_prefix).unwrap();

    let mut elements =
        vec![tx_prefix, version, sender_address, FieldElement::ZERO, calldata_hash, max_fee, chain_id.0, nonce];
    if let Some(compiled_class_hash) = compiled_class_hash {
        elements.push(FieldElement::from_bytes_be(&compiled_class_hash.into()).unwrap())
    }

    let tx_hash = T::compute_hash_on_elements(&elements);

    tx_hash.into()
}

const QUERY_VERSION_OFFSET: FieldElement =
    FieldElement::from_mont([18446744073700081665, 17407, 18446744073709551584, 576460752142434320]);

/// Estimate fee adds an additional offset to the transaction version
/// when handling Transaction within Madara, we ignore the offset and use the actual version.
/// However, before sending the transaction to the account, we need to add the offset back for
/// signature verification to work
pub fn calculate_transaction_version(is_query: bool, version: TransactionVersion) -> TransactionVersion {
    if !is_query {
        return version;
    }
    let version = FieldElement::from(version.0) + QUERY_VERSION_OFFSET;
    TransactionVersion(StarkFelt::from(version))
}

/// calls [calculate_transaction_version] after converting version to [TransactionVersion]
pub fn calculate_transaction_version_from_u8(is_query: bool, version: u8) -> TransactionVersion {
    calculate_transaction_version(is_query, TransactionVersion(StarkFelt::from(version)))
}

/// Computes the transaction hash of an invoke transaction.
///
/// # Argument
///
/// * `transaction` - The invoke transaction to get the hash of.
pub fn calculate_invoke_tx_hash(transaction: OldInvokeTransaction, chain_id: Felt252Wrapper) -> Felt252Wrapper {
    calculate_transaction_hash_common::<PedersenHasher>(
        transaction.sender_address,
        transaction.calldata.as_slice(),
        transaction.max_fee,
        transaction.nonce,
        calculate_transaction_version_from_u8(transaction.is_query, transaction.version),
        b"invoke",
        chain_id,
        None,
    )
}

impl OldInvokeTransaction {
    /// converts the transaction to a [Transaction] object
    pub fn from_invoke(self, chain_id: Felt252Wrapper) -> OldTransaction {
        OldTransaction {
            tx_type: TxType::Invoke,
            version: self.version,
            hash: calculate_invoke_tx_hash(self.clone(), chain_id),
            signature: self.signature,
            sender_address: self.sender_address,
            nonce: self.nonce,
            call_entrypoint: CallEntryPointWrapper::new(
                None,
                EntryPointTypeWrapper::External,
                None,
                self.calldata,
                self.sender_address,
                self.sender_address,
                Felt252Wrapper::from(0_u8), // FIXME 710 update this once transaction contains the initial gas
                None,
            ),
            contract_class: None,
            contract_address_salt: None,
            max_fee: self.max_fee,
            is_query: self.is_query,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct InvokeTransactionV0 {
    pub max_fee: u128,
    pub signature: Vec<Felt252Wrapper>,
    pub contract_address: Felt252Wrapper,
    pub entry_point_selector: Felt252Wrapper,
    pub calldata: Vec<Felt252Wrapper>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct InvokeTransactionV1 {
    pub max_fee: u128,
    pub signature: Vec<Felt252Wrapper>,
    pub nonce: Felt252Wrapper,
    pub sender_address: Felt252Wrapper,
    pub calldata: Vec<Felt252Wrapper>,
}

/// Encrypted Invoke transaction.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EncryptedInvokeTransaction {
    /// Encrypted transaction data.
    pub encrypted_data: Vec<String>,
    /// Nonce for decrypting the encrypted transaction.
    pub nonce: String,
    /// t for calculating time-lock puzzle.
    pub t: u64,
    /// g for calculating time-lock puzzle.
    pub g: String,
    /// n for calculating time-lock puzzle.
    pub n: String,
}

#[derive(Debug, Clone, Eq, PartialEq, From)]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub enum DeclareTransaction {
    V0(DeclareTransactionV0),
    V1(DeclareTransactionV1),
    V2(DeclareTransactionV2),
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DeclareTransactionV0 {
    pub max_fee: u128,
    pub signature: Vec<Felt252Wrapper>,
    pub nonce: Felt252Wrapper,
    pub class_hash: Felt252Wrapper,
    pub sender_address: Felt252Wrapper,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DeclareTransactionV1 {
    pub max_fee: u128,
    pub signature: Vec<Felt252Wrapper>,
    pub nonce: Felt252Wrapper,
    pub class_hash: Felt252Wrapper,
    pub sender_address: Felt252Wrapper,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DeclareTransactionV2 {
    pub max_fee: u128,
    pub signature: Vec<Felt252Wrapper>,
    pub nonce: Felt252Wrapper,
    pub class_hash: Felt252Wrapper,
    pub sender_address: Felt252Wrapper,
    pub compiled_class_hash: Felt252Wrapper,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct DeployAccountTransaction {
    pub max_fee: u128,
    pub signature: Vec<Felt252Wrapper>,
    pub nonce: Felt252Wrapper,
    pub contract_address_salt: Felt252Wrapper,
    pub constructor_calldata: Vec<Felt252Wrapper>,
    pub class_hash: Felt252Wrapper,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub struct HandleL1MessageTransaction {
    pub nonce: u64,
    pub contract_address: Felt252Wrapper,
    pub entry_point_selector: Felt252Wrapper,
    pub calldata: Vec<Felt252Wrapper>,
}

pub type EntryPointExecutionResultWrapper<T> = Result<T, EntryPointExecutionErrorWrapper>;

#[derive(Debug, Error)]
pub enum EntryPointExecutionErrorWrapper {
    /// Transaction execution error.
    #[error(transparent)]
    EntryPointExecution(#[from] EntryPointExecutionError),
    /// Starknet API error.
    #[error(transparent)]
    StarknetApi(#[from] StarknetApiError),
    /// Block context serialization error.
    #[error("Block context serialization error")]
    BlockContextSerializationError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct CallEntryPointWrapper {
    /// The class hash
    pub class_hash: Option<Felt252Wrapper>,
    /// The casm class hash used in declare v2
    pub compiled_class_hash: Option<Felt252Wrapper>,
    /// The entrypoint type
    pub entrypoint_type: EntryPointTypeWrapper,
    /// The entrypoint selector
    /// An invoke transaction without an entry point selector invokes the 'execute' function.
    pub entrypoint_selector: Option<Felt252Wrapper>,
    /// The Calldata
    pub calldata: BoundedVec<Felt252Wrapper>,
    /// The storage address
    pub storage_address: Felt252Wrapper,
    /// The caller address
    pub caller_address: Felt252Wrapper,
    /// The initial gas
    pub initial_gas: Felt252Wrapper,
}
// Regular implementation.
impl CallEntryPointWrapper {
    /// Creates a new instance of a call entrypoint.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_hash: Option<Felt252Wrapper>,
        entrypoint_type: EntryPointTypeWrapper,
        entrypoint_selector: Option<Felt252Wrapper>,
        calldata: BoundedVec<Felt252Wrapper>,
        storage_address: Felt252Wrapper,
        caller_address: Felt252Wrapper,
        initial_gas: Felt252Wrapper,
        casm_class_hash: Option<Felt252Wrapper>,
    ) -> Self {
        Self {
            class_hash,
            entrypoint_type,
            entrypoint_selector,
            calldata,
            storage_address,
            caller_address,
            initial_gas,
            compiled_class_hash: casm_class_hash,
        }
    }

    /// Executes an entry point.
    ///
    /// # Arguments
    ///
    /// * `self` - The entry point to execute.
    /// * `state` - The state to execute the entry point on.
    /// * `block` - The block to execute the entry point on.
    /// * `fee_token_address` - The fee token address.
    ///
    /// # Returns
    ///
    /// * The result of the entry point execution.
    pub fn execute<S: State>(
        &self,
        state: &mut S,
        block_context: BlockContext,
    ) -> EntryPointExecutionResultWrapper<CallInfo> {
        let call_entry_point: CallEntryPoint =
            self.clone().try_into().map_err(EntryPointExecutionErrorWrapper::StarknetApi)?;

        let execution_resources = &mut ExecutionResources::default();
        let account_context = AccountTransactionContext::default();
        let max_steps = block_context.invoke_tx_max_n_steps;
        let context = &mut EntryPointExecutionContext::new(block_context, account_context, max_steps);

        call_entry_point
            .execute(state, execution_resources, context)
            .map_err(EntryPointExecutionErrorWrapper::EntryPointExecution)
    }
}

// Traits implementation.
impl Default for CallEntryPointWrapper {
    fn default() -> Self {
        Self {
            class_hash: None,
            entrypoint_type: EntryPointTypeWrapper::External,
            entrypoint_selector: Some(Felt252Wrapper::default()),
            calldata: BoundedVec::default(),
            storage_address: Felt252Wrapper::default(),
            caller_address: Felt252Wrapper::default(),
            initial_gas: Felt252Wrapper::default(),
            compiled_class_hash: None,
        }
    }
}

impl TryInto<CallEntryPoint> for CallEntryPointWrapper {
    type Error = StarknetApiError;

    fn try_into(self) -> Result<CallEntryPoint, Self::Error> {
        let class_hash = if let Some(class_hash) = self.class_hash {
            Some(ClassHash(StarkFelt::new(class_hash.into())?))
        } else {
            None
        };

        let entrypoint = CallEntryPoint {
            class_hash,
            entry_point_type: self.entrypoint_type.clone().into(),
            entry_point_selector: EntryPointSelector(StarkFelt::new(
                self.entrypoint_selector.unwrap_or_default().into(),
            )?),
            calldata: Calldata(Arc::new(
                self.calldata
                    .clone()
                    .into_inner()
                    .iter()
                    .map(|x| StarkFelt::try_from(format!("0x{:X}", x.0).as_str()).unwrap())
                    .collect(),
            )),
            storage_address: ContractAddress::try_from(StarkFelt::new(self.storage_address.into())?)?,
            caller_address: ContractAddress::try_from(StarkFelt::new(self.caller_address.into())?)?,
            call_type: CallType::Call,
            // I have no idea what I'm doing
            // starknet-lib is constantly breaking it's api
            // I hope it's nothing important ¯\_(ツ)_/¯
            code_address: None,
            initial_gas: Felt252::from_bytes_be(&self.initial_gas.0.to_bytes_be()),
        };

        Ok(entrypoint)
    }
}

/// Enum that represents all the entrypoints types.
#[derive(Clone, Debug, PartialEq, Eq, Default, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "parity-scale-codec", derive(parity_scale_codec::Encode, parity_scale_codec::Decode))]
#[cfg_attr(feature = "scale-info", derive(scale_info::TypeInfo))]
pub enum EntryPointTypeWrapper {
    /// A constructor entry point.
    #[serde(rename = "CONSTRUCTOR")]
    Constructor,
    /// An external entry point.
    #[serde(rename = "EXTERNAL")]
    #[default]
    External,
    /// An L1 handler entry point.
    #[serde(rename = "L1_HANDLER")]
    L1Handler,
}

// Traits implementation.
impl From<EntryPointType> for EntryPointTypeWrapper {
    fn from(entry_point_type: EntryPointType) -> Self {
        match entry_point_type {
            EntryPointType::Constructor => EntryPointTypeWrapper::Constructor,
            EntryPointType::External => EntryPointTypeWrapper::External,
            EntryPointType::L1Handler => EntryPointTypeWrapper::L1Handler,
        }
    }
}

impl From<EntryPointTypeWrapper> for EntryPointType {
    fn from(entrypoint: EntryPointTypeWrapper) -> Self {
        match entrypoint {
            EntryPointTypeWrapper::Constructor => EntryPointType::Constructor,
            EntryPointTypeWrapper::External => EntryPointType::External,
            EntryPointTypeWrapper::L1Handler => EntryPointType::L1Handler,
        }
    }
}

/// Representation of a Starknet Entry Point.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntryPointWrapper(EntryPoint);
/// SCALE trait.
impl Encode for EntryPointWrapper {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&self.0.selector.0.0);
        dest.write(&self.0.offset.0.to_be_bytes());
    }
}
/// SCALE trait.
impl Decode for EntryPointWrapper {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let mut selector = [0u8; 32];
        // Use this because usize can be of different byte size.
        let mut offset = [0u8; core::mem::size_of::<usize>()];
        input.read(&mut selector)?;
        input.read(&mut offset)?;

        Ok(EntryPointWrapper(EntryPoint {
            selector: EntryPointSelector(StarkFelt(selector)),
            offset: EntryPointOffset(usize::from_be_bytes(offset)),
        }))
    }
}

// Traits implementation.

impl From<EntryPoint> for EntryPointWrapper {
    fn from(entry_point: EntryPoint) -> Self {
        Self(entry_point)
    }
}

impl From<EntryPointWrapper> for EntryPoint {
    fn from(entry_point: EntryPointWrapper) -> Self {
        entry_point.0
    }
}
