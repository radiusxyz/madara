use core::str::FromStr;

use log::error;
use mc_config::config_map;
use mc_rpc_core::types::MaxArraySize;
pub use mc_rpc_core::utils::*;
pub use mc_rpc_core::{Felt, StarknetReadRpcApiServer, StarknetWriteRpcApiServer};
use mp_felt::Felt252Wrapper;
use mp_hashers::pedersen::PedersenHasher;
use mp_hashers::HasherT;
use num_bigint::{BigInt, RandBigInt};
use rand::rngs::OsRng;
use sp_runtime::BoundedVec;
use starknet_core::types::FieldElement;
use starknet_crypto::{get_public_key, sign, verify};

use crate::StarknetRpcApiError;

pub fn sign_message(message: String) -> Result<BoundedVec<Felt252Wrapper, MaxArraySize>, StarknetRpcApiError> {
    // Generate commitment
    // 1. Get sequencer private key
    let config_map = config_map();
    let sequencer_private_key = config_map.get_string("sequencer_private_key").map_err(|_| {
        error!("sequencer_private_key must be set");
        StarknetRpcApiError::InternalServerError
    })?;

    // 2. Make random FieldElement for making k to sign
    let mut rng = OsRng;
    let lower_bound = BigInt::from(0);
    let upper_bound = BigInt::parse_bytes(FieldElement::MAX.to_string().as_bytes(), 10).ok_or_else(|| {
        error!("Failed to parse BigInt {}", FieldElement::MAX);
        StarknetRpcApiError::InternalServerError
    })?;

    let hex_k = rng.gen_bigint_range(&lower_bound, &upper_bound).to_str_radix(16);
    let k = FieldElement::from_str(&format!("0x{}", hex_k)).map_err(|_| {
        error!("Failed to convert BigInt to FieldElement: 0x{}", hex_k);
        StarknetRpcApiError::InternalServerError
    })?;

    // 3. Make message
    let message = message.as_bytes();
    let commitment = PedersenHasher::hash_bytes(message);

    // 4. Sign the commitment
    let signature = sign(
        &FieldElement::from_str(sequencer_private_key.as_str()).map_err(|_| {
            error!("Failed to convert sequencer private key to FieldElement: {}", sequencer_private_key);
            StarknetRpcApiError::InternalServerError
        })?,
        &FieldElement::from(commitment),
        &k,
    )
    .map_err(|_| {
        error!("Failed to sign the sequencer private key {} commitment", sequencer_private_key);
        StarknetRpcApiError::InternalServerError
    })?;

    let vec = vec![signature.r.into(), signature.s.into(), signature.v.into()];

    BoundedVec::<Felt252Wrapper, MaxArraySize>::try_from(vec).map_err(|e| {
        error!("Failed to convert Vec to BoundedVec: {e:?}");
        StarknetRpcApiError::InternalServerError
    })
}

pub fn verify_sign(message: String, r: FieldElement, s: FieldElement) -> bool {
    let config_map = config_map();
    let sequencer_private_key_string =
        config_map.get_string("sequencer_private_key").expect("sequencer private key must be set");
    let sequencer_private_key = FieldElement::from_str(sequencer_private_key_string.as_str()).unwrap_or_else(|_| {
        panic!("Failed to convert sequencer private key to FieldElement: {sequencer_private_key_string}")
    });

    let sequencer_public_key = get_public_key(&sequencer_private_key);

    let message = message.as_bytes();
    let commitment = PedersenHasher::hash_bytes(message);

    verify(&sequencer_public_key, &FieldElement::from(commitment), &r, &s).unwrap_or(false)
}
