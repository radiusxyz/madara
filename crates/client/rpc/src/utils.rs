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

use crate::constants::{sbb, MODULUS};
use crate::StarknetRpcApiError;

/// Attempts to convert a little-endian byte representation of
/// a scalar into a `Scalar`, failing if the input is not canonical.
fn is_bytes_valid(buf: &[u8]) -> bool {
    let mut chunks = buf.chunks_exact(8);
    let mut s = [0u64; 4];

    for (s_item, chunk) in s.iter_mut().zip(&mut chunks) {
        if let Ok(b) = <[u8; 8]>::try_from(chunk) {
            *s_item = u64::from_le_bytes(b);
        } else {
            return false;
        }
    }

    // Checked by comparison with modular values
    let (_, borrow) = sbb(s[0], MODULUS[0], 0);
    let (_, borrow) = sbb(s[1], MODULUS[1], borrow);
    let (_, borrow) = sbb(s[2], MODULUS[2], borrow);
    let (_, borrow) = sbb(s[3], MODULUS[3], borrow);

    (borrow as u8) & 1 == 1
}

/// This function is used in the context of attempting to convert a scalar
/// from its little-endian byte representation into a `Scalar` type.
/// It is utilized in the `encrypt` function to preemptively prevent failure
/// in cases where the input is not in canonical form.
/// This function checks if the provided byte array meets specific conditions
/// (e.g., being less than a certain modulus value).
pub fn is_message_valid(message_bytes: &[u8]) -> bool {
    let mut message_vecs: Vec<Vec<u8>> = message_bytes.to_vec().chunks(32).map(|s| s.into()).collect();

    for message_vec in message_vecs.iter_mut() {
        message_vec.resize(32, 0);
        let temp = &*message_vec;
        let bytes: [u8; 32] = match temp.as_slice().try_into() {
            Ok(bytes) => bytes,
            _ => return false,
        };

        if !is_bytes_valid(&bytes) {
            return false;
        }
    }

    true
}

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
