use crate::constants::{sbb, MODULUS};

/// Attempts to convert a little-endian byte representation of
/// a scalar into a `Scalar`, failing if the input is not canonical.
fn check_bytes_validity(buf: &[u8]) -> bool {
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
pub fn check_message_validity(message_bytes: &[u8]) -> bool {
    let mut message_vecs: Vec<Vec<u8>> = message_bytes.to_vec().chunks(32).map(|s| s.into()).collect();

    for message_vec in message_vecs.iter_mut() {
        message_vec.resize(32, 0);
        let temp = &*message_vec;
        let message: [u8; 32] = match temp.as_slice().try_into() {
            Ok(message) => message,
            _ => return false,
        };

        if !check_bytes_validity(&message) {
            return false;
        }
    }

    true
}
