//! Raccoon-G HD-wallet verification, strict authors' PoC profile.
//!
//! This executable profile is separate from NIST Raccoon-128-1. Paper-to-code
//! conformance and the security provenance of these parameters remain pending.
#![no_std]

pub mod arithmetic;
pub mod constants;
pub mod xof;
use arithmetic::{
    Poly, add, challenge, forward, from_montgomery, inverse, matrix_poly, multiply, sub,
    to_montgomery,
};
use constants::Q;
use xof::{Xof, shake256};

pub const PK_BYTES: usize = 16144;
pub const SIG_BYTES: usize = 20768;
pub const PK_WORDS: usize = PK_BYTES / 8;
pub const SIG_WORDS: usize = SIG_BYTES / 8;
pub const RECORD_WORDS: usize = PK_WORDS + 4 + SIG_WORDS;
/// Advice transport bound, not a measured proof capacity.
pub const MAX_BATCH: usize = 64;
pub const DOMAIN: [u64; 4] = [
    u64::from_le_bytes(*b"pqbench/"),
    u64::from_le_bytes(*b"raccoong"),
    u64::from_le_bytes(*b"/hd-poc/"),
    u64::from_le_bytes(*b"strictv1"),
];
/// floor(B^2) for the ideal real-valued authors' depth-1000 bound expression.
/// Derived independently at 256 and 512 bits. This does not reproduce Python
/// binary64 rounding near the boundary; it defines the explicit strict profile.
pub const NORM_SQUARED: u128 = 25650475979193785709999263840;
pub const HINT_MODULUS: u64 = 2048;

#[inline]
pub fn decode7(bytes: &[u8]) -> u64 {
    let mut padded = [0; 8];
    padded[..7].copy_from_slice(&bytes[..7]);
    u64::from_le_bytes(padded)
}

#[inline]
fn centered_magnitude(value: u64, modulus: u64) -> u64 {
    if value > modulus / 2 {
        modulus - value
    } else {
        value
    }
}

/// Canonical parsing and exact norm predicate, independent of the hash equation.
pub fn canonical_and_norm(pk: &[u8; PK_BYTES], signature: &[u8; SIG_BYTES]) -> bool {
    for coefficient in pk[16..].as_chunks::<7>().0 {
        if decode7(coefficient) >= Q {
            return false;
        }
    }
    let mut norm = 0u128;
    for coefficient in signature[32..32 + 9 * 256 * 7].as_chunks::<7>().0 {
        let value = decode7(coefficient);
        if value >= Q {
            return false;
        }
        let magnitude = centered_magnitude(value, Q) as u128;
        norm += magnitude * magnitude;
        if norm > NORM_SQUARED {
            return false;
        }
    }
    for coefficient in signature[32 + 9 * 256 * 7..].as_chunks::<2>().0 {
        let value = u16::from_le_bytes(*coefficient) as u64;
        if value >= HINT_MODULUS {
            return false;
        }
        let magnitude = centered_magnitude(value, HINT_MODULUS) as u128;
        // Below 2^98 before early rejection, well below u128. No overflow or
        // truncation can bypass this bound, even for arbitrary canonical input.
        norm += (magnitude * magnitude) << 76;
        if norm > NORM_SQUARED {
            return false;
        }
    }
    true
}

#[inline]
fn rounded(value: u64, shift: u32, modulus: u64) -> u64 {
    let result = (value + (1 << (shift - 1))) >> shift;
    if result >= modulus {
        result - modulus
    } else {
        result
    }
}

pub fn verify(pk: &[u8; PK_BYTES], message: &[u8; 32], signature: &[u8; SIG_BYTES]) -> bool {
    if !canonical_and_norm(pk, signature) {
        return false;
    }
    let tr = shake256(&[pk]);
    let mu = shake256(&[&tr, message]);
    let c_hash: &[u8; 32] = signature[..32].try_into().unwrap();
    let mut c = challenge(c_hash);
    forward(&mut c);

    let mut z = [[0; 256]; 9];
    for (i, polynomial) in z.iter_mut().enumerate() {
        for (j, coefficient) in polynomial.iter_mut().enumerate() {
            *coefficient = to_montgomery(decode7(&signature[32 + 7 * (i * 256 + j)..]));
        }
        forward(polynomial);
    }
    let mut hash = Xof::new(136);
    // hdr24('H', len(mu)=32, q_bytes * 9 * 256=16128).
    hash.update(&[b'H', 0, 32, 0, 0, 0, 63, 0]);
    hash.update(&mu);
    for row in 0..9 {
        let mut value: Poly = [0; 256];
        let mut a: Poly = [0; 256];
        for (column, z_poly) in z.iter().enumerate() {
            matrix_poly(&pk[..16], row, column, &mut a);
            for j in 0..256 {
                value[j] = add(value[j], multiply(a[j], z_poly[j]));
            }
        }
        let mut t: Poly = [0; 256];
        for (j, coefficient) in t.iter_mut().enumerate() {
            let full = decode7(&pk[16 + 7 * (row * 256 + j)..]);
            *coefficient = to_montgomery(rounded(full, 35, 16384) << 35);
        }
        forward(&mut t);
        for j in 0..256 {
            value[j] = sub(value[j], multiply(c[j], t[j]));
        }
        inverse(&mut value);
        for (j, coefficient) in value.iter().enumerate() {
            let v = rounded(from_montgomery(*coefficient), 38, HINT_MODULUS);
            let offset = 32 + 9 * 256 * 7 + 2 * (row * 256 + j);
            let h = u16::from_le_bytes(signature[offset..offset + 2].try_into().unwrap()) as u64;
            let sum = v + h;
            let w = if sum >= HINT_MODULUS {
                sum - HINT_MODULUS
            } else {
                sum
            };
            hash.update(&w.to_le_bytes()[..7]);
        }
    }
    let mut result = [0; 32];
    hash.read(&mut result);
    result == *c_hash
}

pub fn verify_words(
    pk: &[u64; PK_WORDS],
    message: &[u64; 4],
    signature: &[u64; SIG_WORDS],
) -> bool {
    #[cfg(target_endian = "little")]
    unsafe {
        // SAFETY: all byte lengths are multiples of eight and these typed arrays
        // contain every canonical byte, with no unbound transport padding.
        verify(
            &*pk.as_ptr().cast(),
            &*message.as_ptr().cast(),
            &*signature.as_ptr().cast(),
        )
    }
    #[cfg(not(target_endian = "little"))]
    compile_error!("Raccoon-G word transport requires little endian");
}
