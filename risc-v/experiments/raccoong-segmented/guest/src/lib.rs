//! One authenticated matrix row of the unchanged strict Raccoon-G relation.
#![no_std]

use leanvm_guest::{Blake2s, PublicValues};
use original::arithmetic::{
    Poly, add, challenge, forward, from_montgomery, inverse, matrix_poly, multiply, sub,
    to_montgomery,
};
use original::xof::{Xof, shake256};
pub use original::{PK_BYTES, PK_WORDS, SIG_BYTES, SIG_WORDS};

pub const ROW_COUNT: usize = 9;
pub const PARTS_PER_SIGNATURE: usize = 5;
pub const ROWS_PER_LEAF: usize = 2;
/// Fixed, charged trace normalization; it is independent of all witnesses.
pub const TRACE_PADDING_STORES: usize = 32768;
pub const W_WORDS: usize = ROW_COUNT * 256 / 4;
pub const W_BYTES: usize = W_WORDS * 8;
pub const HINT_MODULUS: u64 = 2048;
pub type Commitment = [u64; W_WORDS];
pub type Binding = [u64; 8];
pub const DOMAIN: [u64; 4] = [
    u64::from_le_bytes(*b"pqbench/"),
    u64::from_le_bytes(*b"rcg-two/"),
    u64::from_le_bytes(*b"strictv1"),
    u64::from_le_bytes(*b"/d512/v1"),
];
const WITNESS_DOMAIN: [[u64; 4]; 2] = [
    [
        u64::from_le_bytes(*b"pqbench/"),
        u64::from_le_bytes(*b"rcg-wit/"),
        u64::from_le_bytes(*b"strictv1"),
        u64::from_le_bytes(*b"/hash0v1"),
    ],
    [
        u64::from_le_bytes(*b"pqbench/"),
        u64::from_le_bytes(*b"rcg-wit/"),
        u64::from_le_bytes(*b"strictv1"),
        u64::from_le_bytes(*b"/hash1v1"),
    ],
];

#[inline]
pub fn w_coefficient(w: &Commitment, index: usize) -> u64 {
    (w[index / 4] >> (16 * (index % 4))) & 0xffff
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

struct Transformed {
    c: Poly,
    z: [Poly; ROW_COUNT],
}

fn transform(signature: &[u8; SIG_BYTES]) -> Transformed {
    let hash: &[u8; 32] = signature[..32].try_into().unwrap();
    let mut c = challenge(hash);
    forward(&mut c);
    let mut z = [[0; 256]; ROW_COUNT];
    for (i, polynomial) in z.iter_mut().enumerate() {
        for (j, coefficient) in polynomial.iter_mut().enumerate() {
            *coefficient = to_montgomery(original::decode7(&signature[32 + 7 * (i * 256 + j)..]));
        }
        forward(polynomial);
    }
    Transformed { c, z }
}

fn reconstruct_row(
    pk: &[u8; PK_BYTES],
    signature: &[u8; SIG_BYTES],
    row: usize,
    transformed: &Transformed,
) -> Poly {
    let mut value = [0; 256];
    let mut a = [0; 256];
    for (column, z_poly) in transformed.z.iter().enumerate() {
        matrix_poly(&pk[..16], row, column, &mut a);
        for j in 0..256 {
            value[j] = add(value[j], multiply(a[j], z_poly[j]));
        }
    }
    let mut t = [0; 256];
    for (j, coefficient) in t.iter_mut().enumerate() {
        let full = original::decode7(&pk[16 + 7 * (row * 256 + j)..]);
        *coefficient = to_montgomery(rounded(full, 35, 16384) << 35);
    }
    forward(&mut t);
    for j in 0..256 {
        value[j] = sub(value[j], multiply(transformed.c[j], t[j]));
    }
    inverse(&mut value);
    for (j, coefficient) in value.iter_mut().enumerate() {
        let rounded_value = rounded(from_montgomery(*coefficient), 38, HINT_MODULUS);
        let offset = 32 + ROW_COUNT * 256 * 7 + 2 * (row * 256 + j);
        let hint = u16::from_le_bytes(signature[offset..offset + 2].try_into().unwrap()) as u64;
        let sum = rounded_value + hint;
        *coefficient = if sum >= HINT_MODULUS {
            sum - HINT_MODULUS
        } else {
            sum
        };
    }
    value
}

/// Fresh prover preparation. The guest never trusts this host reconstruction.
pub fn reconstruct_commitment(
    pk: &[u8; PK_BYTES],
    signature: &[u8; SIG_BYTES],
) -> Option<Commitment> {
    if !original::canonical_and_norm(pk, signature) {
        return None;
    }
    let transformed = transform(signature);
    let mut w = [0; W_WORDS];
    for row in 0..ROW_COUNT {
        let values = reconstruct_row(pk, signature, row, &transformed);
        for (j, value) in values.into_iter().enumerate() {
            let index = row * 256 + j;
            w[index / 4] |= value << (16 * (index % 4));
        }
    }
    Some(w)
}

/// Complete global checks, including all original canonicality and norm checks.
pub fn global_checks(
    pk: &[u8; PK_BYTES],
    message: &[u8; 32],
    signature: &[u8; SIG_BYTES],
    w: &Commitment,
) -> bool {
    if !original::canonical_and_norm(pk, signature) {
        return false;
    }
    for index in 0..ROW_COUNT * 256 {
        if w_coefficient(w, index) >= HINT_MODULUS {
            return false;
        }
    }
    let tr = shake256(&[pk]);
    let mu = shake256(&[&tr, message]);
    let mut hash = Xof::new(136);
    hash.update(&[b'H', 0, 32, 0, 0, 0, 63, 0]);
    hash.update(&mu);
    for index in 0..ROW_COUNT * 256 {
        hash.update(&w_coefficient(w, index).to_le_bytes()[..7]);
    }
    let mut reconstructed_hash = [0; 32];
    hash.read(&mut reconstructed_hash);
    reconstructed_hash == signature[..32]
}

pub fn verify_row(
    pk: &[u8; PK_BYTES],
    message: &[u8; 32],
    signature: &[u8; SIG_BYTES],
    w: &Commitment,
    row: usize,
) -> bool {
    if row >= ROW_COUNT || !global_checks(pk, message, signature, w) {
        return false;
    }
    let transformed = transform(signature);
    let reconstructed = reconstruct_row(pk, signature, row, &transformed);
    reconstructed
        .into_iter()
        .enumerate()
        .all(|(j, value)| value == w_coefficient(w, row * 256 + j))
}

/// Canonical groups cover rows (0,1), (2,3), (4,5), (6,7), and (8,8).
pub fn rows_for_part(part: usize) -> Option<[usize; ROWS_PER_LEAF]> {
    if part >= PARTS_PER_SIGNATURE {
        return None;
    }
    let first = 2 * part;
    Some([first, (first + 1).min(ROW_COUNT - 1)])
}

pub fn verify_part(
    pk: &[u8; PK_BYTES],
    message: &[u8; 32],
    signature: &[u8; SIG_BYTES],
    w: &Commitment,
    part: usize,
) -> bool {
    let Some(rows) = rows_for_part(part) else {
        return false;
    };
    if !global_checks(pk, message, signature, w) {
        return false;
    }
    let transformed = transform(signature);
    for row in rows {
        let reconstructed = reconstruct_row(pk, signature, row, &transformed);
        if !reconstructed
            .into_iter()
            .enumerate()
            .all(|(j, value)| value == w_coefficient(w, row * 256 + j))
        {
            return false;
        }
    }
    true
}

/// Two separated BLAKE2s hashes of the same fixed canonical witness encoding.
pub fn binding(signature: &[u8; SIG_BYTES], w: &Commitment) -> Binding {
    let mut result = [0; 8];
    for domain in 0..2 {
        let mut hash = Blake2s::new();
        hash.update_words(&WITNESS_DOMAIN[domain]);
        hash.update_words(&[SIG_BYTES as u64, W_BYTES as u64]);
        hash.update(signature);
        hash.update_words(w);
        result[4 * domain..4 * domain + 4].copy_from_slice(&hash.finalize_words());
    }
    result
}

pub fn expected_words(
    pk: &[u64; PK_WORDS],
    message: &[u64; 4],
    row: usize,
    digest: &Binding,
) -> [u64; 4] {
    let rows = rows_for_part(row).expect("invalid part");
    let mut public = PublicValues::new();
    public
        .commit(&DOMAIN)
        .commit(&(row as u64))
        .commit(&(rows[0] as u64))
        .commit(&(rows[1] as u64))
        .commit(pk)
        .commit(message)
        .commit(digest);
    public.digest()
}

pub fn verify_words(
    pk: &[u64; PK_WORDS],
    message: &[u64; 4],
    signature: &[u64; SIG_WORDS],
    w: &Commitment,
    row: usize,
) -> Option<Binding> {
    #[cfg(target_endian = "little")]
    unsafe {
        // SAFETY: typed words contain all exact bytes, on the specified LE target.
        let pk = &*pk.as_ptr().cast::<[u8; PK_BYTES]>();
        let message = &*message.as_ptr().cast::<[u8; 32]>();
        let signature = &*signature.as_ptr().cast::<[u8; SIG_BYTES]>();
        if !verify_part(pk, message, signature, w, row) {
            return None;
        }
        Some(binding(signature, w))
    }
    #[cfg(not(target_endian = "little"))]
    compile_error!("Segmented transport requires little endian");
}
