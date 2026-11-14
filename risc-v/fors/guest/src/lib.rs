//! FORS verification with n=32, k=16, a=8 and Ethereum Keccak-256.
//!
//! All domain/address encodings match the project's independent Python relation.
//! This is a few-time forest component, not the complete SLH-DSA signature scheme.
#![no_std]

use leanvm_guest::keccak::keccak256;

pub const N: usize = 32;
pub const K: usize = 16;
pub const A: usize = 8;
pub const RECORD_WORDS: usize = 12 + K * (A + 1) * 4;
pub const ADVICE_WORDS: usize = 1 << 18;
pub const MAX_BATCH: usize = (ADVICE_WORDS - 1) / RECORD_WORDS;

pub type Digest = [u64; 4];
/// Public seed, forest root and 32-byte message, each in little-endian words.
pub type Header = [Digest; 3];
/// For each tree: the opened secret, followed by its eight authentication siblings.
pub type Signature = [[Digest; A + 1]; K];

/// Domain of the public claim, followed by the full fixed parameter tuple.
pub const PROFILE: [u64; 4] = [
    u64::from_le_bytes(*b"FORSv001"),
    N as u64,
    K as u64,
    A as u64,
];

pub const fn domain(name: &[u8]) -> [u64; 2] {
    let mut bytes = [0u8; 16];
    let prefix = b"FORS:";
    let mut i = 0;
    while i < prefix.len() {
        bytes[i] = prefix[i];
        i += 1;
    }
    i = 0;
    while i < name.len() {
        bytes[5 + i] = name[i];
        i += 1;
    }
    bytes[12] = 1;
    bytes[13] = N as u8;
    bytes[14] = K as u8;
    bytes[15] = A as u8;
    let mut lo = 0u64;
    let mut hi = 0u64;
    i = 0;
    while i < 8 {
        lo |= (bytes[i] as u64) << (8 * i);
        hi |= (bytes[i + 8] as u64) << (8 * i);
        i += 1;
    }
    [lo, hi]
}

pub const LEAF: [u64; 2] = domain(b"LEAF");
pub const NODE: [u64; 2] = domain(b"NODE");
pub const ROOT: [u64; 2] = domain(b"ROOT");
pub const MSG: [u64; 2] = domain(b"MSG");

/// Hash the nonce-free fixed message relation into the 16 selected leaf indices.
pub fn indices(header: &Header) -> [u8; K] {
    let mut input = [0; 14];
    input[..2].copy_from_slice(&MSG);
    input[2..6].copy_from_slice(&header[0]);
    input[6..10].copy_from_slice(&header[1]);
    input[10..14].copy_from_slice(&header[2]);
    let hash = keccak256(&input, 112);
    core::array::from_fn(|i| (hash[i / 8] >> (8 * (i % 8))) as u8)
}

#[inline]
pub fn leaf(seed: &Digest, tree: usize, index: usize, secret: &Digest) -> Digest {
    let input = [
        LEAF[0],
        LEAF[1],
        seed[0],
        seed[1],
        seed[2],
        seed[3],
        tree as u64,
        index as u64,
        secret[0],
        secret[1],
        secret[2],
        secret[3],
    ];
    keccak256(&input, 96)
}

#[inline]
pub fn node(
    seed: &Digest,
    tree: usize,
    height: usize,
    index: usize,
    left: &Digest,
    right: &Digest,
) -> Digest {
    let input = [
        NODE[0],
        NODE[1],
        seed[0],
        seed[1],
        seed[2],
        seed[3],
        (tree as u64) | ((height as u64) << 32),
        index as u64,
        left[0],
        left[1],
        left[2],
        left[3],
        right[0],
        right[1],
        right[2],
        right[3],
    ];
    keccak256(&input, 128)
}

pub fn forest_root(seed: &Digest, roots: &[Digest; K]) -> Digest {
    let mut input = [0; 6 + K * 4];
    input[..2].copy_from_slice(&ROOT);
    input[2..6].copy_from_slice(seed);
    for (i, root) in roots.iter().enumerate() {
        input[6 + 4 * i..10 + 4 * i].copy_from_slice(root);
    }
    keccak256(&input, input.len() * 8)
}

/// Recompute every authentication path and the compressed forest root.
/// Every input word is a fixed-width byte string; there are no unchecked host hints.
pub fn verify(header: &Header, signature: &Signature) -> bool {
    let indices = indices(header);
    let mut roots = [[0; 4]; K];
    for tree in 0..K {
        let mut index = indices[tree] as usize;
        let mut current = leaf(&header[0], tree, index, &signature[tree][0]);
        for height in 0..A {
            let sibling = &signature[tree][height + 1];
            current = if index & 1 == 0 {
                node(&header[0], tree, height + 1, index >> 1, &current, sibling)
            } else {
                node(&header[0], tree, height + 1, index >> 1, sibling, &current)
            };
            index >>= 1;
        }
        roots[tree] = current;
    }
    forest_root(&header[0], &roots) == header[1]
}
