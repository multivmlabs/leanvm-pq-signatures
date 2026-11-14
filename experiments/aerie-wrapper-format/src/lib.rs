//! Host/guest byte contract for complete Aerie verification under leanVM.
//! No native acceptance bit or precomputed target enters this contract.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

pub const MAGIC: [u8; 8] = *b"AERLVM01";
pub const HEADER_BYTES: usize = 32;
pub const MAX_RECORDS: usize = 65_536;
pub const MAX_STATEMENT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
pub const AERIE_PER_RECORD_MAGIC: &[u8; 16] = b"aerie/falcon/v1p";
pub const DOMAIN: &[u8] = b"pq-leanbench/aerie-leanvm/full-verifier/v1\0";
pub const PROFILE: &[u8] = b"aerie=49b6c212c209286c536196f53618823ffdf0e899;Falcon512;wire1-per-record;fn-dsa0.3.0-raw-empty-context;akita=e023b6a46143f7b23199ccecb2684192baf7b640-dev-protocol;jolt=c7c2d08d5bb0c7c80501f29f723e595af7fcff3c;spongefish=ef9741346a150039427d9e0c02d6b2d73e93ec81;transcript=blake2b";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    Header,
    Count,
    StatementLength,
    ProofLength,
    Overflow,
    Tail,
    SaltProfile,
}

#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    pub records: usize,
    pub statement: &'a [u8],
    pub proof: &'a [u8],
}

fn bounded_lengths(records: usize, statement: usize, proof: usize) -> Result<usize, FormatError> {
    if records == 0 || records > MAX_RECORDS {
        return Err(FormatError::Count);
    }
    if statement == 0 || statement > MAX_STATEMENT_BYTES {
        return Err(FormatError::StatementLength);
    }
    if proof < AERIE_PER_RECORD_MAGIC.len() || proof > MAX_PROOF_BYTES {
        return Err(FormatError::ProofLength);
    }
    HEADER_BYTES
        .checked_add(statement)
        .and_then(|n| n.checked_add(proof))
        .ok_or(FormatError::Overflow)
}

/// Parse borrowed input with bounded lengths and exact consumption.
/// The caller must additionally parse the canonical public statement, check
/// its count equals `records`, and run the complete native Aerie verifier.
pub fn decode(bytes: &[u8]) -> Result<Frame<'_>, FormatError> {
    if bytes.len() < HEADER_BYTES || bytes[..8] != MAGIC {
        return Err(FormatError::Header);
    }
    let read = |at| -> Result<usize, FormatError> {
        let mut word = [0; 8];
        word.copy_from_slice(&bytes[at..at + 8]);
        usize::try_from(u64::from_le_bytes(word)).map_err(|_| FormatError::Overflow)
    };
    let records = read(8)?;
    let statement_len = read(16)?;
    let proof_len = read(24)?;
    let exact = bounded_lengths(records, statement_len, proof_len)?;
    if exact != bytes.len() {
        return Err(FormatError::Tail);
    }
    let split = HEADER_BYTES + statement_len;
    let proof = &bytes[split..];
    if &proof[..AERIE_PER_RECORD_MAGIC.len()] != AERIE_PER_RECORD_MAGIC {
        return Err(FormatError::SaltProfile);
    }
    Ok(Frame {
        records,
        statement: &bytes[HEADER_BYTES..split],
        proof,
    })
}

pub fn encode(records: usize, statement: &[u8], proof: &[u8]) -> Result<Vec<u8>, FormatError> {
    let length = bounded_lengths(records, statement.len(), proof.len())?;
    if &proof[..AERIE_PER_RECORD_MAGIC.len()] != AERIE_PER_RECORD_MAGIC {
        return Err(FormatError::SaltProfile);
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&(records as u64).to_le_bytes());
    bytes.extend_from_slice(&(statement.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(proof.len() as u64).to_le_bytes());
    bytes.extend_from_slice(statement);
    bytes.extend_from_slice(proof);
    Ok(bytes)
}

/// Claim digest. It commits to intended canonical keys/messages, count and
/// the pinned verification profile, not to one proof or one signature byte
/// string. Proof bytes and salts can remain private execution input.
pub fn claim_digest(records: usize, canonical_statement: &[u8]) -> [u8; 32] {
    let mut hash = Shake256::default();
    hash.update(DOMAIN);
    hash.update(&(PROFILE.len() as u32).to_le_bytes());
    hash.update(PROFILE);
    hash.update(&(records as u64).to_le_bytes());
    hash.update(&(canonical_statement.len() as u64).to_le_bytes());
    hash.update(canonical_statement);
    let mut result = [0; 32];
    hash.finalize_xof().read(&mut result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn proof() -> Vec<u8> {
        let mut p = AERIE_PER_RECORD_MAGIC.to_vec();
        p.extend_from_slice(b"body");
        p
    }
    #[test]
    fn exact_roundtrip_and_tails() {
        let encoded = encode(1, b"canonical", &proof()).unwrap();
        let parsed = decode(&encoded).unwrap();
        assert_eq!(parsed.records, 1);
        assert_eq!(parsed.statement, b"canonical");
        assert_eq!(parsed.proof, proof());
        let mut trailer = encoded.clone();
        trailer.push(0);
        assert_eq!(decode(&trailer).unwrap_err(), FormatError::Tail);
        assert_eq!(
            decode(&encoded[..encoded.len() - 1]).unwrap_err(),
            FormatError::Tail
        );
    }
    #[test]
    fn rejects_limits_and_other_salt_profile_before_payload() {
        assert_eq!(encode(0, b"x", &proof()).unwrap_err(), FormatError::Count);
        let mut bytes = encode(1, b"x", &proof()).unwrap();
        bytes[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            decode(&bytes),
            Err(FormatError::StatementLength | FormatError::Overflow)
        ));
        let mut common = proof();
        common[15] = b'c';
        assert_eq!(
            encode(1, b"x", &common).unwrap_err(),
            FormatError::SaltProfile
        );
    }
    #[test]
    fn claim_binds_count_and_full_canonical_statement() {
        assert_ne!(
            claim_digest(1, b"key/message"),
            claim_digest(2, b"key/message")
        );
        assert_ne!(
            claim_digest(1, b"key/message"),
            claim_digest(1, b"key/Message")
        );
    }
}
