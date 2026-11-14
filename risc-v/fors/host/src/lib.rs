//! Deterministic FORS fixtures and independently derived public outputs.
//! Seeds below are public benchmark material and must not be used as wallet keys.

use fors::{A, Digest, Header, K, MAX_BATCH, PROFILE, Signature};
use leanvm_guest::{PublicValues, Run};
use sha2::{Digest as _, Sha256};

pub const ELF: &[u8] = include_bytes!("../../fors.elf");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub header: Header,
    pub signature: Signature,
}

pub fn bytes(words: &Digest) -> [u8; 32] {
    let mut out = [0; 32];
    for (chunk, word) in out.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

pub fn words(bytes: &[u8; 32]) -> Digest {
    core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
}

fn hash(data: &[u8]) -> Digest {
    let mut lanes = vec![0u64; data.len().div_ceil(8)];
    for (i, &byte) in data.iter().enumerate() {
        lanes[i / 8] |= (byte as u64) << (8 * (i % 8));
    }
    leanvm_guest::keccak::keccak256(&lanes, data.len())
}

fn address(tree: usize, height: usize, index: usize) -> [u8; 16] {
    let mut out = [0; 16];
    out[..4].copy_from_slice(&(tree as u32).to_le_bytes());
    out[4..8].copy_from_slice(&(height as u32).to_le_bytes());
    out[8..].copy_from_slice(&(index as u64).to_le_bytes());
    out
}

/// Exactly the independent Python fixture algorithm, including its SHA-256 seeds.
pub fn record(number: usize) -> Record {
    let mut tag = b"pqbench-fors-fixture-v1".to_vec();
    tag.extend_from_slice(&(number as u64).to_le_bytes());
    tag.extend_from_slice(&[K as u8, A as u8]);
    let derive = |suffix: &[u8]| -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(&tag);
        hash.update(suffix);
        hash.finalize().into()
    };
    let sk_seed = derive(b":sk");
    let seed = words(&derive(b":pk"));
    let message = words(&derive(b":message"));
    let mut roots = [[0; 4]; K];
    let mut trees = Vec::with_capacity(K);
    let mut secrets = Vec::with_capacity(K);
    for (tree, root) in roots.iter_mut().enumerate() {
        let secret: Vec<Digest> = (0..1 << A)
            .map(|index| {
                let mut input = b"TEST-SECRET:".to_vec();
                input.extend_from_slice(&sk_seed);
                input.extend_from_slice(&address(tree, 0, index));
                hash(&input)
            })
            .collect();
        let leaves: Vec<Digest> = secret
            .iter()
            .enumerate()
            .map(|(index, secret)| fors::leaf(&seed, tree, index, secret))
            .collect();
        let mut levels = vec![leaves];
        for height in 1..=A {
            let previous = levels.last().unwrap();
            levels.push(
                previous
                    .chunks_exact(2)
                    .enumerate()
                    .map(|(index, pair)| fors::node(&seed, tree, height, index, &pair[0], &pair[1]))
                    .collect(),
            );
        }
        *root = levels[A][0];
        trees.push(levels);
        secrets.push(secret);
    }
    let root = fors::forest_root(&seed, &roots);
    let header = [seed, root, message];
    let indices = fors::indices(&header);
    let signature = core::array::from_fn(|tree| {
        let index = indices[tree] as usize;
        core::array::from_fn(|height| {
            if height == 0 {
                secrets[tree][index]
            } else {
                trees[tree][height - 1][(index >> (height - 1)) ^ 1]
            }
        })
    });
    let out = Record { header, signature };
    assert!(
        fors::verify(&out.header, &out.signature),
        "fixture verifies"
    );
    out
}

/// Receiver computation: only public seed/root/message records, with no signatures.
pub fn expected_output(headers: &[Header]) -> [u64; 4] {
    assert!(!headers.is_empty() && headers.len() <= MAX_BATCH);
    let mut public = PublicValues::new();
    public.commit(&PROFILE).commit(&(headers.len() as u64));
    for header in headers {
        public.commit(header);
    }
    public.digest()
}

pub fn batch(n: usize) -> Run {
    batch_range(0, n)
}

pub fn batch_range(start: usize, n: usize) -> Run {
    batch_with_records(start, n).0
}

pub fn batch_with_records(start: usize, n: usize) -> (Run, Vec<Record>) {
    assert!(n > 0 && n <= MAX_BATCH);
    start.checked_add(n).expect("fixture range overflow");
    let records: Vec<_> = (start..start + n).map(record).collect();
    let headers: Vec<_> = records.iter().map(|record| record.header).collect();
    let expected = expected_output(&headers);
    let mut advice = Vec::with_capacity(1 + n * fors::RECORD_WORDS);
    advice.push(n as u64);
    for record in &records {
        advice.extend(record.header.into_iter().flatten());
        advice.extend(record.signature.into_iter().flatten().flatten());
    }
    (Run { advice, expected }, records)
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn record_json(record: &Record) -> serde_json::Value {
    serde_json::json!({
        "seed": hex(&bytes(&record.header[0])),
        "root": hex(&bytes(&record.header[1])),
        "message": hex(&bytes(&record.header[2])),
        "signature": record.signature.iter().map(|opening| serde_json::json!({
            "secret": hex(&bytes(&opening[0])),
            "auth": opening[1..].iter().map(|digest| hex(&bytes(digest))).collect::<Vec<_>>()
        })).collect::<Vec<_>>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanvm::{Machine, Program};

    fn guest(advice: &[u64]) -> Result<[u64; 4], leanvm::Trap> {
        let program = Program::from_elf(ELF).unwrap();
        Machine::new(program.rv(), advice).run()
    }

    #[test]
    fn valid_guest_binds_the_public_claims() {
        let (run, records) = batch_with_records(0, 1);
        assert_eq!(guest(&run.advice), Ok(run.expected));
        let mut headers = vec![records[0].header];
        headers[0][2][0] ^= 1;
        assert_ne!(expected_output(&headers), run.expected);
        headers[0][2][0] ^= 1;
        headers[0][1][0] ^= 1;
        assert_ne!(expected_output(&headers), run.expected);
    }

    #[test]
    fn bad_witnesses_trap_inside_the_guest() {
        let run = batch(1);
        // seed, public root, message, first secret, first authentication sibling,
        // final authentication sibling. Each mutation reaches actual verification.
        for offset in [1, 5, 9, 13, 17, fors::RECORD_WORDS] {
            let mut advice = run.advice.clone();
            advice[offset] ^= 1;
            assert!(guest(&advice).is_err(), "word {offset} must reject");
        }
        for n in [0, (MAX_BATCH + 1) as u64, u64::MAX] {
            let mut advice = run.advice.clone();
            advice[0] = n;
            assert!(guest(&advice).is_err(), "invalid count {n}");
        }
    }

    #[test]
    fn native_mutations_and_domain_separation() {
        let record = record(7);
        for part in 0..3 {
            let mut bad = record.clone();
            bad.header[part][0] ^= 1;
            assert!(!fors::verify(&bad.header, &bad.signature));
        }
        let mut bad = record.clone();
        bad.signature.swap(0, 1);
        assert!(!fors::verify(&bad.header, &bad.signature));
        assert_ne!(fors::LEAF, fors::NODE);
        assert_ne!(fors::NODE, fors::ROOT);
        assert_ne!(fors::ROOT, fors::MSG);
    }
}
