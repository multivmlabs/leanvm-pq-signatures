use leanvm_guest::{PublicValues, Run};
use raccoon_riscv_guest::{DOMAIN, MAX_BATCH, PK_BYTES, SIG_BYTES, SIG_WORDS, fixture, verify};

pub const ELF: &[u8] = include_bytes!("../../raccoon.elf");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRecord {
    pub public_key: [u8; PK_BYTES],
    pub message: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub public: PublicRecord,
    pub signature: [u8; SIG_BYTES],
}

pub fn record(index: usize) -> Record {
    let mut result = Record {
        public: PublicRecord {
            public_key: [0; PK_BYTES],
            message: [0; 32],
        },
        signature: [0; SIG_BYTES],
    };
    fixture(
        index.try_into().expect("index fits u64"),
        &mut result.public.public_key,
        &mut result.signature,
        &mut result.public.message,
    );
    assert!(verify(
        &result.public.public_key,
        &result.public.message,
        &result.signature
    ));
    result
}

fn words<const W: usize>(bytes: &[u8]) -> [u64; W] {
    assert!(bytes.len() <= 8 * W);
    core::array::from_fn(|i| {
        let mut word = [0; 8];
        let start = i * 8;
        if start < bytes.len() {
            let n = (bytes.len() - start).min(8);
            word[..n].copy_from_slice(&bytes[start..start + n]);
        }
        u64::from_le_bytes(word)
    })
}

pub fn expected_output(records: &[PublicRecord]) -> [u64; 4] {
    assert!((1..=MAX_BATCH).contains(&records.len()));
    let mut values = PublicValues::new();
    values.commit(&DOMAIN).commit(&(records.len() as u64));
    for record in records {
        values.commit(&words::<282>(&record.public_key));
        values.commit(&words::<4>(&record.message));
    }
    values.digest()
}

pub fn run_from_records(records: &[Record]) -> Run {
    assert!((1..=MAX_BATCH).contains(&records.len()));
    let public: Vec<_> = records.iter().map(|r| r.public.clone()).collect();
    let mut advice = vec![records.len() as u64];
    for record in records {
        advice.extend(words::<282>(&record.public.public_key));
        advice.extend(words::<4>(&record.public.message));
        advice.extend(words::<SIG_WORDS>(&record.signature));
    }
    Run {
        advice,
        expected: expected_output(&public),
    }
}

pub fn records(start: usize, n: usize) -> Vec<Record> {
    assert!((1..=MAX_BATCH).contains(&n));
    (start..start.checked_add(n).expect("index overflow"))
        .map(record)
        .collect()
}

pub fn batch_range(start: usize, n: usize) -> Run {
    run_from_records(&records(start, n))
}

pub fn batch(n: usize) -> Run {
    batch_range(0, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanvm::{Machine, Program};
    use raccoon_riscv_guest::{PK_WORDS, RECORD_WORDS};

    fn on_vm(run: &Run) -> Result<[u64; 4], leanvm::Trap> {
        let program = Program::from_elf(ELF).expect("RV64IM ELF");
        Machine::new(program.rv(), &run.advice).run()
    }

    #[test]
    fn deterministic_distinct_records_match_actual_riscv_execution() {
        assert_eq!(record(0), record(0));
        assert_ne!(record(0).public.public_key, record(1).public.public_key);
        assert_ne!(record(0).public.message, record(1).public.message);
        for n in 1..=2 {
            let run = batch(n);
            assert_eq!(run.advice.len(), 1 + n * RECORD_WORDS);
            assert_eq!(on_vm(&run).expect("honest guest exits"), run.expected);
        }
    }

    #[test]
    fn altered_keys_messages_and_challenges_fail_in_actual_guest() {
        let honest = batch(1);
        for index in [1, 1 + PK_WORDS, 1 + PK_WORDS + 4] {
            let mut bad = honest.clone();
            bad.advice[index] ^= 1;
            assert!(on_vm(&bad).is_err(), "altered word {index}");
        }
    }

    #[test]
    fn invalid_encodings_and_transport_bounds_fail_in_actual_guest() {
        let honest = batch(1);
        let mut key = honest.clone();
        // t[0][0] is the first 7-bit coefficient after the 16-byte A seed.
        key.advice[1 + 16 / 8] |= 127;
        assert!(on_vm(&key).is_err(), "127 is outside Z_125");
        let mut padding = honest.clone();
        padding.advice[1 + PK_WORDS + 4 + SIG_WORDS - 1] |= 1 << 32;
        assert!(on_vm(&padding).is_err(), "transport padding");
        let mut signature_padding = honest.clone();
        signature_padding.advice[1 + PK_WORDS + 4 + SIG_WORDS - 1] |= 1 << 24;
        assert!(on_vm(&signature_padding).is_err(), "signature padding");
        let mut unary = honest.clone();
        for word in &mut unary.advice[1 + PK_WORDS + 4..] {
            *word = u64::MAX;
        }
        unary.advice[1 + PK_WORDS + 4 + SIG_WORDS - 1] &= u32::MAX as u64;
        assert!(on_vm(&unary).is_err(), "unterminated unary coding");
        for count in [0, MAX_BATCH as u64 + 1] {
            let mut bad = honest.clone();
            bad.advice[0] = count;
            assert!(on_vm(&bad).is_err(), "count {count}");
        }
    }

    #[test]
    fn public_digest_binds_count_order_keys_and_messages() {
        let a = record(0).public;
        let b = record(1).public;
        assert_ne!(
            expected_output(std::slice::from_ref(&a)),
            expected_output(&[a.clone(), b.clone()])
        );
        assert_ne!(
            expected_output(&[a.clone(), b.clone()]),
            expected_output(&[b, a.clone()])
        );
        let mut changed = a.clone();
        changed.message[31] ^= 128;
        assert_ne!(
            expected_output(std::slice::from_ref(&a)),
            expected_output(&[changed])
        );
        let mut changed = a.clone();
        changed.public_key[PK_BYTES - 1] ^= 1;
        assert_ne!(expected_output(&[a]), expected_output(&[changed]));
    }

    #[test]
    fn byte_aligned_signature_zero_padding_is_enforced() {
        // Algebraic zero-key/zero-response parser control, generated by the
        // independent Python reference. Never used in the benchmark corpus.
        let bytes = include_bytes!("../testdata/byte-aligned.bin");
        let mut record = Record {
            public: PublicRecord {
                public_key: bytes[..PK_BYTES].try_into().unwrap(),
                message: bytes[PK_BYTES..PK_BYTES + 32].try_into().unwrap(),
            },
            signature: bytes[PK_BYTES + 32..].try_into().unwrap(),
        };
        assert!(verify(
            &record.public.public_key,
            &record.public.message,
            &record.signature
        ));
        let honest = run_from_records(&[record.clone()]);
        assert_eq!(on_vm(&honest).unwrap(), honest.expected);
        // Coding ends on byte 10848. This bit is entirely outside that coding.
        record.signature[SIG_BYTES - 1] = 1;
        assert!(!verify(
            &record.public.public_key,
            &record.public.message,
            &record.signature
        ));
        assert!(on_vm(&run_from_records(&[record])).is_err());
    }

    #[test]
    fn valid_coding_at_the_exact_last_signature_bit_is_accepted() {
        // Every payload bit is used, with no padding and no extra byte to fetch.
        // This is a parser completeness control, never a benchmark fixture.
        let bytes = include_bytes!("../testdata/exact-full.bin");
        let record = Record {
            public: PublicRecord {
                public_key: bytes[..PK_BYTES].try_into().unwrap(),
                message: bytes[PK_BYTES..PK_BYTES + 32].try_into().unwrap(),
            },
            signature: bytes[PK_BYTES + 32..].try_into().unwrap(),
        };
        assert!(verify(
            &record.public.public_key,
            &record.public.message,
            &record.signature
        ));
        let honest = run_from_records(&[record]);
        assert_eq!(on_vm(&honest).unwrap(), honest.expected);
    }

    #[test]
    fn norms_are_checked_even_when_the_challenge_equation_is_correct() {
        // Python recomputes the challenge equation for every input below.
        // Rejection therefore requires the indicated infinity or L2 check.
        for bytes in [
            &include_bytes!("../testdata/hint-l2-fail.bin")[..],
            &include_bytes!("../testdata/hint-inf-fail.bin")[..],
            &include_bytes!("../testdata/response-inf-fail.bin")[..],
        ] {
            let record = Record {
                public: PublicRecord {
                    public_key: bytes[..PK_BYTES].try_into().unwrap(),
                    message: bytes[PK_BYTES..PK_BYTES + 32].try_into().unwrap(),
                },
                signature: bytes[PK_BYTES + 32..].try_into().unwrap(),
            };
            assert!(!verify(
                &record.public.public_key,
                &record.public.message,
                &record.signature
            ));
            assert!(on_vm(&run_from_records(&[record])).is_err());
        }
    }

    #[test]
    fn sdk_keccak_matches_unchanged_reference_on_full_states() {
        unsafe extern "C" {
            fn pqbench_raccoon_ref_keccak_f1600(state: *mut u64);
        }
        let mut random = 0x1234567890abcdefu64;
        for case in 0..130 {
            let input = core::array::from_fn(|_| {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                match case {
                    0 => 0,
                    1 => u64::MAX,
                    _ => random,
                }
            });
            let mut expected: [u64; 25] = input;
            // SAFETY: exact-size aligned state, reference permutation only.
            unsafe {
                pqbench_raccoon_ref_keccak_f1600(expected.as_mut_ptr());
            }
            let mut actual = input;
            leanvm_guest::keccak::f1600(&mut actual);
            assert_eq!(actual, expected, "full state {case}");
        }
    }
}
