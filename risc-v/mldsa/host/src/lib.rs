use leanvm_guest::{PublicValues, Run};
use mldsa_riscv_guest::{DOMAIN, MAX_BATCH, PK_BYTES, SIG_BYTES, SIG_WORDS, fixture, verify};

pub const ELF: &[u8] = include_bytes!("../../mldsa.elf");

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
        values.commit(&words::<164>(&record.public_key));
        values.commit(&words::<4>(&record.message));
    }
    values.digest()
}

pub fn run_from_records(records: &[Record]) -> Run {
    assert!((1..=MAX_BATCH).contains(&records.len()));
    let public: Vec<_> = records.iter().map(|r| r.public.clone()).collect();
    let mut advice = vec![records.len() as u64];
    for record in records {
        advice.extend(words::<164>(&record.public.public_key));
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
    use mldsa_riscv_guest::{PK_WORDS, RECORD_WORDS};

    #[test]
    fn sdk_keccak_matches_reference_on_arbitrary_full_states() {
        #[repr(C)]
        struct State {
            lanes: [u64; 25],
            position: u32,
        }
        unsafe extern "C" {
            fn pqcrystals_dilithium_fips202_ref_shake256_squeeze(
                out: *mut u8,
                len: usize,
                state: *mut State,
            );
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
            let mut expected = State {
                lanes: input,
                position: 136,
            };
            let mut byte = 0;
            // The full rate has been consumed, so squeeze applies exactly one permutation.
            unsafe {
                pqcrystals_dilithium_fips202_ref_shake256_squeeze(&mut byte, 1, &mut expected);
            }
            let mut actual = input;
            leanvm_guest::keccak::f1600(&mut actual);
            assert_eq!(actual, expected.lanes, "full state {case}");
        }
    }

    #[test]
    fn freestanding_memory_handles_alignment_tails_and_overlaps() {
        unsafe extern "C" {
            fn pqbench_mldsa_memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8;
            fn pqbench_mldsa_memset(dst: *mut u8, c: i32, n: usize) -> *mut u8;
            fn pqbench_mldsa_memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8;
        }
        #[repr(align(8))]
        struct Bytes([u8; 128]);
        for a in 0..=16 {
            for b in 0..=16 {
                for n in 0..=64 {
                    let source = Bytes(core::array::from_fn(|i| (i * 17 + 3) as u8));
                    let mut target = Bytes([0x77; 128]);
                    let mut expected = target.0;
                    expected[a..a + n].copy_from_slice(&source.0[b..b + n]);
                    unsafe {
                        pqbench_mldsa_memcpy(
                            target.0.as_mut_ptr().add(a),
                            source.0.as_ptr().add(b),
                            n,
                        );
                    }
                    assert_eq!(target.0, expected);
                    expected[a..a + n].fill(0xc3);
                    unsafe {
                        pqbench_mldsa_memset(target.0.as_mut_ptr().add(a), 0x1c3, n);
                    }
                    assert_eq!(target.0, expected);
                    let mut moving = Bytes(source.0);
                    let mut expected = source.0;
                    expected.copy_within(b..b + n, a);
                    unsafe {
                        pqbench_mldsa_memmove(
                            moving.0.as_mut_ptr().add(a),
                            moving.0.as_ptr().add(b),
                            n,
                        );
                    }
                    assert_eq!(moving.0, expected);
                }
            }
        }
    }

    fn on_vm(run: &Run) -> Result<[u64; 4], leanvm::Trap> {
        let program = Program::from_elf(ELF).expect("valid RV64IM guest ELF");
        Machine::new(program.rv(), &run.advice).run()
    }

    fn set_signature_byte(run: &mut Run, offset: usize, byte: u8) {
        let word = 1 + PK_WORDS + 4 + offset / 8;
        let shift = 8 * (offset % 8);
        run.advice[word] = (run.advice[word] & !(255 << shift)) | (u64::from(byte) << shift);
    }

    #[test]
    fn deterministic_distinct_records_native_and_guest_agree() {
        let first = record(0);
        assert_eq!(first, record(0));
        let second = record(1);
        assert_ne!(first.public.public_key, second.public.public_key);
        assert_ne!(first.public.message, second.public.message);
        for n in 1..=2 {
            let run = batch(n);
            assert_eq!(run.advice.len(), 1 + n * RECORD_WORDS);
            assert_eq!(on_vm(&run).expect("honest guest exits"), run.expected);
        }
    }

    #[test]
    fn changing_key_message_or_challenge_is_rejected_inside_the_guest() {
        let honest = batch(1);
        for index in [1, 1 + PK_WORDS, 1 + PK_WORDS + 4] {
            let mut bad = honest.clone();
            bad.advice[index] ^= 1;
            assert!(on_vm(&bad).is_err(), "altered word {index} must trap");
        }
    }

    #[test]
    fn malformed_hint_bound_z_norm_and_signature_padding_are_rejected() {
        let honest = batch(1);
        let mut hints = honest.clone();
        set_signature_byte(&mut hints, SIG_BYTES - 1, 81);
        assert!(on_vm(&hints).is_err(), "hint boundary >80 must trap");
        let mut duplicate_hints = honest.clone();
        for i in 0..4 {
            set_signature_byte(&mut duplicate_hints, SIG_BYTES - 4 + i, 2);
        }
        set_signature_byte(&mut duplicate_hints, 2336, 0);
        set_signature_byte(&mut duplicate_hints, 2337, 0);
        assert!(
            on_vm(&duplicate_hints).is_err(),
            "duplicate hint indices must trap"
        );
        let mut unused_hint = honest.clone();
        for i in 0..4 {
            set_signature_byte(&mut unused_hint, SIG_BYTES - 4 + i, 0);
        }
        set_signature_byte(&mut unused_hint, 2336, 1);
        assert!(
            on_vm(&unused_hint).is_err(),
            "nonzero unused hint encoding must trap"
        );
        let mut norm = honest.clone();
        // z[0] = GAMMA1 - 0 = 131072, outside GAMMA1-BETA.
        set_signature_byte(&mut norm, 32, 0);
        set_signature_byte(&mut norm, 33, 0);
        let byte = ((norm.advice[1 + PK_WORDS + 4 + 34 / 8] >> (8 * (34 % 8))) & 255) as u8;
        set_signature_byte(&mut norm, 34, byte & !3);
        assert!(on_vm(&norm).is_err(), "out-of-bound z must trap");
        let mut padding = honest.clone();
        padding.advice[1 + PK_WORDS + 4 + SIG_WORDS - 1] |= 1 << 32;
        assert!(
            on_vm(&padding).is_err(),
            "nonzero signature padding must trap"
        );
        let mut count = honest;
        count.advice[0] = 0;
        assert!(on_vm(&count).is_err(), "zero batch must trap");
    }

    #[test]
    fn public_output_binds_count_order_keys_and_messages() {
        let a = record(0).public;
        let b = record(1).public;
        assert_ne!(
            expected_output(&[a.clone()]),
            expected_output(&[a.clone(), b.clone()])
        );
        assert_ne!(
            expected_output(&[a.clone(), b.clone()]),
            expected_output(&[b, a.clone()])
        );
        let mut different = a.clone();
        different.message[0] ^= 1;
        assert_ne!(expected_output(&[a]), expected_output(&[different]));
    }
}
