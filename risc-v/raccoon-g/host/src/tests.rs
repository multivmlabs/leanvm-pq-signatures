use super::*;
use raccoong_riscv_guest::{
    NORM_SQUARED, arithmetic::*, canonical_and_norm, constants::Q, xof::Xof,
};

fn on_vm(run: &Run) -> Result<[u64; 4], leanvm::Trap> {
    let program = leanvm::Program::from_elf(ELF).expect("approved RISC-V ELF");
    leanvm::Machine::new(program.rv(), &run.advice).run()
}

#[test]
fn montgomery_ntt_matches_independent_schoolbook_ring() {
    let mut state = 197819u64;
    let mut sample = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % Q
    };
    for _ in 0..2048 {
        let a = sample();
        let b = sample();
        assert_eq!(from_montgomery(to_montgomery(a)), a);
        assert_eq!(
            from_montgomery(multiply(to_montgomery(a), to_montgomery(b))),
            ((a as u128 * b as u128) % (Q as u128)) as u64
        );
    }
    for case in 0..4 {
        let a: Poly = core::array::from_fn(|j| match case {
            0 => {
                if j == 0 {
                    1
                } else {
                    0
                }
            }
            1 => {
                if j == 255 {
                    Q - 1
                } else {
                    0
                }
            }
            _ => sample(),
        });
        let b: Poly = core::array::from_fn(|_| sample());
        let mut ah = a.map(to_montgomery);
        let mut bh = b.map(to_montgomery);
        forward(&mut ah);
        forward(&mut bh);
        let mut roundtrip = ah;
        inverse(&mut roundtrip);
        assert_eq!(roundtrip.map(from_montgomery), a);
        let mut product = core::array::from_fn(|j| multiply(ah[j], bh[j]));
        inverse(&mut product);
        let mut expected = [0u64; 256];
        for (i, &a_coefficient) in a.iter().enumerate() {
            for (j, &b_coefficient) in b.iter().enumerate() {
                let value = ((a_coefficient as u128 * b_coefficient as u128) % (Q as u128)) as u64;
                let index = (i + j) % 256;
                expected[index] = if i + j < 256 {
                    (expected[index] + value) % Q
                } else {
                    (expected[index] + Q - value) % Q
                };
            }
        }
        assert_eq!(
            product.map(from_montgomery),
            expected,
            "schoolbook case {case}"
        );
    }
}

#[test]
fn shake_matches_fips202_known_answers_and_streaming() {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|x| format!("{x:02x}")).collect()
    }
    let mut output = [0; 32];
    let mut xof = Xof::new(136);
    xof.read(&mut output);
    assert_eq!(
        hex(&output),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    );
    let mut xof = Xof::new(168);
    xof.read(&mut output);
    assert_eq!(
        hex(&output),
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    );
    let input = core::array::from_fn::<_, 1024, _>(|i| i as u8);
    for rate in [136, 168] {
        let mut whole = Xof::new(rate);
        whole.update(&input);
        let mut expected = [0; 1024];
        whole.read(&mut expected);
        let mut segmented = Xof::new(rate);
        for chunk in input.chunks(7) {
            segmented.update(chunk);
        }
        let mut actual = [0; 1024];
        for chunk in actual.chunks_mut(11) {
            segmented.read(chunk);
        }
        assert_eq!(expected, actual);
    }
}

#[test]
fn canonical_norm_rejects_aliases_and_checks_both_signs() {
    let mut pk = [0; PK_BYTES];
    let mut signature = [0; SIG_BYTES];
    assert!(canonical_and_norm(&pk, &signature));
    pk[16..23].copy_from_slice(&Q.to_le_bytes()[..7]);
    assert!(!canonical_and_norm(&pk, &signature));
    pk[16..23].fill(0);
    signature[32..39].copy_from_slice(&Q.to_le_bytes()[..7]);
    assert!(!canonical_and_norm(&pk, &signature));
    signature[32..39].fill(0);
    let hint = 32 + 9 * 256 * 7;
    signature[hint..hint + 2].copy_from_slice(&2048u16.to_le_bytes());
    assert!(!canonical_and_norm(&pk, &signature));
    signature[hint..hint + 2].fill(0);
    let mut radius = 0u128;
    let mut step = 1u128 << 63;
    while step > 0 {
        let candidate = radius + step;
        if candidate * candidate <= NORM_SQUARED {
            radius = candidate;
        }
        step >>= 1;
    }
    for sign in [false, true] {
        for (magnitude, expected) in [(radius as u64, true), (radius as u64 + 1, false)] {
            let residue = if sign { Q - magnitude } else { magnitude };
            signature[32..39].copy_from_slice(&residue.to_le_bytes()[..7]);
            assert_eq!(canonical_and_norm(&pk, &signature), expected);
        }
    }
    signature[32..39].fill(0);
    // Hint 1024 uses the upstream even-modulus midpoint convention, but its
    // scaled square alone exceeds this profile's bound and must be rejected.
    signature[hint..hint + 2].copy_from_slice(&1024u16.to_le_bytes());
    assert!(!canonical_and_norm(&pk, &signature));
}

#[test]
fn honest_python_signatures_execute_inside_actual_guest() {
    let records = records(0, 2);
    assert_eq!(record(0), record(0));
    assert_ne!(records[0].public.public_key, records[1].public.public_key);
    assert_ne!(records[0].public.message, records[1].public.message);
    for count in 1..=2 {
        let run = run_from_records(&records[..count]);
        assert_eq!(on_vm(&run).expect("honest guest exits"), run.expected);
    }
}

#[test]
fn malformed_public_keys_messages_signatures_fail_inside_actual_guest() {
    let mut record = record(0);
    let honest = run_from_records(&[record.clone()]);
    // Changed message checks the complete matrix, challenge and signature hash.
    let mut changed = honest.clone();
    changed.advice[1 + PK_WORDS] ^= 1;
    assert!(on_vm(&changed).is_err());
    // Changed signature hash independently changes challenge polynomial.
    let mut changed = honest.clone();
    changed.advice[1 + PK_WORDS + 4] ^= 1;
    assert!(on_vm(&changed).is_err());
    // Changing one canonical key byte remains inside the arithmetic relation.
    let mut changed = honest.clone();
    changed.advice[1] ^= 1;
    assert!(on_vm(&changed).is_err());
    for count in [0, MAX_BATCH as u64 + 1] {
        let mut changed = honest.clone();
        changed.advice[0] = count;
        assert!(on_vm(&changed).is_err());
    }
    record.public.public_key[16..23].copy_from_slice(&Q.to_le_bytes()[..7]);
    assert!(on_vm(&run_from_records(&[record])).is_err());
    let mut record = super::record(0);
    record.signature[32..39].copy_from_slice(&Q.to_le_bytes()[..7]);
    assert!(on_vm(&run_from_records(&[record])).is_err());
    let mut record = super::record(0);
    let hint = 32 + 9 * 256 * 7;
    record.signature[hint..hint + 2].copy_from_slice(&2048u16.to_le_bytes());
    assert!(on_vm(&run_from_records(&[record])).is_err());
}

#[test]
fn public_digest_binds_all_ordered_key_message_pairs_and_count() {
    let records = records(0, 2);
    let a = records[0].public.clone();
    let b = records[1].public.clone();
    assert_ne!(
        expected_output(core::slice::from_ref(&a)),
        expected_output(&[a.clone(), b.clone()])
    );
    assert_ne!(
        expected_output(&[a.clone(), b.clone()]),
        expected_output(&[b, a.clone()])
    );
    let mut changed = a.clone();
    changed.public_key[PK_BYTES - 1] ^= 1;
    assert_ne!(
        expected_output(core::slice::from_ref(&a)),
        expected_output(&[changed])
    );
    let mut changed = a.clone();
    changed.message[31] ^= 128;
    assert_ne!(expected_output(&[a]), expected_output(&[changed]));
}

#[test]
fn independent_python_transcript_samples_match() {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    for index in 0..3 {
        let record = record(index);
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../review/oracle-record-{index}.json"));
        let oracle: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let intermediate = &oracle["intermediate"];
        let tr = raccoong_riscv_guest::xof::shake256(&[&record.public.public_key]);
        let mu = raccoong_riscv_guest::xof::shake256(&[&tr, &record.public.message]);
        assert_eq!(hex(&tr), intermediate["tr"].as_str().unwrap());
        assert_eq!(hex(&mu), intermediate["mu"].as_str().unwrap());
        let c_hash: &[u8; 32] = record.signature[..32].try_into().unwrap();
        let c = challenge(c_hash).map(from_montgomery);
        let expected: Poly = core::array::from_fn(|j| {
            let value = intermediate["challenge"][j].as_i64().unwrap();
            if value < 0 { Q - 1 } else { value as u64 }
        });
        assert_eq!(c, expected);
        let mut matrix = [0; 256];
        matrix_poly(&record.public.public_key[..16], 0, 0, &mut matrix);
        let expected: Poly =
            core::array::from_fn(|j| intermediate["matrix_a00_ntt"][j].as_u64().unwrap());
        assert_eq!(matrix.map(from_montgomery), expected);
    }
}

#[test]
fn root_and_derived_wallet_signatures_execute_inside_actual_guest() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/hd-controls.json");
    let hd: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for name in ["m", "m/7", "m/11'"] {
        let fixture = serde_json::to_vec(&hd["nodes"][name]["signed_record"]).unwrap();
        let record = record_from_json(&fixture);
        let run = run_from_records(&[record]);
        assert_eq!(
            on_vm(&run).expect("honest derived-key guest exits"),
            run.expected
        );
    }
}

#[test]
fn exact_norm_bound_is_enforced_with_correct_challenge_equations() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/norm-controls.json");
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(data["excluded_from_benchmarks"], true);
    for case in data["cases"].as_array().unwrap() {
        let record = Record {
            public: PublicRecord {
                public_key: decode(case, "public_key"),
                message: decode(case, "message"),
            },
            signature: decode(case, "signature"),
        };
        let expected = case["expected_integer_accepts"].as_bool().unwrap();
        assert_eq!(
            verify(
                &record.public.public_key,
                &record.public.message,
                &record.signature
            ),
            expected,
            "{}",
            case["name"]
        );
        let run = run_from_records(&[record]);
        let result = on_vm(&run);
        if expected {
            assert_eq!(result.unwrap(), run.expected);
        } else {
            assert!(result.is_err(), "{}", case["name"]);
        }
    }
}
