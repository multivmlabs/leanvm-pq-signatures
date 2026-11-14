use super::*;
use leanvm::{Machine, Program};
use raccoong_segmented_guest::{PK_BYTES, global_checks, verify_row, w_coefficient};

fn on_vm(run: &Run) -> Result<[u64; 4], leanvm::Trap> {
    let program = Program::from_elf(ELF).unwrap();
    Machine::new(program.rv(), &run.advice).run()
}

#[test]
fn every_row_of_three_original_records_accepts_and_matches_python_commitment() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap();
    for index in 0..3 {
        let raw = record(index);
        let prepared = prepare(&raw);
        let oracle: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join(format!(
                "risc-v/raccoon-g/review/oracle-record-{index}.json"
            )))
            .unwrap(),
        )
        .unwrap();
        for row in 0..ROW_COUNT {
            for j in 0..256 {
                assert_eq!(
                    w_coefficient(&prepared.w, row * 256 + j),
                    oracle["intermediate"]["w"][row][j].as_u64().unwrap()
                );
            }
            assert!(verify_row(
                &prepared.public.public_key,
                &prepared.public.message,
                &prepared.signature,
                &prepared.w,
                row
            ));
        }
        for part in 0..PARTS_PER_SIGNATURE {
            let run = row_run(&prepared, part);
            assert_eq!(on_vm(&run).unwrap(), run.expected);
        }
    }
}

#[test]
fn malformed_global_inputs_and_selected_row_equations_fail_in_actual_elf() {
    let original = prepare(&record(0));
    let mut cases = Vec::new();
    let mut key = original.clone();
    key.public.public_key[PK_BYTES - 7] ^= 1;
    cases.push(key);
    let mut message = original.clone();
    message.public.message[31] ^= 1;
    cases.push(message);
    let mut challenge = original.clone();
    challenge.signature[0] ^= 1;
    cases.push(challenge);
    let mut response = original.clone();
    response.signature[32] ^= 1;
    cases.push(response);
    let mut hint = original.clone();
    hint.signature[32 + 9 * 256 * 7] ^= 1;
    cases.push(hint);
    let mut w = original.clone();
    w.w[0] ^= 1;
    cases.push(w);
    let mut high_w = original.clone();
    high_w.w[W_WORDS - 1] |= 2048 << 48;
    cases.push(high_w);
    let q = 562949953438721u64.to_le_bytes();
    let mut bad_pk = original.clone();
    bad_pk.public.public_key[16..23].copy_from_slice(&q[..7]);
    cases.push(bad_pk);
    let mut bad_z = original.clone();
    bad_z.signature[32..39].copy_from_slice(&q[..7]);
    cases.push(bad_z);
    let mut bad_hint = original.clone();
    bad_hint.signature[32 + 9 * 256 * 7..32 + 9 * 256 * 7 + 2]
        .copy_from_slice(&2048u16.to_le_bytes());
    cases.push(bad_hint);
    for mut invalid in cases {
        invalid.binding = raccoong_segmented_guest::binding(&invalid.signature, &invalid.w);
        assert!(!verify_row(
            &invalid.public.public_key,
            &invalid.public.message,
            &invalid.signature,
            &invalid.w,
            0
        ));
        assert!(on_vm(&row_run(&invalid, 0)).is_err());
    }
    let mut invalid_row = row_run(&original, 0);
    invalid_row.advice[0] = PARTS_PER_SIGNATURE as u64;
    assert!(on_vm(&invalid_row).is_err());
}

#[test]
fn an_unselected_hint_change_is_only_a_partial_claim_with_a_new_binding() {
    let original = prepare(&record(0));
    let mut partial = original.clone();
    let offset = 32 + 9 * 256 * 7 + 2 * (8 * 256);
    let h = u16::from_le_bytes(partial.signature[offset..offset + 2].try_into().unwrap());
    partial.signature[offset..offset + 2].copy_from_slice(&((h + 1) % 2048).to_le_bytes());
    partial.binding = raccoong_segmented_guest::binding(&partial.signature, &partial.w);
    assert_ne!(partial.binding, original.binding);
    assert_ne!(&partial.binding[..4], &original.binding[..4]);
    assert_ne!(&partial.binding[4..], &original.binding[4..]);
    assert!(global_checks(
        &partial.public.public_key,
        &partial.public.message,
        &partial.signature,
        &partial.w
    ));
    assert!(verify_row(
        &partial.public.public_key,
        &partial.public.message,
        &partial.signature,
        &partial.w,
        0
    ));
    assert!(!verify_row(
        &partial.public.public_key,
        &partial.public.message,
        &partial.signature,
        &partial.w,
        8
    ));
    let good_partial = row_run(&partial, 0);
    assert_eq!(on_vm(&good_partial).unwrap(), good_partial.expected);
    assert_ne!(good_partial.expected, row_run(&original, 0).expected);
    assert!(on_vm(&row_run(&partial, 4)).is_err());
}

#[test]
fn expected_outputs_bind_public_pair_row_and_both_digest_halves() {
    let prepared = prepare(&record(0));
    let expected = expected_row_output(&prepared.public, 0, &prepared.binding);
    assert_ne!(
        expected,
        expected_row_output(&prepared.public, 1, &prepared.binding)
    );
    for index in [0, 3, 4, 7] {
        let mut binding = prepared.binding;
        binding[index] ^= 1;
        assert_ne!(expected, expected_row_output(&prepared.public, 0, &binding));
    }
    let mut public = prepared.public.clone();
    public.public_key[PK_BYTES - 1] ^= 1;
    assert_ne!(expected, expected_row_output(&public, 0, &prepared.binding));
    public = prepared.public.clone();
    public.message[31] ^= 1;
    assert_ne!(expected, expected_row_output(&public, 0, &prepared.binding));
}

fn decode<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N);
    core::array::from_fn(|index| u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap())
}

#[test]
fn independent_python_codec_and_challenge_consistent_norm_controls_match_actual_elf() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let controls: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("review/codec-controls.json")).unwrap())
            .unwrap();
    for (index, case) in controls["cases"].as_array().unwrap().iter().enumerate() {
        let w_bytes = decode::<4608>(case["w_le16"].as_str().unwrap());
        let binding_bytes = decode::<64>(case["binding"].as_str().unwrap());
        let prepared = PreparedRecord {
            public: PublicRecord {
                public_key: decode(case["public_key"].as_str().unwrap()),
                message: decode(case["message"].as_str().unwrap()),
            },
            signature: decode(case["signature"].as_str().unwrap()),
            w: core::array::from_fn(|i| {
                u64::from_le_bytes(w_bytes[8 * i..8 * i + 8].try_into().unwrap())
            }),
            binding: core::array::from_fn(|i| {
                u64::from_le_bytes(binding_bytes[8 * i..8 * i + 8].try_into().unwrap())
            }),
        };
        assert_eq!(
            raccoong_segmented_guest::binding(&prepared.signature, &prepared.w),
            prepared.binding
        );
        let accepts = case["expected_integer_accepts"].as_bool().unwrap();
        for part in 0..PARTS_PER_SIGNATURE {
            let expected = decode::<32>(case["expected_part_outputs"][part].as_str().unwrap());
            let actual = expected_row_output(&prepared.public, part, &prepared.binding);
            let expected: [u64; 4] = core::array::from_fn(|i| {
                u64::from_le_bytes(expected[8 * i..8 * i + 8].try_into().unwrap())
            });
            assert_eq!(actual, expected, "independent Python public codec");
            assert_eq!(
                raccoong_segmented_guest::verify_part(
                    &prepared.public.public_key,
                    &prepared.public.message,
                    &prepared.signature,
                    &prepared.w,
                    part
                ),
                accepts
            );
        }
        // The ordinary records already exercise every part above. These seven
        // algebraic cases specifically require the exact norm check to reject.
        if index >= 3 {
            let run = row_run(&prepared, index % PARTS_PER_SIGNATURE);
            match on_vm(&run) {
                Ok(output) => {
                    assert!(accepts);
                    assert_eq!(output, run.expected);
                }
                Err(_) => assert!(!accepts),
            }
        }
    }
}
