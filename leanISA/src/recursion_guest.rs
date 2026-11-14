//! Fixed-arity recursive verification of custom leaf proofs.
//!
//! The verifier DSL is extracted at build time from leanEthereum/leanVM revision
//! 575df819d9c857f38068cecf7b1640e0ce4bfb29. The upstream source is copyright
//! (c) 2026 leanEthereum, licensed under MIT OR Apache-2.0. This extraction uses
//! its MIT license, reproduced in `third_party/leanvm-MIT.txt`.
//!
//! The recursive verifier deliberately defers one evaluation of each child's
//! bytecode polynomial. The wrapper publishes all these obligations. A receiver
//! must recompute their values from its trusted leaf program before deriving the
//! wrapper public input and verifying the wrapper proof.

use std::collections::BTreeMap;

use leanvm_core::cpu::Program;
use primitives::field::F192;

pub const DOMAIN: &[u8; 16] = b"pqbench/recagg1\0";
pub const MAX_CHILDREN: usize = 16;

const UPSTREAM_GUEST: &str =
    include_str!("../vendor/leanVM/crates/rec_aggregation/guests/lean_ethereum.py");
const WRAPPER_MAIN: &str = include_str!("../guests/aggregate_falcon.py");
const VERIFIER_END: &str =
    "# =============================== WOTS+C, both schemes ===============================";

/// The unfilled single-file guest: generic verifier plus the custom wrapper.
pub fn source() -> String {
    let (verifier, _) = UPSTREAM_GUEST
        .split_once(VERIFIER_END)
        .expect("the pinned verifier extraction boundary must exist");
    assert_eq!(verifier.matches("def verify_sub(").count(), 1);
    assert!(!verifier.contains("def main("));
    let functions_at = verifier
        .find("@inline\ndef pack64x2")
        .expect("the pinned packing helper must exist");
    let (constants, functions) = verifier.split_at(functions_at);
    let (wrapper_constants, wrapper_main) = wrapper_parts();
    format!("{constants}\n{wrapper_constants}\n{functions}\n{wrapper_main}")
}

fn wrapper_parts() -> (&'static str, &'static str) {
    WRAPPER_MAIN.split_at(
        WRAPPER_MAIN
            .find("def main():")
            .expect("the wrapper main must exist"),
    )
}

/// Structural replacements for the leaf layout and fixed wrapper statement.
pub fn replacements(
    kbc: usize,
    leaf_seed: [F192; 2],
    children: usize,
) -> Result<BTreeMap<String, String>, String> {
    validate_header(kbc, &leaf_seed, children)?;
    let mut replacements = crate::recursion_support::replacements(kbc);
    replacements.insert("AGG_CHILDREN_PLACEHOLDER".into(), children.to_string());
    for (index, value) in leaf_seed.iter().enumerate() {
        replacements.insert(
            format!("AGG_LEAF_SEED_{index}_PLACEHOLDER"),
            format!("f192({},{},{})", value.c0, value.c1, value.c2),
        );
    }
    replacements.insert(
        "AGG_DOMAIN_PLACEHOLDER".into(),
        u128::from_le_bytes(*DOMAIN).to_string(),
    );
    Ok(replacements)
}

/// Compile the exact wrapper authorized by its child seed and count.
pub fn compile(kbc: usize, leaf_seed: [F192; 2], children: usize) -> Result<Program, String> {
    let substitutions = replacements(kbc, leaf_seed, children)?;
    let ast = lean_compiler::parse_with_replacements(&source(), &substitutions)?;
    Ok(lean_compiler::compile(&ast))
}

fn validate_header(kbc: usize, leaf_seed: &[F192; 2], children: usize) -> Result<(), String> {
    if !(1..=MAX_CHILDREN).contains(&children) {
        return Err(format!("recursive child count must be 1..={MAX_CHILDREN}"));
    }
    if kbc == 0 || kbc >= 32 {
        return Err("leaf bytecode logarithm must be 1..32".into());
    }
    if leaf_seed.iter().any(|word| word.c2 != 0) {
        return Err("leaf program seed must be two canonical 128-bit cells".into());
    }
    Ok(())
}

fn append_canonical(bytes: &mut Vec<u8>, word: F192) -> Result<(), String> {
    if word.c2 != 0 {
        return Err("a digest must be encoded as canonical 128-bit cells".into());
    }
    bytes.extend_from_slice(&word.c0.to_le_bytes());
    bytes.extend_from_slice(&word.c1.to_le_bytes());
    Ok(())
}

fn append_field(bytes: &mut Vec<u8>, word: F192) {
    bytes.extend_from_slice(&word.c0.to_le_bytes());
    bytes.extend_from_slice(&word.c1.to_le_bytes());
    bytes.extend_from_slice(&word.c2.to_le_bytes());
}

/// Exact bytes hashed in-circuit, including every deferred evaluation value.
///
/// The header is domain16 || child_count_LE128 || child_program_seed32. Each
/// child contributes public_input32 then its bytecode point and claimed value,
/// every field element encoded as three LE64 limbs. `pack_pair` puts two field
/// elements into three canonical hash cells, so an odd number of fields is
/// followed by one zero field element, not merely one zero limb.
pub fn statement_preimage(
    kbc: usize,
    leaf_seed: [F192; 2],
    child_pi: &[[F192; 2]],
    points: &[Vec<F192>],
    values: &[F192],
) -> Result<Vec<u8>, String> {
    validate_header(kbc, &leaf_seed, child_pi.len())?;
    if points.len() != child_pi.len() || values.len() != child_pi.len() {
        return Err("one deferred point and value are required per child".into());
    }
    let variables = kbc + leanvm_core::leaf::N_BYTECODE_SELECTORS;
    let fields = variables + 1;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&(child_pi.len() as u128).to_le_bytes());
    for word in leaf_seed {
        append_canonical(&mut bytes, word)?;
    }
    for ((public, point), value) in child_pi.iter().zip(points).zip(values) {
        if point.len() != variables {
            return Err(format!(
                "deferred bytecode point must have {variables} coordinates"
            ));
        }
        for &word in public {
            append_canonical(&mut bytes, word)?;
        }
        for &coordinate in point {
            append_field(&mut bytes, coordinate);
        }
        append_field(&mut bytes, *value);
        if !fields.is_multiple_of(2) {
            append_field(&mut bytes, F192::ZERO);
        }
    }
    Ok(bytes)
}

pub fn public_input(
    kbc: usize,
    leaf_seed: [F192; 2],
    child_pi: &[[F192; 2]],
    points: &[Vec<F192>],
    values: &[F192],
) -> Result<[F192; 2], String> {
    let digest = primitives::hash::hash(&statement_preimage(
        kbc, leaf_seed, child_pi, points, values,
    )?);
    let word = |at: usize| u64::from_le_bytes(digest[at..at + 8].try_into().unwrap());
    Ok([
        F192::new(word(0), word(8), 0),
        F192::new(word(16), word(24), 0),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_keeps_top_limbs_and_odd_field_padding() {
        let kbc = 18;
        let mut point = vec![F192::ZERO; kbc + leanvm_core::leaf::N_BYTECODE_SELECTORS];
        point[0] = F192::new(3, 5, 7);
        let seed = [F192::new(11, 13, 0), F192::new(17, 19, 0)];
        let pi = [[F192::new(23, 29, 0), F192::new(31, 37, 0)]];
        let value = F192::new(41, 43, 47);
        let preimage = statement_preimage(kbc, seed, &pi, &[point.clone()], &[value]).unwrap();
        assert_eq!(preimage.len(), 64 + 32 + 24 * 24);
        assert_eq!(
            &preimage[96..120],
            &[3u64, 5, 7]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(&preimage[preimage.len() - 24..], &[0; 24]);
        point[0].c2 ^= 1;
        let changed = statement_preimage(kbc, seed, &pi, &[point], &[value]).unwrap();
        assert_ne!(preimage, changed);
    }

    #[test]
    fn native_statement_encoding_matches_the_actual_guest_packing() {
        let start = UPSTREAM_GUEST.find("@inline\ndef pack64x2").unwrap();
        let end = UPSTREAM_GUEST
            .find("@inline\ndef challenge_from_state")
            .unwrap();
        let packers = &UPSTREAM_GUEST[start..end];
        for (kbc, children) in [(18, 1), (17, 2)] {
            let variables = kbc + leanvm_core::leaf::N_BYTECODE_SELECTORS;
            let fields = variables + 1;
            let seed = [F192::new(11, 13, 0), F192::new(17, 19, 0)];
            let pis: Vec<_> = (0..children)
                .map(|i| {
                    [
                        F192::new(23 + i as u64, 29, 0),
                        F192::new(31, 37 + i as u64, 0),
                    ]
                })
                .collect();
            let points: Vec<_> = (0..children)
                .map(|i| {
                    (0..variables)
                        .map(|j| F192::new((i + 1) as u64, (j + 2) as u64, ((j + 3) * 7) as u64))
                        .collect()
                })
                .collect();
            let values: Vec<_> = (0..children)
                .map(|i| F192::new(41 + i as u64, 43, 47))
                .collect();
            let pi = public_input(kbc, seed, &pis, &points, &values).unwrap();
            let (wrapper_constants, wrapper_main) = wrapper_parts();
            let stub = format!(
                "from snark_lib import *\nY_TOWER = f192(0,1,0)\nY_INV = f192(1,0,1)\nDEFER_SIZE = {fields}\nDEFER_STMT_CELLS = {fields}\n\n{wrapper_constants}\n{packers}\n\
                 def exponent_tables():\n    return 0, 0\n\n\
                 def verify_sub(pi0, pi1, seed0, seed1, logs, squares, deferred):\n    hint_witness(deferred[0:{fields}], \"test_deferred\")\n    return\n\n{wrapper_main}"
            );
            let mut substitutions = BTreeMap::new();
            substitutions.insert("AGG_CHILDREN_PLACEHOLDER".into(), children.to_string());
            substitutions.insert("AGG_LEAF_SEED_0_PLACEHOLDER".into(), "f192(11,13,0)".into());
            substitutions.insert("AGG_LEAF_SEED_1_PLACEHOLDER".into(), "f192(17,19,0)".into());
            substitutions.insert(
                "AGG_DOMAIN_PLACEHOLDER".into(),
                u128::from_le_bytes(*DOMAIN).to_string(),
            );
            let ast = lean_compiler::parse_with_replacements(&stub, &substitutions).unwrap();
            let mut program = lean_compiler::compile(&ast);
            program.set_witness(
                "aggregate_child_pi",
                pis.iter().map(|p| p.to_vec()).collect(),
            );
            program.set_witness(
                "test_deferred",
                points
                    .iter()
                    .zip(&values)
                    .map(|(point, &value)| {
                        let mut fields = point.clone();
                        fields.push(value);
                        fields
                    })
                    .collect(),
            );
            let execution = program.execute(pi).unwrap();
            assert!(execution.unconstrained_reads.is_empty());
        }
    }

    #[test]
    #[ignore = "requires the generated ETHFALCON leaf program and proves two bounded negative-control fixtures"]
    fn deferred_evaluation_is_required_for_root_authorization() {
        use leanvm_core::cpu::{Op, fs_seed, prove, scalar_proof, to_scalar, verify};
        use primitives::field::g_pow;

        leanvm_core::init_prover();
        let leaf_source = std::fs::read_to_string("artifacts/falcon-30-recursive/leaf-program.py")
            .expect("generate the 30-signature experiment's leaf program first");
        let expected_leaf = lean_compiler::compile(&lean_compiler::parse(&leaf_source).unwrap());
        let kbc = expected_leaf.prog.len().trailing_zeros() as usize;
        let expected_seed = fs_seed(&expected_leaf);
        let pi = [F192::new(101, 103, 0), F192::new(107, 109, 0)];

        // Prover APIs are not a security boundary. Keep A's cached transcript
        // seed but supply a valid execution of a different, same-size program B.
        // B only halts and therefore proves no ETHFALCON signature relation.
        let mut inconsistent = expected_leaf.clone();
        inconsistent.prog.fill(Op::Xor { a: 0, b: 0, c: 0 });
        inconsistent.prog[0] = Op::Set {
            o: 50_000,
            k: F192::from(g_pow(inconsistent.prog.len() - 1)),
        };
        inconsistent.prog[1] = Op::Set {
            o: 50_001,
            k: F192::ONE,
        };
        inconsistent.prog[2] = Op::Jump {
            oc: 50_001,
            od: 50_000,
            of: 50_001,
        };
        inconsistent.min_log_committed = 22;
        assert_eq!(fs_seed(&inconsistent), expected_seed);
        let execution = inconsistent.execute(pi).unwrap();
        assert_eq!(execution.cycles, 3);
        assert!(execution.unconstrained_reads.is_empty());
        let (inconsistent_proof, _) = prove(&inconsistent, pi, 1).unwrap();
        let rejected = verify(&expected_leaf, &pi, &inconsistent_proof)
            .expect_err("the full native verifier must reject the wrong bytecode");
        let table: Vec<u64> = leanvm_core::cpu::bytecode_table(&expected_leaf.prog)
            .into_iter()
            .map(|word| word.0)
            .collect();
        let expected_bytecode = verifier::Bytecode::new(&table);
        let replay = verifier::replay_unchecked(
            &expected_bytecode,
            &leanvm_core::cpu::public_input_bytes(&pi),
            &scalar_proof(&inconsistent_proof),
        )
        .expect("unchecked replay is not checked verification");
        let correct_value = leanvm_core::cpu::from_scalar(
            expected_bytecode.evaluate(&replay.bytecode_point).unwrap(),
        );
        let prepared = crate::recursion_support::child_witness_replay_unchecked_for_test(
            &inconsistent,
            &expected_bytecode,
            pi,
            &inconsistent_proof,
        )
        .unwrap();
        assert_ne!(prepared.bytecode_value, correct_value);
        let points = [prepared.bytecode_point];
        let dishonest_pi = public_input(
            kbc,
            expected_seed,
            &[pi],
            &points,
            &[prepared.bytecode_value],
        )
        .unwrap();
        let authorized_pi =
            public_input(kbc, expected_seed, &[pi], &points, &[correct_value]).unwrap();
        assert_ne!(dishonest_pi, authorized_pi);
        let mut wrapper = compile(kbc, expected_seed, 1).unwrap();
        for (name, entries) in prepared.streams {
            wrapper.set_witness(name, entries);
        }
        wrapper.set_witness("aggregate_child_pi", vec![pi.to_vec()]);
        let partial = wrapper.execute(dishonest_pi).unwrap();
        assert!(partial.unconstrained_reads.is_empty());
        let (wrapper_proof, _) = prove(&wrapper, dishonest_pi, 1).unwrap();
        verify(&wrapper, &dishonest_pi, &wrapper_proof).unwrap();
        let root_rejection = verify(&wrapper, &authorized_pi, &wrapper_proof)
            .expect_err("recomputing the expected bytecode value must reject the false root");

        let output = serde_json::json!({
            "expected_child_kbc": kbc,
            "different_program_cycles": execution.cycles,
            "full_native_child_verifier_rejects": format!("{rejected:?}"),
            "unchecked_replay_succeeds": true,
            "recursive_partial_verifier_execution_accepts": true,
            "wrapper_proof_verifies_against_prover_value": true,
            "wrapper_proof_rejected_after_expected_bytecode_evaluation": format!("{root_rejection:?}"),
            "correct_value": [correct_value.c0, correct_value.c1, correct_value.c2],
            "prover_value": [prepared.bytecode_value.c0, prepared.bytecode_value.c1, prepared.bytecode_value.c2],
            "point": points[0].iter().map(|x| [x.c0,x.c1,x.c2]).collect::<Vec<_>>(),
            "child_proof_bytes": bincode::serialized_size(&inconsistent_proof).unwrap(),
            "wrapper_proof_bytes": bincode::serialized_size(&wrapper_proof).unwrap(),
            "scope": "test-only malicious prover control demonstrates the required outer bytecode evaluation; not a backend soundness attack"
        });
        let directory = std::path::Path::new("results/falcon-30-recursive");
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            directory.join("deferred-boundary.json"),
            serde_json::to_vec_pretty(&output).unwrap(),
        )
        .unwrap();
        println!("native bytecode evaluation rejected a genuinely proven partial-verifier forgery");
        // Keep the conversion used above tied to the public native field bridge.
        assert_eq!(
            to_scalar(&correct_value),
            expected_bytecode.evaluate(&replay.bytecode_point).unwrap()
        );
    }
}
