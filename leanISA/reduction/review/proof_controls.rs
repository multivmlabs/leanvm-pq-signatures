//! Actual two-level recursive forgery control for the production receipt API.
//!
//! The malicious producer changes its execution bytecode while retaining the
//! approved program's cached Fiat-Shamir seed. The old recursive core defers
//! precisely the check that detects this. Every wrapper proof below is a real
//! STARK of the unchanged approved wrapper code. Only producer-side preparation
//! uses the deliberately wrong table; the final receiver remains unchanged.

use std::{fs, path::Path};

use leanvm_core::cpu::{self, Op, Proof};
use primitives::field::{F192, g_pow};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    pipeline, receipt, recursion_support,
    wrapper::{self, Family, State},
};

const APPROVED_LEAF: &str = "from snark_lib import *\n\ndef main():\n    public = GEN ** 0\n    public[1] = 7\n    public[GEN] = 9\n    return\n";

fn prove_prepared(family: &Family, prepared: &pipeline::PreparedMerge) -> Proof {
    let mut program = family.program.clone();
    for (name, rows) in &prepared.streams {
        program.set_witness(name, rows.clone());
    }
    let executed = program
        .execute(prepared.public_input)
        .expect("constrained recursive execution");
    assert!(executed.unconstrained_reads.is_empty());
    let (proof, _) = cpu::prove(&program, prepared.public_input, 1).expect("actual wrapper STARK");
    cpu::verify(&family.program, &prepared.public_input, &proof)
        .expect("full native wrapper proof");
    proof
}

fn envelope(
    policy: [F192; 2],
    families: &[Family],
    state: State,
    proof: Proof,
) -> receipt::Envelope {
    receipt::Envelope {
        magic: receipt::MAGIC,
        signatures: 4,
        slots: 4,
        depth: 2,
        policy,
        leaf_seed: families[0].seed,
        root_seed: families[2].seed,
        state,
        proof,
    }
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
#[ignore = "produces six real proofs and exercises a two-level malicious producer; run after benchmark jobs"]
fn false_bytecode_claim_survives_two_real_wrappers_but_complete_consumer_rejects() {
    leanvm_core::init_prover();
    let (policy, approved) = wrapper::build(APPROVED_LEAF, 2, 1).expect("approved bottom-up key");
    assert!(approved[0].program.prog.len() >= 4);

    // Honest positive control with the same approved leaf and wrapper keys.
    let honest_pi = [F192::new(7, 0, 0), F192::new(9, 0, 0)];
    let (honest_leaf, _) = cpu::prove(&approved[0].program, honest_pi, 1).unwrap();
    cpu::verify(&approved[0].program, &honest_pi, &honest_leaf).unwrap();
    let honest_state = State {
        claim_digest: honest_pi,
        accumulators: vec![],
    };
    let first = pipeline::prepare(
        policy,
        &approved[..1],
        &[honest_state.clone(), honest_state],
        &[honest_leaf.clone(), honest_leaf],
    )
    .unwrap();
    let first_proof = prove_prepared(&approved[1], &first);
    let second = pipeline::prepare(
        policy,
        &approved[..2],
        &[first.state.clone(), first.state.clone()],
        &[first_proof.clone(), first_proof],
    )
    .unwrap();
    let second_proof = prove_prepared(&approved[2], &second);
    let honest = envelope(policy, &approved, second.state.clone(), second_proof);
    let honest_semantic =
        wrapper::claim_digest(&[first.state.claim_digest, first.state.claim_digest]).unwrap();
    let honest_verifier = receipt::Verifier::new(policy, &approved, honest_semantic, 4, 4).unwrap();
    assert_eq!(
        honest_verifier
            .verify(&honest)
            .unwrap()
            .terminal_evaluations,
        2
    );

    // This requested statement is false for APPROVED_LEAF. The malicious
    // producer nevertheless proves a three-step halt using the approved IV.
    let false_pi = [F192::new(101, 103, 0), F192::new(107, 109, 0)];
    assert!(approved[0].program.execute(false_pi).is_err());
    let mut wrong_program = approved[0].program.clone();
    wrong_program.prog.fill(Op::Xor { a: 0, b: 0, c: 0 });
    let halt = wrong_program.prog.len() - 1;
    wrong_program.prog[0] = Op::Set {
        o: 50_000,
        k: F192::from(g_pow(halt)),
    };
    wrong_program.prog[1] = Op::Set {
        o: 50_001,
        k: F192::ONE,
    };
    wrong_program.prog[2] = Op::Jump {
        oc: 50_001,
        od: 50_000,
        of: 50_001,
    };
    assert_eq!(cpu::fs_seed(&wrong_program), approved[0].seed);
    let wrong_run = wrong_program.execute(false_pi).unwrap();
    assert_eq!(wrong_run.cycles, 3);
    assert!(wrong_run.unconstrained_reads.is_empty());
    let (wrong_leaf, _) = cpu::prove(&wrong_program, false_pi, 1).unwrap();
    let original_rejection = cpu::verify(&approved[0].program, &false_pi, &wrong_leaf)
        .expect_err("full child verifier detects wrong bytecode");

    let expected_bytecode =
        verifier::Bytecode::new(&approved[0].table.iter().map(|x| x.0).collect::<Vec<_>>());
    let replay = || {
        recursion_support::child_witness_replay_unchecked_for_test(
            &wrong_program,
            &expected_bytecode,
            false_pi,
            &wrong_leaf,
        )
        .unwrap()
    };
    let sampled = replay();
    let true_value = cpu::from_scalar(
        expected_bytecode
            .evaluate(
                &sampled
                    .bytecode_point
                    .iter()
                    .map(cpu::to_scalar)
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
    );
    assert_ne!(sampled.bytecode_value, true_value);

    // A producer may compute a sumcheck using an arbitrary table. This cannot
    // authorize that table: its program ID stays A, and the receiver rebuilds A.
    let mut producer_families = approved.clone();
    producer_families[0].table = cpu::bytecode_table(&wrong_program.prog);
    let false_state = State {
        claim_digest: false_pi,
        accumulators: vec![],
    };
    let false_first = pipeline::compose(
        policy,
        &producer_families[..1],
        &[false_state.clone(), false_state],
        vec![sampled, replay()],
    )
    .unwrap();
    let false_first_proof = prove_prepared(&approved[1], &false_first);

    // The first wrapper is a valid proof of its own execution, including its
    // sumcheck, even though it carries a false inherited A-table evaluation.
    // Normal child admission therefore accepts it at the next level. That is
    // expected: eventual settlement must be applied after all reductions.
    let false_second = pipeline::prepare(
        policy,
        &producer_families[..2],
        &[false_first.state.clone(), false_first.state.clone()],
        &[false_first_proof.clone(), false_first_proof],
    )
    .unwrap();
    let false_second_proof = prove_prepared(&approved[2], &false_second);
    let forged = envelope(
        policy,
        &approved,
        false_second.state.clone(),
        false_second_proof,
    );
    let false_semantic = wrapper::claim_digest(&[
        false_first.state.claim_digest,
        false_first.state.claim_digest,
    ])
    .unwrap();
    let final_verifier = receipt::Verifier::new(policy, &approved, false_semantic, 4, 4).unwrap();
    let Err(final_rejection) = final_verifier.verify(&forged) else {
        panic!("eventual true-table evaluation must reject the inherited false claim");
    };
    assert_eq!(final_rejection, "terminal family 0 is false");

    // Transport goes through the same strict production codec before receipt
    // verification. Root metadata or a stale pin cannot explain this rejection.
    let encoded = receipt::encode(&forged).unwrap();
    let decoded = receipt::decode(&encoded).unwrap();
    let Err(decoded_rejection) = final_verifier.verify(&decoded) else {
        panic!("decoded false claim must still reject");
    };
    assert_eq!(decoded_rejection, final_rejection);
    let honest_bytes = receipt::encode(&honest).unwrap();
    assert!(
        honest_verifier
            .verify(&receipt::decode(&honest_bytes).unwrap())
            .is_ok()
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(receipt::decode(&trailing).is_err());

    let output = Path::new(env!("CARGO_MANIFEST_DIR")).join("review/proof-controls");
    fs::create_dir_all(&output).unwrap();
    fs::write(output.join("honest-two-level.proof"), &honest_bytes).unwrap();
    fs::write(output.join("false-inherited-two-level.proof"), &encoded).unwrap();
    fs::write(output.join("approved-leaf.py"), APPROVED_LEAF).unwrap();
    let report = json!({
        "schema": 1,
        "backend_revision": "575df819d9c857f38068cecf7b1640e0ce4bfb29",
        "approved_leaf_source_sha256": sha256(APPROVED_LEAF.as_bytes()),
        "honest_complete_two_level_receiver_accepts": true,
        "false_leaf_full_native_rejection": format!("{original_rejection:?}"),
        "wrong_leaf_cycles": wrong_run.cycles,
        "actual_wrapper_proofs_produced": 4,
        "actual_leaf_proofs_produced": 2,
        "false_claim_carried_through_two_approved_wrappers": true,
        "both_malicious_wrapper_executions_have_no_unconstrained_reads": true,
        "both_malicious_wrapper_proofs_verify_under_approved_wrapper_code": true,
        "final_production_receiver_rejection": final_rejection,
        "honest_root_sha256": sha256(&honest_bytes),
        "dishonest_root_sha256": sha256(&encoded),
        "terminal_evaluations_required": 2,
        "codec_rejects_appended_bytes": true,
        "scope": "Actual generic recursion/reduction integration control using a small approved leaf relation. It is not a signature forgery or full backend soundness audit."
    });
    fs::write(
        output.join("two-level-malicious.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "two real reduction layers retain a false inherited bytecode claim until the complete trusted-table receiver rejects it"
    );
}
