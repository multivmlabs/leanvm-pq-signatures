//! Small-table execution controls, independent of the recursive wrapper.
use std::path::Path;

use crate::reduction::{self, Claim, Round};
use primitives::field::{F64, F192};
use serde_json::Value;

fn field(v: &Value) -> F192 {
    let c = v.as_array().expect("three field limbs");
    assert_eq!(c.len(), 3);
    F192::new(
        c[0].as_u64().unwrap(),
        c[1].as_u64().unwrap(),
        c[2].as_u64().unwrap(),
    )
}

fn digest(v: &Value) -> [F192; 2] {
    let text = v.as_str().unwrap();
    let raw: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(raw.len(), 32);
    let lane = |i| u64::from_le_bytes(raw[i..i + 8].try_into().unwrap());
    [
        F192::new(lane(0), lane(8), 0),
        F192::new(lane(16), lane(24), 0),
    ]
}

#[test]
fn native_prover_matches_independent_python_field_and_transcript_vectors() {
    let vectors: Value =
        serde_json::from_str(include_str!("../review/oracle-vectors.json")).unwrap();
    for vector in vectors["vectors"].as_array().unwrap() {
        let table: Vec<_> = vector["table"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let v = field(v);
                assert_eq!((v.c1, v.c2), (0, 0));
                F64(v.c0)
            })
            .collect();
        let claims: Vec<_> = vector["points"]
            .as_array()
            .unwrap()
            .iter()
            .zip(vector["values"].as_array().unwrap())
            .map(|(p, v)| Claim {
                point: p.as_array().unwrap().iter().map(field).collect(),
                value: field(v),
            })
            .collect();
        let program = digest(&vector["poly_id_hex"]);
        let context = digest(&vector["context_hex"]);
        assert_eq!(
            reduction::initial_state(program, context, &claims).unwrap(),
            digest(&vector["instance_digest_hex"])
        );
        let proof = reduction::prove(&table, program, context, &claims).unwrap();
        let rounds: Vec<_> = vector["rounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| Round {
                c0: field(&r[0]),
                c2: field(&r[1]),
            })
            .collect();
        assert_eq!(proof.rounds, rounds);
        assert_eq!(
            proof.reduced.point,
            vector["new_point"]
                .as_array()
                .unwrap()
                .iter()
                .map(field)
                .collect::<Vec<_>>()
        );
        assert_eq!(proof.reduced.value, field(&vector["new_value"]));
        reduction::verify_link(program, context, &claims, &proof).unwrap();
        reduction::check_terminal(&table, &proof.reduced).unwrap();
    }
}

#[test]
fn constrained_guest_checks_reduction_and_actual_terminal_table() {
    let summary: Value = serde_json::from_str(include_str!("controls/summary.json")).unwrap();
    assert_eq!(summary["all_passed"], true);
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("guest/controls");
    let mut accepted = 0;
    let mut rejected = 0;
    for case in summary["cases"].as_array().unwrap() {
        let fixture: Value = serde_json::from_slice(
            &std::fs::read(
                directory.join(format!("{}.input.json", case["case"].as_str().unwrap())),
            )
            .unwrap(),
        )
        .unwrap();
        let source = fixture["source"].as_str().unwrap();
        assert!(
            source.starts_with(include_str!("sumcheck.py")),
            "regenerate stale controls after guest changes"
        );
        let ast = lean_compiler::parse(source).unwrap();
        let mut program = lean_compiler::compile(&ast);
        for (name, entries) in fixture["witness"].as_object().unwrap() {
            let rows = entries
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row.as_array().unwrap().iter().map(field).collect())
                .collect();
            program.set_witness(name, rows);
        }
        let succeeds = program
            .execute([F192::ZERO; 2])
            .is_ok_and(|run| run.unconstrained_reads.is_empty());
        let expected = case["expected_accept"].as_bool().unwrap();
        assert_eq!(succeeds, expected, "{}", case["case"]);
        if succeeds {
            accepted += 1
        } else {
            rejected += 1
        }
    }
    assert_eq!((accepted, rejected), (24, 69));
}
