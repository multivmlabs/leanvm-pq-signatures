#[path = "../src/recursion_support.rs"]
mod recursion_support;

use bincode::Options;
use primitives::field::F192;
use serde::Deserialize;

#[derive(Deserialize)]
struct Input {
    source: String,
    public_input: [[u64; 3]; 2],
}

fn main() {
    leanvm_core::init_prover();
    let args: Vec<_> = std::env::args().collect();
    let input: Input = serde_json::from_slice(&std::fs::read(&args[1]).unwrap()).unwrap();
    let program = lean_compiler::compile(&lean_compiler::parse(&input.source).unwrap());
    let pi = input.public_input.map(|x| F192::new(x[0], x[1], x[2]));
    let proof = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(&std::fs::read(&args[2]).unwrap())
        .unwrap();
    let child = recursion_support::child_witness(&program, pi, &proof).unwrap();
    let table: Vec<_> = leanvm_core::cpu::bytecode_table(&program.prog)
        .into_iter()
        .map(|word| word.0)
        .collect();
    let independent = verifier::Bytecode::new(&table)
        .evaluate(
            &child
                .bytecode_point
                .iter()
                .map(leanvm_core::cpu::to_scalar)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    assert_eq!(
        child.bytecode_value,
        leanvm_core::cpu::from_scalar(independent)
    );
    let mut wrong_pi = pi;
    wrong_pi[0] += F192::ONE;
    assert!(recursion_support::child_witness(&program, wrong_pi, &proof).is_err());
    let mut corrupt = proof.clone();
    corrupt.stream[0] += F192::ONE;
    assert!(recursion_support::child_witness(&program, pi, &corrupt).is_err());
    let kbc = program.prog.len().ilog2() as usize;
    let replacements = recursion_support::replacements(kbc);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "bytecode_log": kbc,
            "placeholder_count": replacements.len(),
            "point_len": child.bytecode_point.len(),
            "portable_bytecode_evaluation_agrees": true,
            "wrong_pi_rejected": true,
            "corrupt_proof_rejected": true,
            "value": [child.bytecode_value.c0, child.bytecode_value.c1, child.bytecode_value.c2],
            "pi": child.public_input.map(|x| [x.c0,x.c1,x.c2]),
            "streams": child.streams.iter().map(|(name,entries)| (name,entries.iter().map(Vec::len).collect::<Vec<_>>())).collect::<std::collections::BTreeMap<_,_>>()
        }))
        .unwrap()
    );
}
