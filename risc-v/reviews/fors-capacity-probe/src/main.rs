use leanvm::{CircuitId, Machine, PerTable, Program, TableId};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs};

fn main() {
    let elf_hash:String=Sha256::digest(fors_host::ELF).iter().map(|b|format!("{b:02x}")).collect();
    assert_eq!(elf_hash,"64480a3bf424f97578f6477a7a4045c2452853a0801f45fc191648eb253e36da");
    let program = Program::from_elf(fors_host::ELF).unwrap();
    // These addresses are read from the exact checked-in ELF's symbol table.
    let start = 0x1000_1164u64;
    let end = start + 2448;
    let tables: Vec<_> = program.rv().entries().iter().map(|e|TableId::of(e.class)).collect();
    let mut reports=Vec::new();
    for n in [1usize,7,8,9,16] {
        let input = fors_host::batch(n);
        let mut machine=Machine::new(program.rv(),&input.advice);
        let mut counts=PerTable::<usize>::default();
        let mut permutations=0usize;
        let mut permutation_cycles=0usize;
        while !machine.halted() {
            let pc=machine.pc();
            if pc==start { permutations+=1; }
            if (start..end).contains(&pc) {permutation_cycles+=1;}
            let step=machine.step().unwrap();
            counts[tables[step.index].unwrap()]+=1;
        }
        assert_eq!(machine.output().unwrap(),input.expected);
        assert_eq!(permutations,150*n);
        let heights=PerTable::from_fn(|t:TableId|t.spec().provable_height(counts[t]));
        let packed:usize=CircuitId::ALL.iter().map(|c|heights[c.table()] << c.stride_log()).sum();
        let by_circuit:Vec<_>=CircuitId::ALL.iter().map(|c|json!({"table":c.table().name(),"part":format!("{:?}",c.part()),"stride_words":1usize<<c.stride_log(),"lower_bound_words":heights[c.table()] << c.stride_log()})).collect();
        let row=json!({"count":n,"output_matches":true,"cycles":counts.values().sum::<usize>(),"keccak_permutations":permutations,"permutation_cycles":permutation_cycles,
            "class_rows":counts.iter().map(|(t,v)|(t.name(),*v)).collect::<BTreeMap<_,_>>(),
            "independent_padded_heights":heights.iter().map(|(t,v)|(t.name(),*v)).collect::<BTreeMap<_,_>>(),
            "packed_witness_lower_bound_words":packed,"circuit_costs":by_circuit,
            "measure_result":format!("{:?}",program.measure(&input.advice).map(|s|s.committed)),
            "scope":"Full unchanged ELF reference-interpreter execution, including past the prover size guard; packed witnesses only are a conservative lower bound, not a proof or exact layout."});
        println!("n{n}: {row}");reports.push(row);
    }
    fs::write("risc-v/reviews/fors-capacity-probe/results.json",serde_json::to_vec_pretty(&reports).unwrap()).unwrap();
}
