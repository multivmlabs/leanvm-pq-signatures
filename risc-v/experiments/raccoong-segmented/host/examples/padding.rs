//! Actual final-ELF instruction check for the disjoint fixed trace padding.
use leanvm::{Machine, PerTable, Program, TableId};
use raccoong_segmented_host::{ELF, TRACE_PADDING_STORES, prepare, record, row_run};
use serde_json::json;
use std::{collections::BTreeMap, fs};

fn main() {
    let output = std::env::args().nth(1).expect("output JSON");
    let record = record(3);
    let prepared = prepare(&record);
    let run = row_run(&prepared, 4);
    let program = Program::from_elf(ELF).unwrap();
    let mut machine = Machine::new(program.rv(), &run.advice);
    let mut padding_rows = PerTable::<usize>::default();
    let mut volatile_stores = 0usize;
    // Addresses are independently read from the pinned final ELF with LLVM nm
    // and objdump. The function contains exactly one sd site and a fixed loop.
    while !machine.halted() {
        let pc = machine.pc();
        let step = machine.step().unwrap();
        if (0x10000038..0x1000005c).contains(&pc) {
            let table = TableId::of(program.rv().entries()[step.index].class).unwrap();
            padding_rows[table] += 1;
        }
        if pc == 0x10000048 {
            volatile_stores += 1;
        }
    }
    assert_eq!(machine.output().unwrap(), run.expected);
    assert_eq!(volatile_stores, TRACE_PADDING_STORES);
    assert_eq!(padding_rows[TableId::SD], TRACE_PADDING_STORES);
    let stats = program.measure(&run.advice).unwrap();
    let report = json!({
        "scope":"Final raw ELF and production measure; no STARK; signature3 part4 old shape outlier",
        "signature":3,"part":4,"volatile_stores":volatile_stores,
        "padding_function_rows":padding_rows.iter().map(|(t,n)|(t.name(),*n)).collect::<BTreeMap<_,_>>(),
        "output_unchanged":true,"committed_words":stats.committed,
        "base_sd":stats.base_counts[TableId::SD],"padded_sd":stats.counts[TableId::SD],
        "cycles":stats.cycles(),
    });
    fs::write(output, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{report}");
}
