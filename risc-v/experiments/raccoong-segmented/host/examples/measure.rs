use leanvm::{Machine, Program};
use raccoong_segmented_host::{ELF, PARTS_PER_SIGNATURE, prepare, record, row_run, rows_for_part};
use serde_json::json;
use std::{collections::BTreeMap, fs, time::Instant};

fn main() {
    let output = std::env::args().nth(1).expect("output JSON");
    let index = std::env::args()
        .nth(2)
        .map(|v| v.parse::<usize>().unwrap())
        .unwrap_or(0);
    let record = record(index);
    let now = Instant::now();
    let prepared = prepare(&record);
    let prepare_s = now.elapsed().as_secs_f64();
    let program = Program::from_elf(ELF).unwrap();
    let mut rows = Vec::new();
    for row in 0..PARTS_PER_SIGNATURE {
        let run = row_run(&prepared, row);
        let output = Machine::new(program.rv(), &run.advice)
            .run()
            .expect("honest raw row completes");
        assert_eq!(output, run.expected, "public row output");
        let measurement = match program.measure(&run.advice) {
            Ok(stats) => {
                json!({"accepted":true,"cycles":stats.cycles(),"committed_words":stats.committed,
                "base_rows":stats.base_counts.iter().map(|(t,n)|(t.name(),*n)).collect::<BTreeMap<_,_>>(),
                "padded_rows":stats.counts.iter().map(|(t,n)|(t.name(),*n)).collect::<BTreeMap<_,_>>()})
            }
            Err(error) => json!({"accepted":false,"error":format!("{error:?}")}),
        };
        rows.push(json!({"part":row,"rows":rows_for_part(row),"raw_output_matches":true,"measurement":measurement}));
    }
    let result = json!({"schema":1,"index":index,"prepare_s":prepare_s,"binding":prepared.binding,
       "scope":"One real original signature decomposed into five linked two-row claims, with row eight repeated and charged; no STARK produced","rows":rows});
    fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    println!("{result}");
}
