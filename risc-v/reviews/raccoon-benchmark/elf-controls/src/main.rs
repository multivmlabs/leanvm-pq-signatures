//! Actual-ELF correctness only. No prover, execution planner or timer.
use leanvm::{Machine, Program};
use std::{fs, path::Path};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let elf = fs::read(&args[1]).unwrap();
    let program = Program::from_elf(&elf).unwrap();
    let mut files: Vec<_> = fs::read_dir(Path::new(&args[2]))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "bin"))
        .collect();
    files.sort();
    const RECORD: usize = 2256 + 32 + 11524;
    for file in files {
        let input = fs::read(&file).unwrap();
        assert!(input.len().is_multiple_of(RECORD));
        let mut advice = vec![(input.len() / RECORD) as u64];
        for record in input.chunks_exact(RECORD) {
            let mut padded = record.to_vec();
            padded.extend([0; 4]);
            advice.extend(padded.chunks_exact(8).map(|b| u64::from_le_bytes(b.try_into().unwrap())));
        }
        let actual = match Machine::new(program.rv(), &advice).run() {
            Ok(output) => hex(&output.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>()),
            Err(error) => format!("TRAP:{error:?}"),
        };
        println!("{}\t{}", file.file_name().unwrap().to_string_lossy(), actual);
    }
}
