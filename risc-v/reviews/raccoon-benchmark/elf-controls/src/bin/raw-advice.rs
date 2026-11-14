//! Raw advice correctness only. No prover, capacity planner or timer.
use leanvm::{Machine, Program};
use std::{fs, path::Path};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let elf = fs::read(&args[1]).unwrap();
    let program = Program::from_elf(&elf).unwrap();
    let mut files: Vec<_> = fs::read_dir(Path::new(&args[2])).unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "bin")).collect();
    files.sort();
    for file in files {
        let input = fs::read(&file).unwrap();
        assert!(input.len().is_multiple_of(8));
        let advice: Vec<_> = input.chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap())).collect();
        let actual = match Machine::new(program.rv(), &advice).run() {
            Ok(output) => output.iter().flat_map(|w| w.to_le_bytes())
                .map(|b| format!("{b:02x}")).collect::<String>(),
            Err(error) => format!("TRAP:{error:?}"),
        };
        println!("{}\t{}", file.file_name().unwrap().to_string_lossy(), actual);
    }
}
