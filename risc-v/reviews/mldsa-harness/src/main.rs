//! Review-only consumer of arbitrary advice, with the unchanged production ELF.
use leanvm::{Machine, Program};

fn main() {
    let path = std::env::args().nth(1).expect("advice file");
    if path == "--dump-elf" {
        use std::io::Write;
        std::io::stdout().write_all(mldsa_riscv_host::ELF).unwrap();
        return;
    }
    let bytes = std::fs::read(path).expect("read advice");
    assert!(bytes.len().is_multiple_of(8));
    let advice: Vec<u64> = bytes.chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    let program = Program::from_elf(mldsa_riscv_host::ELF).expect("pinned ELF");
    match Machine::new(program.rv(), &advice).run() {
        Ok(output) => println!("{}", output.map(|w| format!("{w:016x}")).join("")),
        Err(error) => {
            eprintln!("guest rejected: {error:?}");
            std::process::exit(1);
        }
    }
}
