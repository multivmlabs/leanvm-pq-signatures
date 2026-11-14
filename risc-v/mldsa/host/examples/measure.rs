use leanvm::{Machine, Program};
use mldsa_riscv_host::{ELF, batch};
fn main() {
    let mut args = std::env::args().skip(1);
    let n = args.next().map_or(1, |x| x.parse().expect("count"));
    let elf = args.next().map(|p| std::fs::read(p).expect("ELF"));
    let program = Program::from_elf(elf.as_deref().unwrap_or(ELF)).expect("ELF program");
    let run = batch(n);
    let mut machine = Machine::new(program.rv(), &run.advice);
    let mut cycles = 0;
    while !machine.halted() {
        machine.step().expect("valid guest execution");
        cycles += 1;
    }
    assert_eq!(machine.output().unwrap(), run.expected);
    let stats = program.measure(&run.advice).expect("one commitment fits");
    println!(
        "{{\"count\":{n},\"cycles\":{cycles},\"committed_words\":{}}}",
        stats.committed
    );
}
