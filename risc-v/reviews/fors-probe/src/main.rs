//! Independent guest-execution checks. This harness changes only attacker-controlled advice.
use leanvm::{Machine, Program};

fn execute(program: &Program, advice: &[u64]) -> Result<[u64; 4], leanvm::Trap> {
    Machine::new(program.rv(), advice).run()
}

fn main() {
    let program = Program::from_elf(fors_host::ELF).unwrap();
    let run = fors_host::batch(1);
    assert_eq!(execute(&program, &run.advice), Ok(run.expected));
    let mut negatives = Vec::new();

    // Every tree and every path height, including the secret opening. Vary limb
    // and bit position so the probe covers upper input bits as well as low bits.
    for tree in 0..fors::K {
        for height in 0..=fors::A {
            let limb = (tree + height) % 4;
            let mut advice = run.advice.clone();
            let offset = 1 + 12 + tree * (fors::A + 1) * 4 + height * 4 + limb;
            advice[offset] ^= 1u64 << ((tree * 7 + height * 11) % 64);
            assert!(execute(&program, &advice).is_err(), "tree {tree}, height {height}, limb {limb}");
            negatives.push(format!("opening-{tree}-{height}-{limb}"));
        }
    }
    for word in 0..12 {
        let mut advice = run.advice.clone();
        advice[1 + word] ^= 1 << 63;
        assert!(execute(&program, &advice).is_err(), "public word {word}");
        negatives.push(format!("public-word-{word}"));
    }
    for n in [0, 2, fors::MAX_BATCH as u64 + 1, u64::MAX] {
        let mut advice = run.advice.clone();
        advice[0] = n;
        assert!(execute(&program, &advice).is_err(), "count {n}");
        negatives.push(format!("count-{n}"));
    }
    let mut swapped = run.advice.clone();
    let first = 13;
    let other = first + (fors::A + 1) * 4;
    for i in 0..(fors::A + 1) * 4 {
        swapped.swap(first + i, other + i);
    }
    assert!(execute(&program, &swapped).is_err());
    negatives.push("swapped-tree-openings".into());
    assert!(execute(&program, &run.advice[..run.advice.len() - 4]).is_err());
    negatives.push("truncated-last-sibling".into());

    // Changing order is a valid new statement, not an invalid signature. It must
    // execute successfully while changing the independently reconstructed digest.
    let (two, records) = fors_host::batch_with_records(0, 2);
    assert_eq!(execute(&program, &two.advice), Ok(two.expected));
    let mut reversed = two.advice.clone();
    let words = fors::RECORD_WORDS;
    for i in 0..words { reversed.swap(1 + i, 1 + words + i); }
    let expected_reversed = fors_host::expected_output(&[records[1].header, records[0].header]);
    assert_ne!(expected_reversed, two.expected);
    assert_eq!(execute(&program, &reversed), Ok(expected_reversed));

    // Unread private advice is not public input. Its presence need not alter a
    // proof's statement; ensure no consumer treats it as another verified item.
    let mut trailing = run.advice.clone();
    trailing.push(u64::MAX);
    assert_eq!(execute(&program, &trailing), Ok(run.expected));

    println!("{}", serde_json::json!({
        "honest_guest_controls": 3,
        "guest_rejection_controls": negatives.len(),
        "negative_cases": negatives,
        "all_rejected": true,
        "reordered_valid_batch_changes_output": true,
        "unread_private_advice_does_not_change_claim": true,
        "scope": "Unchanged optimized FORS guest executed by leanVM's RISC-V interpreter; no host validation result substitutes for guest rejection; no STARK forgery claimed."
    }));
}
