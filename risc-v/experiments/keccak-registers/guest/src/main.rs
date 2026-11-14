//! Verify every FORS signature, then commit the exact ordered public claim list.
#![no_std]
#![no_main]

use fors_registers::{Header, MAX_BATCH, PROFILE, Signature};
use leanvm_guest::{commit, read};

leanvm_guest::advice_words!(fors_registers::ADVICE_WORDS);

#[unsafe(no_mangle)]
extern "C" fn main() {
    let n = *read::<u64>();
    assert!(
        n > 0 && n <= MAX_BATCH as u64,
        "batch count outside advice capacity"
    );
    commit(&PROFILE);
    commit(&n);
    for _ in 0..n {
        let header = read::<Header>();
        let signature = read::<Signature>();
        assert!(
            fors_registers::verify(header, signature),
            "FORS signature must verify"
        );
        commit(header);
    }
}
