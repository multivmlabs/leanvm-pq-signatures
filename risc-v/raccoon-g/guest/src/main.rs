#![no_std]
#![no_main]
use leanvm_guest::{commit, read};
use raccoong_riscv_guest::{DOMAIN, MAX_BATCH, PK_WORDS, SIG_WORDS, verify_words};

// 64 full compact records fit in this 4 MiB advice region. This is a transport
// bound, unrelated to the prover's committed-witness capacity.
leanvm_guest::advice_words!(1 << 19);

#[unsafe(no_mangle)]
extern "C" fn main() {
    let count = read::<u64>();
    assert!((1..=MAX_BATCH as u64).contains(count));
    commit(&DOMAIN);
    commit(count);
    for _ in 0..*count {
        let pk = read::<[u64; PK_WORDS]>();
        let message = read::<[u64; 4]>();
        let signature = read::<[u64; SIG_WORDS]>();
        assert!(verify_words(pk, message, signature));
        commit(pk);
        commit(message);
    }
}
