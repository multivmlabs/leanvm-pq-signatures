#![no_std]
#![no_main]
use leanvm_guest::{commit, read};
use raccoong_segmented_guest::{
    DOMAIN, PARTS_PER_SIGNATURE, PK_WORDS, SIG_WORDS, TRACE_PADDING_STORES, W_WORDS, rows_for_part,
    verify_words,
};

leanvm_guest::advice_words!(1 << 13);

#[unsafe(no_mangle)]
extern "C" fn main() {
    let row = *read::<u64>();
    assert!(row < PARTS_PER_SIGNATURE as u64);
    let pk = read::<[u64; PK_WORDS]>();
    let message = read::<[u64; 4]>();
    let signature = read::<[u64; SIG_WORDS]>();
    let w = read::<[u64; W_WORDS]>();
    let digest = verify_words(pk, message, signature, w, row as usize).expect("invalid row claim");
    commit(&DOMAIN);
    commit(&row);
    let rows = rows_for_part(row as usize).unwrap();
    commit(&(rows[0] as u64));
    commit(&(rows[1] as u64));
    commit(pk);
    commit(message);
    commit(&digest);
    normalize_trace();
}

/// The native recursive tree needs one padded instruction-table shape. A fixed
/// number of real stores moves every measured part above the same SD boundary.
/// No input changes this count, and the writes cannot alias keys or SDK output.
#[inline(never)]
fn normalize_trace() {
    let mut scratch = 0u64;
    let pointer = &mut scratch as *mut u64;
    for value in 0..TRACE_PADDING_STORES {
        // SAFETY: pointer refers to this live, naturally aligned local u64.
        // Volatile keeps every charged store in the actual guest execution.
        unsafe { pointer.write_volatile(value as u64) };
    }
}
