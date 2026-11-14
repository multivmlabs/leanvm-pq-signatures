use leanvm_guest::Run;
pub use original::{PublicRecord, Record, record};
pub use raccoong_segmented_guest::{
    Binding, Commitment, PARTS_PER_SIGNATURE, ROW_COUNT, ROWS_PER_LEAF, TRACE_PADDING_STORES,
    rows_for_part,
};
use raccoong_segmented_guest::{PK_WORDS, SIG_BYTES, SIG_WORDS, W_WORDS, expected_words};

pub const ELF: &[u8] = include_bytes!("../../raccoong-segmented.elf");

#[derive(Clone)]
pub struct PreparedRecord {
    pub public: PublicRecord,
    pub signature: [u8; SIG_BYTES],
    pub w: Commitment,
    pub binding: Binding,
}

fn words<const N: usize>(bytes: &[u8]) -> [u64; N] {
    assert_eq!(bytes.len(), 8 * N);
    core::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
}

pub fn records(start: usize, n: usize) -> Vec<Record> {
    assert!((1..=1000).contains(&n));
    (start..start.checked_add(n).expect("index overflow"))
        .map(record)
        .collect()
}

/// Fresh witness preparation, never a cache of oracle commitments or advice.
/// Runners must charge this and row_run's advice construction as prover work.
pub fn prepare(record: &Record) -> PreparedRecord {
    let w = raccoong_segmented_guest::reconstruct_commitment(
        &record.public.public_key,
        &record.signature,
    )
    .expect("canonical signature and norm");
    assert!(
        raccoong_segmented_guest::global_checks(
            &record.public.public_key,
            &record.public.message,
            &record.signature,
            &w
        ),
        "full signature challenge mismatch"
    );
    let binding = raccoong_segmented_guest::binding(&record.signature, &w);
    PreparedRecord {
        public: record.public.clone(),
        signature: record.signature,
        w,
        binding,
    }
}

pub fn expected_row_output(public: &PublicRecord, row: usize, binding: &Binding) -> [u64; 4] {
    expected_words(
        &words::<PK_WORDS>(&public.public_key),
        &words::<4>(&public.message),
        row,
        binding,
    )
}

pub fn row_run(prepared: &PreparedRecord, row: usize) -> Run {
    assert!(row < PARTS_PER_SIGNATURE);
    let mut advice = Vec::with_capacity(1 + PK_WORDS + 4 + SIG_WORDS + W_WORDS);
    advice.push(row as u64);
    advice.extend(words::<PK_WORDS>(&prepared.public.public_key));
    advice.extend(words::<4>(&prepared.public.message));
    advice.extend(words::<SIG_WORDS>(&prepared.signature));
    advice.extend(prepared.w);
    Run {
        advice,
        expected: expected_row_output(&prepared.public, row, &prepared.binding),
    }
}

#[cfg(test)]
mod tests;
