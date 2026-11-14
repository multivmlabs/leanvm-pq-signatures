//! Host fixtures and intended-public-statement derivation, never a verification hint.
use leanvm_guest::{PublicValues, Run};
use raccoong_riscv_guest::{DOMAIN, MAX_BATCH, PK_BYTES, PK_WORDS, SIG_BYTES, SIG_WORDS, verify};
use std::path::{Path, PathBuf};

pub const ELF: &[u8] = include_bytes!("../../raccoong.elf");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRecord {
    pub public_key: [u8; PK_BYTES],
    pub message: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub public: PublicRecord,
    pub signature: [u8; SIG_BYTES],
}

fn decode<const N: usize>(value: &serde_json::Value, field: &str) -> [u8; N] {
    let text = value[field].as_str().expect("fixture hex field");
    assert_eq!(text.len(), 2 * N, "fixture length for {field}");
    let mut result = [0; N];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("fixture hex");
    }
    result
}

pub fn record_from_json(bytes: &[u8]) -> Record {
    let json: serde_json::Value = serde_json::from_slice(bytes).expect("fixture JSON");
    assert_eq!(json.as_object().expect("fixture object").len(), 3);
    let result = Record {
        public: PublicRecord {
            public_key: decode(&json, "public_key"),
            message: decode(&json, "message"),
        },
        signature: decode(&json, "signature"),
    };
    assert!(
        verify(
            &result.public.public_key,
            &result.public.message,
            &result.signature
        ),
        "fixture does not satisfy strict signature profile"
    );
    result
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .to_owned()
}

pub fn record(index: usize) -> Record {
    let saved = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("testdata/record-{index}.json"));
    let path = if saved.is_file() {
        saved
    } else {
        let root = root();
        let cache = root.join(".cache/raccoong-fixtures");
        std::fs::create_dir_all(&cache).expect("fixture cache directory");
        let output = cache.join(format!("record-{index}.json"));
        if !output.is_file() {
            let python = root.join(".venv/bin/python");
            let status = std::process::Command::new(python)
                .arg(root.join("risc-v/raccoon-g/generate_fixtures.py"))
                .arg("--index")
                .arg(index.to_string())
                .arg("--out")
                .arg(&output)
                .status()
                .expect("run pinned Python fixture generator");
            assert!(status.success(), "fixture generation failed");
        }
        output
    };
    record_from_json(&std::fs::read(path).expect("fixture file"))
}

fn words<const N: usize>(bytes: &[u8]) -> [u64; N] {
    assert_eq!(bytes.len(), 8 * N);
    core::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
}

pub fn expected_output(records: &[PublicRecord]) -> [u64; 4] {
    assert!((1..=MAX_BATCH).contains(&records.len()));
    let mut values = PublicValues::new();
    values.commit(&DOMAIN).commit(&(records.len() as u64));
    for record in records {
        values.commit(&words::<PK_WORDS>(&record.public_key));
        values.commit(&words::<4>(&record.message));
    }
    values.digest()
}

pub fn run_from_records(records: &[Record]) -> Run {
    assert!((1..=MAX_BATCH).contains(&records.len()));
    let public: Vec<_> = records.iter().map(|r| r.public.clone()).collect();
    let mut advice = vec![records.len() as u64];
    for record in records {
        advice.extend(words::<PK_WORDS>(&record.public.public_key));
        advice.extend(words::<4>(&record.public.message));
        advice.extend(words::<SIG_WORDS>(&record.signature));
    }
    Run {
        advice,
        expected: expected_output(&public),
    }
}

pub fn records(start: usize, n: usize) -> Vec<Record> {
    assert!((1..=MAX_BATCH).contains(&n));
    (start..start.checked_add(n).expect("index overflow"))
        .map(record)
        .collect()
}
pub fn batch_range(start: usize, n: usize) -> Run {
    run_from_records(&records(start, n))
}
pub fn batch(n: usize) -> Run {
    batch_range(0, n)
}

#[cfg(test)]
mod tests;
