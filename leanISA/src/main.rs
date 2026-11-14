use std::{collections::BTreeMap, error::Error, fs, path::Path, time::Instant};

use bincode::Options;
use fiat_shamir::transcript::Proof;
use leanvm_core::cpu;
use primitives::field::F192;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
type Cell = [u64; 3];

#[global_allocator]
static ALLOCATOR: bench::Jemalloc = bench::Jemalloc;

#[derive(Deserialize, Serialize)]
struct Input {
    scheme: String,
    source: String,
    public_input: [Cell; 2],
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    witness: BTreeMap<String, Vec<Vec<Cell>>>,
    #[serde(default)]
    metadata: Value,
}

fn word(v: &Cell) -> F192 {
    F192::new(v[0], v[1], v[2])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn proof_encoding(proof: &Proof) -> Result<Value> {
    Ok(json!({
        "scalar_stream_count": proof.stream.len(),
        "scalar_stream_bytes": bincode::serialized_size(&proof.stream)?,
        "merkle_bytes": bincode::serialized_size(&proof.merkle)?,
        "merkle_phases": proof.merkle.iter().map(|phase| json!({
            "opened_rows": phase.leaf_data.len(),
            "opened_field_words": phase.leaf_data.iter().map(Vec::len).sum::<usize>(),
            "sibling_hashes": phase.sibling_hashes.len(),
        })).collect::<Vec<_>>()
    }))
}

fn peak_rss() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // getrusage writes the entire supplied struct on success.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    let raw = unsafe { usage.assume_init() }.ru_maxrss as u64;
    Some(if cfg!(target_os = "macos") {
        raw
    } else {
        raw * 1024
    })
}

fn save_json(path: &str, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let action = args
        .next()
        .ok_or("expected inspect, execute, prove, or verify")?;
    if !["inspect", "execute", "prove", "verify"].contains(&action.as_str()) {
        return Err("usage: pq-leanbench execute|prove|verify --input FILE [--proof FILE] [--report FILE] [--repeat N] [--warmup N] [--rate 1..4]".into());
    }
    let mut options = BTreeMap::new();
    while let Some(key) = args.next() {
        if ![
            "--input",
            "--proof",
            "--report",
            "--repeat",
            "--warmup",
            "--rate",
            "--expect-guest-hash",
            "--expect-public-input",
            "--min-log-committed",
        ]
        .contains(&key.as_str())
        {
            return Err(format!("unknown option {key}").into());
        }
        let value = args.next().ok_or("option is missing a value")?;
        if options.insert(key, value).is_some() {
            return Err("duplicate option".into());
        }
    }
    let input_path = options.get("--input").ok_or("--input is required")?;
    let mut input: Input = serde_json::from_slice(&fs::read(input_path)?)?;
    if input.public_input.iter().any(|x| x[2] != 0) {
        return Err("public inputs must be two canonical 128-bit cells".into());
    }
    let repeat: usize = options.get("--repeat").map_or(Ok(1), |s| s.parse())?;
    let warmup: usize = options.get("--warmup").map_or(Ok(0), |s| s.parse())?;
    let rate: usize = options.get("--rate").map_or(Ok(1), |s| s.parse())?;
    if repeat == 0 || !(1..=4).contains(&rate) {
        return Err("repeat must be positive and rate must be 1..4".into());
    }
    if ["prove", "verify"].contains(&action.as_str()) && !options.contains_key("--proof") {
        return Err("--proof is required for prove/verify".into());
    }
    parallel::init();
    let started = Instant::now();
    let ast = lean_compiler::parse(&input.source).map_err(|e| format!("parse guest: {e}"))?;
    let mut program = lean_compiler::compile(&ast);
    let min_log_committed: usize = options
        .get("--min-log-committed")
        .map_or(Ok(0), |s| s.parse())?;
    if min_log_committed > leanvm_core::pcs::MAX_MU {
        return Err("minimum commitment size exceeds the pinned backend limit".into());
    }
    program.min_log_committed = min_log_committed;
    let compile_s = started.elapsed().as_secs_f64();
    for (name, entries) in &input.witness {
        program.set_witness(
            name,
            entries
                .iter()
                .map(|row| row.iter().map(word).collect())
                .collect(),
        );
    }
    let pi = input.public_input.map(|c| word(&c));
    let guest_hash = hex(&cpu::public_input_bytes(&cpu::fs_seed(&program)));
    let public_input_hex = hex(&cpu::public_input_bytes(&pi));
    for (flag, actual) in [
        ("--expect-guest-hash", &guest_hash),
        ("--expect-public-input", &public_input_hex),
    ] {
        if let Some(expected) = options.get(flag)
            && !actual.eq_ignore_ascii_case(expected)
        {
            return Err(format!("{flag}: expected {expected}, received {actual}").into());
        }
    }
    let mut report = json!({
        "schema_version": 1, "action": action, "scheme": input.scheme,
        "metadata": input.metadata, "leanvm_revision": env!("LEANVM_BUILD_REVISION"),
        "leanvm_source_dirty_at_build": env!("LEANVM_BUILD_DIRTY"),
        "guest_hash": guest_hash, "public_input_hex": public_input_hex,
        "statement_pinned": options.contains_key("--expect-guest-hash") && options.contains_key("--expect-public-input"),
        "compile_s": compile_s, "log_inv_rate": rate,
        "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
        "threads_env": std::env::var("LEANVM_NUM_THREADS").ok(),
        "zero_knowledge": false,
        "min_log_committed": min_log_committed,
    });
    if action == "inspect" {
        report["bytecode_instructions"] = json!(program.code_len());
        report["log_bytecode"] = json!(program.prog.len().trailing_zeros());
    } else if action == "verify" {
        report.as_object_mut().unwrap().remove("log_inv_rate");
        let encoded = fs::read(&options["--proof"])?;
        let proof: Proof = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(&encoded)?;
        let now = Instant::now();
        cpu::verify(&program, &pi, &proof).map_err(|e| format!("verify: {e:?}"))?;
        report["verify_s"] = json!([now.elapsed().as_secs_f64()]);
        report["proof_bytes"] = json!(encoded.len());
        report["proof_encoding"] = proof_encoding(&proof)?;
        report["verified"] = json!(true);
        let now = Instant::now();
        let table: Vec<u64> = cpu::bytecode_table(&program.prog)
            .iter()
            .map(|word| word.0)
            .collect();
        let bytecode = verifier::Bytecode::new(&table);
        report["bytecode_prepare_s"] = json!(now.elapsed().as_secs_f64());
        let public_bytes = cpu::public_input_bytes(&pi);
        let mut cached = Vec::new();
        for pass in 0..(warmup + repeat) {
            let now = Instant::now();
            verifier::verify_execution(&bytecode, &public_bytes, &cpu::scalar_proof(&proof))
                .map_err(|e| format!("cached verify: {e:?}"))?;
            if pass >= warmup {
                cached.push(now.elapsed().as_secs_f64());
            }
        }
        report["verify_cached_s"] = json!(cached);
    } else {
        let now = Instant::now();
        let exec = program
            .execute(pi)
            .map_err(|e| format!("execution: {e:?}"))?;
        if !exec.unconstrained_reads.is_empty() {
            return Err(format!("unconstrained reads: {:?}", exec.unconstrained_reads).into());
        }
        report["execute_s"] = json!(now.elapsed().as_secs_f64());
        report["cycles"] = json!(exec.cycles);
        report["opcode_rows"] = json!(exec.rows());
        report["memory_cells"] = json!(exec.mem_used);
        report["bytecode_instructions"] = json!(program.code_len());
        drop(exec);
        if action == "prove" {
            let mut prove_times = Vec::new();
            let mut verify_times = Vec::new();
            let mut proof_sizes = Vec::new();
            let mut last_proof = None;
            for pass in 0..(warmup + repeat) {
                let now = Instant::now();
                let (proof, stats) =
                    cpu::prove(&program, pi, rate).map_err(|e| format!("prove: {e:?}"))?;
                let prove_s = now.elapsed().as_secs_f64();
                let now = Instant::now();
                cpu::verify(&program, &pi, &proof).map_err(|e| format!("verify: {e:?}"))?;
                let verify_s = now.elapsed().as_secs_f64();
                if pass >= warmup {
                    prove_times.push(prove_s);
                    verify_times.push(verify_s);
                    proof_sizes.push(bincode::serialized_size(&proof)?);
                }
                report["committed_cells"] = json!(stats.committed);
                report["log_memory_cells"] = json!(stats.log_mem);
                last_proof = Some(proof);
            }
            let last_proof = last_proof.ok_or("no proof")?;
            report["proof_encoding"] = proof_encoding(&last_proof)?;
            let bytes = bincode::serialize(&last_proof)?;
            let path = &options["--proof"];
            if let Some(parent) = Path::new(path).parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, &bytes)?;
            report["prove_s"] = json!(prove_times);
            report["verify_s"] = json!(verify_times);
            report["proof_bytes_samples"] = json!(proof_sizes);
            report["proof_bytes"] = json!(bytes.len());
            report["warmup_passes"] = json!(warmup);
            report["verified"] = json!(true);
            // Export enough to verify independently, with no signature witness.
            input.witness.clear();
            save_json(&format!("{path}.statement.json"), &input)?;
        }
    }
    report["process_peak_rss_bytes"] = json!(peak_rss());
    if let Some(path) = options.get("--report") {
        save_json(path, &report)?;
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
