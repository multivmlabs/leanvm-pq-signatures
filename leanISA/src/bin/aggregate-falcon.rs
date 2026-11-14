//! Experimental fixed-arity recursion over actual ETHFALCON leaf proofs.
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use bincode::Options;
use leanvm_core::cpu::{self, Program, Proof};
use primitives::field::F192;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[allow(dead_code)]
#[path = "../recursion_guest.rs"]
mod recursion_guest;
#[allow(dead_code)]
#[path = "../recursion_support.rs"]
mod recursion_support;

#[global_allocator]
static ALLOCATOR: bench::Jemalloc = bench::Jemalloc;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
type Cell = [u64; 3];
type Streams = BTreeMap<String, Vec<Vec<F192>>>;
const FALCON_DOMAIN: &[u8; 16] = b"pqbench/falcon1\0";

#[derive(Deserialize, Clone)]
struct Record {
    public_key_hex: String,
    message_hex: String,
}
#[derive(Deserialize, Clone)]
struct Manifest {
    schema_version: u32,
    scheme: String,
    leaf_size: usize,
    records: Vec<Record>,
}
#[derive(Deserialize)]
struct Input {
    source: String,
    public_input: [Cell; 2],
    witness: BTreeMap<String, Vec<Vec<Cell>>>,
}

/// No signatures or child proofs are carried by the aggregate transport.
#[derive(Serialize, Deserialize, Clone)]
struct Envelope {
    version: u32,
    leaf_guest_hash: [u8; 32],
    leaf_size: usize,
    deferred_points: Vec<Vec<F192>>,
    proof: Proof,
}

fn wire() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.is_ascii() || !text.len().is_multiple_of(2) {
        return Err("hex must be ASCII with even length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn halves(bytes: [u8; 32]) -> [F192; 2] {
    let w = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
    [F192::new(w(0), w(8), 0), F192::new(w(16), w(24), 0)]
}
fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    primitives::hash::hash(&parts.concat())
}
fn program_hash(program: &Program) -> [u8; 32] {
    cpu::public_input_bytes(&cpu::fs_seed(program))
}

/// Independent compact-public-key decoder, matching the leaf's canonical LE16 key commitment.
fn key_hash(encoded: &[u8]) -> Result<[u8; 32]> {
    if encoded.len() != 897 || encoded[0] != 9 {
        return Err("expected canonical Falcon-512 public key".into());
    }
    let mut raw = Vec::with_capacity(1024);
    for coefficient in 0..512 {
        let mut value = 0u16;
        for bit in 0..14 {
            let offset = coefficient * 14 + bit;
            value = (value << 1) | ((encoded[1 + offset / 8] >> (7 - offset % 8)) & 1) as u16;
        }
        if value >= 12289 {
            return Err("noncanonical public key coefficient".into());
        }
        raw.extend_from_slice(&value.to_le_bytes());
    }
    Ok(primitives::hash::hash(&raw))
}

/// Derive expected leaf claims from the public manifest, never from a prover's PI hints.
fn expected_inputs(manifest: &Manifest) -> Result<Vec<[F192; 2]>> {
    if manifest.schema_version != 1
        || manifest.scheme != "ethfalcon-512-keccak"
        || manifest.leaf_size != 5
    {
        return Err(
            "this experiment requires schema1 ETHFALCON with five signatures per leaf".into(),
        );
    }
    if manifest.records.len() != 30 {
        return Err("this experiment requires exactly 30 claims".into());
    }
    let mut unique = BTreeSet::new();
    let mut result = Vec::new();
    for group in manifest.records.chunks(manifest.leaf_size) {
        let count = (group.len() as u64).to_be_bytes();
        let mut accumulator = hash_parts(&[FALCON_DOMAIN, &count]);
        for record in group {
            let key = unhex(&record.public_key_hex)?;
            let message = unhex(&record.message_hex)?;
            if message.len() != 32 {
                return Err("the fixed leaf guest requires 32-byte messages".into());
            }
            if !unique.insert((key.clone(), message.clone())) {
                return Err("duplicate key/message claim".into());
            }
            let key_digest = key_hash(&key)?;
            let message_digest = primitives::hash::hash(&message);
            let claim = hash_parts(&[FALCON_DOMAIN, &key_digest, &message_digest]);
            accumulator = hash_parts(&[&accumulator, &claim]);
        }
        result.push(halves(accumulator));
    }
    Ok(result)
}

fn set_streams(program: &mut Program, streams: &Streams) {
    for (name, entries) in streams {
        program.set_witness(name.clone(), entries.clone());
    }
}
fn peak_rss() -> u64 {
    bench::peak_rss_bytes()
}
fn verify_core(program: &Program, pi: &[F192; 2], proof: &Proof) -> Result<()> {
    cpu::verify(program, pi, proof).map_err(|e| format!("proof verification: {e:?}"))?;
    Ok(())
}

fn evaluate_deferrals(leaf: &Program, points: &[Vec<F192>]) -> Result<Vec<F192>> {
    let variables =
        leaf.prog.len().trailing_zeros() as usize + leanvm_core::leaf::N_BYTECODE_SELECTORS;
    let table: Vec<u64> = cpu::bytecode_table(&leaf.prog)
        .iter()
        .map(|word| word.0)
        .collect();
    let bytecode = verifier::Bytecode::new(&table);
    points
        .iter()
        .map(|point| {
            if point.len() != variables {
                return Err("incorrect deferred point dimension".into());
            }
            bytecode
                .evaluate(&point.iter().map(cpu::to_scalar).collect::<Vec<_>>())
                .map(cpu::from_scalar)
                .map_err(|e| format!("deferred bytecode evaluation: {e:?}").into())
        })
        .collect()
}

/// The only final verdict: expected claims, expected code, all deferred evaluations, and one root proof.
fn verify_aggregate(leaf: &Program, manifest: &Manifest, envelope: &Envelope) -> Result<Value> {
    let started = Instant::now();
    let child_pi = expected_inputs(manifest)?;
    let seed = cpu::fs_seed(leaf);
    if envelope.version != 1
        || envelope.leaf_size != manifest.leaf_size
        || envelope.leaf_guest_hash != program_hash(leaf)
        || envelope.deferred_points.len() != child_pi.len()
    {
        return Err("aggregate program/count/format mismatch".into());
    }
    let kbc = leaf.prog.len().trailing_zeros() as usize;
    let prep = Instant::now();
    let wrapper = recursion_guest::compile(kbc, seed, child_pi.len())?;
    let compile_s = prep.elapsed().as_secs_f64();
    let evaluation = Instant::now();
    let values = evaluate_deferrals(leaf, &envelope.deferred_points)?;
    let deferred_evaluation_s = evaluation.elapsed().as_secs_f64();
    let pi =
        recursion_guest::public_input(kbc, seed, &child_pi, &envelope.deferred_points, &values)?;
    let native = Instant::now();
    verify_core(&wrapper, &pi, &envelope.proof)?;
    let core_verify_s = native.elapsed().as_secs_f64();
    Ok(
        json!({"verified":true,"signatures":manifest.records.len(),"child_proofs":child_pi.len(),
        "leaf_guest_hash":hex(&program_hash(leaf)),"root_guest_hash":hex(&program_hash(&wrapper)),
        "public_input_hex":hex(&cpu::public_input_bytes(&pi)),"compile_root_s":compile_s,
        "deferred_evaluation_s":deferred_evaluation_s,"root_core_verify_s":core_verify_s,
        "verification_total_s":started.elapsed().as_secs_f64(),
        "root_core_proof_bytes":bincode::serialized_size(&envelope.proof)?,
        "aggregate_wire_bytes":wire().serialized_size(envelope)?,
        "deferred_points_count":envelope.deferred_points.len(),"zero_knowledge":false,
        "verification_uses_child_proofs":false,"verification_uses_signatures":false}),
    )
}

fn prove(
    leaf: &Program,
    source: &str,
    manifest: &Manifest,
    leaf_dir: &Path,
    out: &Path,
    rate: usize,
) -> Result<()> {
    fs::create_dir_all(out)?;
    let expected = expected_inputs(manifest)?;
    let kbc = leaf.prog.len().trailing_zeros() as usize;
    let seed = cpu::fs_seed(leaf);
    let mut streams: Streams = BTreeMap::new();
    let mut points = Vec::new();
    let mut values = Vec::new();
    let mut leaf_reports = Vec::new();
    let work_started = Instant::now();
    for (index, &pi) in expected.iter().enumerate() {
        let input: Input = read_json(&leaf_dir.join(format!("leaf-{index}.json")))?;
        if input.source != source || input.public_input.map(|c| F192::new(c[0], c[1], c[2])) != pi {
            return Err(format!("leaf{index}: source or expected claim commitment differs").into());
        }
        let proof_path = out.join(format!("leaf-{index}.proof"));
        let report_path = out.join(format!("leaf-{index}.report.json"));
        let proof = if proof_path.exists() {
            let proof: Proof = wire().deserialize(&fs::read(&proof_path)?)?;
            verify_core(leaf, &pi, &proof)?;
            let mut report: Value = read_json(&report_path)?;
            report["reused"] = json!(true);
            leaf_reports.push(report);
            println!("leaf{index}: reused verified proof");
            proof
        } else {
            let mut program = leaf.clone();
            for (name, entries) in input.witness {
                program.set_witness(
                    name,
                    entries
                        .into_iter()
                        .map(|row| {
                            row.into_iter()
                                .map(|c| F192::new(c[0], c[1], c[2]))
                                .collect()
                        })
                        .collect(),
                );
            }
            let now = Instant::now();
            let (proof, stats) =
                cpu::prove(&program, pi, rate).map_err(|e| format!("leaf{index} prove: {e:?}"))?;
            let prove_s = now.elapsed().as_secs_f64();
            verify_core(leaf, &pi, &proof)?;
            fs::write(&proof_path, wire().serialize(&proof)?)?;
            let report = json!({"leaf":index,"signatures":manifest.leaf_size,"prove_s":prove_s,
                "cycles":stats.cycles,"committed_cells":stats.committed,"proof_bytes":bincode::serialized_size(&proof)?,
                "public_input_hex":hex(&cpu::public_input_bytes(&pi)),"reused":false,
                "process_peak_rss_bytes_so_far":peak_rss()});
            save(&report_path, &report)?;
            println!(
                "leaf{index}: {} signatures, {} cycles, {:.3}s",
                manifest.leaf_size, stats.cycles, prove_s
            );
            leaf_reports.push(report);
            proof
        };
        let now = Instant::now();
        let prepared = recursion_support::child_witness(leaf, pi, &proof)?;
        println!(
            "leaf{index}: recursive advice prepared in {:.3}s",
            now.elapsed().as_secs_f64()
        );
        for (name, mut entries) in prepared.streams {
            streams.entry(name).or_default().append(&mut entries);
        }
        streams
            .entry("aggregate_child_pi".into())
            .or_default()
            .push(pi.to_vec());
        points.push(prepared.bytecode_point);
        values.push(prepared.bytecode_value);
    }
    // Independently discharge the deferred claims before using them as the root statement.
    if evaluate_deferrals(leaf, &points)? != values {
        return Err("host deferred evaluations disagree".into());
    }
    let root_pi = recursion_guest::public_input(kbc, seed, &expected, &points, &values)?;
    let mut wrapper = recursion_guest::compile(kbc, seed, expected.len())?;
    set_streams(&mut wrapper, &streams);
    println!(
        "recursive wrapper compiled: {} instructions",
        wrapper.code_len()
    );
    let now = Instant::now();
    let execution = wrapper
        .execute(root_pi)
        .map_err(|e| format!("recursive execution: {e:?}"))?;
    if !execution.unconstrained_reads.is_empty() {
        return Err("recursive guest has unconstrained reads".into());
    }
    println!(
        "recursive execution: {} cycles, {} memory cells, {:.3}s",
        execution.cycles,
        execution.mem_used,
        now.elapsed().as_secs_f64()
    );
    let root_cycles = execution.cycles;
    let root_memory = execution.mem_used;
    drop(execution);

    // These mutations bypass host child verification and reach the guest's own verifier.
    let mut guest_checks = Vec::new();
    for (label, name, entry, position) in [
        ("child_scalar", "stream", 0, 20),
        ("child_merkle_row", "merkle_leaf_rows", 0, 0),
        ("child_public_input", "aggregate_child_pi", 0, 0),
    ] {
        let mut changed = streams.clone();
        changed.get_mut(name).ok_or("missing mutation stream")?[entry][position].c0 ^= 1;
        let mut negative = wrapper.clone();
        set_streams(&mut negative, &changed);
        let failure = negative
            .execute(root_pi)
            .err()
            .ok_or_else(|| format!("recursive verifier accepted altered child advice: {label}"))?;
        guest_checks
            .push(json!({"case":label,"rejected":true,"diagnostic":format!("{failure:?}")}));
    }
    let now = Instant::now();
    let (proof, stats) =
        cpu::prove(&wrapper, root_pi, rate).map_err(|e| format!("root prove: {e:?}"))?;
    let root_prove_s = now.elapsed().as_secs_f64();
    verify_core(&wrapper, &root_pi, &proof)?;
    let envelope = Envelope {
        version: 1,
        leaf_guest_hash: program_hash(leaf),
        leaf_size: manifest.leaf_size,
        deferred_points: points,
        proof,
    };
    fs::write(out.join("aggregate.proof"), wire().serialize(&envelope)?)?;
    fs::write(
        out.join("aggregate.core.proof"),
        wire().serialize(&envelope.proof)?,
    )?;
    let verification = verify_aggregate(leaf, manifest, &envelope)?;

    let mut outer_checks = Vec::new();
    let mut wrong = envelope.clone();
    wrong.deferred_points[0][0].c2 ^= 1;
    outer_checks.push(
        json!({"case":"deferred_point","rejected":verify_aggregate(leaf,manifest,&wrong).is_err()}),
    );
    let mut changed_manifest = manifest.clone();
    let mut message = unhex(&changed_manifest.records[0].message_hex)?;
    message[0] ^= 1;
    changed_manifest.records[0].message_hex = hex(&message);
    outer_checks.push(json!({"case":"intended_message","rejected":verify_aggregate(leaf,&changed_manifest,&envelope).is_err()}));
    let mut wrong = envelope.clone();
    wrong.leaf_guest_hash[0] ^= 1;
    outer_checks.push(json!({"case":"child_program_identity","rejected":verify_aggregate(leaf,manifest,&wrong).is_err()}));
    if outer_checks.iter().any(|check| check["rejected"] != true) {
        return Err("outer verifier negative check failed".into());
    }
    let total_leaf_s: f64 = leaf_reports
        .iter()
        .map(|r| r["prove_s"].as_f64().unwrap_or(0.0))
        .sum();
    let reused = leaf_reports
        .iter()
        .filter(|report| report["reused"] == true)
        .count();
    let child_bytes: u64 = leaf_reports
        .iter()
        .map(|report| report["proof_bytes"].as_u64().unwrap_or(0))
        .sum();
    let report = json!({"kind":"actual_recursive_ethfalcon_30","leanvm_revision":env!("LEANVM_BUILD_REVISION"),
        "leaf_reports":leaf_reports,"root_prove_s":root_prove_s,"root_cycles":root_cycles,
        "root_memory_cells":root_memory,"root_committed_cells":stats.committed,"root_opcode_rows":stats.rows,
        "leaf_prover_work_s":total_leaf_s,"total_prover_work_s":total_leaf_s+root_prove_s,
        "leaf_proofs_reused":reused,"raw_child_proof_bytes_total":child_bytes,
        "experiment_process_elapsed_s":work_started.elapsed().as_secs_f64(),"process_peak_rss_bytes":peak_rss(),
        "log_inv_rate":rate,"verification":verification,"guest_negative_checks":guest_checks,"outer_negative_checks":outer_checks,
        "statement_preimage_bytes":recursion_guest::statement_preimage(kbc,seed,&expected,&envelope.deferred_points,&values)?.len(),
        "structure":"six independent five-signature leaf proofs, verified by one fixed-arity recursive root; six deferred bytecode evaluations discharged natively"});
    save(&out.join("report.json"), &report)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let action = arguments.next().ok_or("expected prove or verify")?;
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if ![
            "--manifest",
            "--leaf-source",
            "--leaf-dir",
            "--out-dir",
            "--proof",
            "--report",
            "--rate",
            "--expect-leaf-guest-hash",
        ]
        .contains(&key.as_str())
        {
            return Err(format!("unknown option {key}").into());
        }
        let value = arguments.next().ok_or("missing option value")?;
        if options.insert(key, value).is_some() {
            return Err("duplicate option".into());
        }
    }
    let path = |key: &str| -> Result<PathBuf> {
        Ok(PathBuf::from(
            options.get(key).ok_or_else(|| format!("{key} required"))?,
        ))
    };
    let manifest: Manifest = read_json(&path("--manifest")?)?;
    let source = fs::read_to_string(path("--leaf-source")?)?;
    leanvm_core::init_prover();
    let leaf = lean_compiler::compile(&lean_compiler::parse(&source)?);
    let actual = hex(&program_hash(&leaf));
    if let Some(expected) = options.get("--expect-leaf-guest-hash")
        && !actual.eq_ignore_ascii_case(expected)
    {
        return Err("unexpected leaf guest hash".into());
    }
    match action.as_str() {
        "prove" => {
            let rate: usize = options.get("--rate").map_or(Ok(1), |s| s.parse())?;
            if !(1..=4).contains(&rate) {
                return Err("rate must be1..4".into());
            }
            prove(
                &leaf,
                &source,
                &manifest,
                &path("--leaf-dir")?,
                &path("--out-dir")?,
                rate,
            )
        }
        "verify" => {
            if !options.contains_key("--expect-leaf-guest-hash") {
                return Err("final verification requires trusted --expect-leaf-guest-hash".into());
            }
            let envelope: Envelope = wire().deserialize(&fs::read(path("--proof")?)?)?;
            let report = verify_aggregate(&leaf, &manifest, &envelope)?;
            if options.contains_key("--report") {
                save(&path("--report")?, &report)?;
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        _ => Err("expected prove or verify".into()),
    }
}
