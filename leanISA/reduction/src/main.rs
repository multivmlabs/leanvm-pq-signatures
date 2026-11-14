//! Real FORS leaves, constrained reductions in Python DSL, complete public-only receipts.
use leanisa_reduced_tree::{
    pipeline,
    receipt::{self, Envelope, Verifier},
    wrapper::{self, Family, State},
};
use leanvm_core::cpu;
use primitives::field::F192;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

#[global_allocator]
static ALLOCATOR: bench::Jemalloc = bench::Jemalloc;
const REVISION: &str = "575df819d9c857f38068cecf7b1640e0ce4bfb29";
type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicRecord {
    public_key_hex: String,
    message_hex: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Public {
    schema: u32,
    backend_revision: String,
    scheme: String,
    signatures: usize,
    leaf_size: usize,
    leaf_source: String,
    public_records: Vec<PublicRecord>,
}
#[derive(Deserialize)]
struct Input {
    source: String,
    public_input: [[u64; 3]; 2],
    witness: BTreeMap<String, Vec<Vec<[u64; 3]>>>,
}
fn hash(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn save(p: impl AsRef<Path>, v: &impl Serialize) -> Result<()> {
    let p = p.as_ref();
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    fs::write(p, serde_json::to_vec_pretty(v)?)?;
    Ok(())
}
fn median(v: &[f64]) -> f64 {
    let mut a = v.to_vec();
    a.sort_by(f64::total_cmp);
    a[a.len() / 2]
}
fn public_claims(p: &Public) -> Result<(Vec<State>, [F192; 2], usize, usize)> {
    if p.schema != 1
        || p.backend_revision != REVISION
        || p.scheme != "fors"
        || !(1..=5).contains(&p.leaf_size)
        || p.signatures > 100
        || p.signatures < 2
        || !p.signatures.is_multiple_of(p.leaf_size)
        || p.public_records.len() != p.signatures
    {
        return Err("unsupported public FORS configuration".into());
    }
    let mut seen = BTreeSet::new();
    let mut raw = Vec::new();
    for r in &p.public_records {
        let key = unhex(&r.public_key_hex)?;
        let msg = unhex(&r.message_hex)?;
        if key.len() != 64 || msg.len() != 32 || !seen.insert((key.clone(), msg.clone())) {
            return Err("public key/message format or repeated intended pair".into());
        }
        raw.push((key, msg));
    }
    let mut domain = b"FORS:BATCH\0\0".to_vec();
    domain.extend([1, 32, 16, 8]);
    if domain.len() != 16 {
        return Err("FORS domain encoding".into());
    }
    let states: Vec<_> = raw
        .chunks_exact(p.leaf_size)
        .map(|group| {
            let mut b = domain.clone();
            for (k, m) in group {
                b.extend(k);
                b.extend(m);
            }
            State {
                claim_digest: wrapper::halves(primitives::hash::hash(&b)),
                accumulators: vec![],
            }
        })
        .collect();
    if states.len() < 2 {
        return Err("at least two real leaves".into());
    }
    let slots = states.len().next_power_of_two();
    let depth = slots.ilog2() as usize;
    let mut semantics: Vec<_> = states.iter().map(|s| s.claim_digest).collect();
    semantics.resize(slots, *semantics.last().unwrap());
    while semantics.len() > 1 {
        semantics = semantics
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| wrapper::claim_digest(chunk))
            .collect::<std::result::Result<_, _>>()?;
    }
    Ok((states, semantics[0], slots, depth))
}
fn family_report(families: &[Family]) -> Value {
    json!(families.iter().enumerate().map(|(i,f)|json!({"family":i,"guest_hash":hex(&cpu::public_input_bytes(&f.seed)),"bytecode_instructions":f.program.prog.len(),"dimensions":f.dimensions,"table_words":f.table.len(),"min_log_committed":f.program.min_log_committed})).collect::<Vec<_>>())
}
fn verify_public(p: &Public, e: &Envelope, repeat: usize, expected_leaf: &str) -> Result<Value> {
    let now = Instant::now();
    let (_, semantic, slots, depth) = public_claims(p)?;
    let claim_s = now.elapsed().as_secs_f64();
    let now = Instant::now();
    let (policy, families) = wrapper::build(&p.leaf_source, depth, p.leaf_size)?;
    let compile_s = now.elapsed().as_secs_f64();
    if hex(&cpu::public_input_bytes(&families[0].seed)) != expected_leaf {
        return Err("caller-trusted leaf program mismatch".into());
    }
    let now = Instant::now();
    let verifier = Verifier::new(policy, &families, semantic, p.signatures, slots)?;
    let tables_s = now.elapsed().as_secs_f64();
    let now = Instant::now();
    let first = verifier.verify(e)?;
    let first_s = now.elapsed().as_secs_f64();
    let mut times = Vec::new();
    let mut cores = Vec::new();
    let mut evaluations = Vec::new();
    for pass in 0..repeat + 1 {
        let now = Instant::now();
        let checked = verifier.verify(e)?;
        let s = now.elapsed().as_secs_f64();
        if pass > 0 {
            times.push(s);
            cores.push(checked.root_core_s);
            evaluations.push(checked.terminal_evaluation_s);
        }
    }
    Ok(
        json!({"schema":1,"action":"verify","verified":true,"all_reduced_claims_settled":true,"uses_child_proof_files":false,"uses_signature_witnesses":false,"backend_revision":REVISION,"signatures":p.signatures,"leaf_size":p.leaf_size,"real_leaves":p.signatures/p.leaf_size,"leaf_slots":slots,"padding_slots":slots-p.signatures/p.leaf_size,"depth":depth,"original_tree_edges":2*(slots-1),"terminal_evaluations":depth,"public_claim_derivation_s":claim_s,"program_compile_s":compile_s,"table_prepare_s":tables_s,"first_complete_verify_s":first_s,"cold_complete_verify_s":compile_s+tables_s+first_s,"prepared_complete_verify_s":times,"prepared_complete_verify_median_s":median(&times),"root_core_s":cores,"terminal_evaluation_s":evaluations,"first_components":first,"families":family_report(&families),"zero_knowledge":false,"peak_rss_bytes":bench::peak_rss_bytes()}),
    )
}
fn prove(p: &Public, inputs: &Path, out: &Path) -> Result<Value> {
    if out.exists() && out.read_dir()?.next().is_some() {
        return Err("refusing to overwrite proving directory".into());
    }
    fs::create_dir_all(out)?;
    let pipeline_start = Instant::now();
    let now = Instant::now();
    let (mut states, semantic, slots, depth) = public_claims(p)?;
    let claim_s = now.elapsed().as_secs_f64();
    let real = states.len();
    let now = Instant::now();
    eprintln!("compile {depth} bounded wrapper levels");
    let (policy, families) = wrapper::build(&p.leaf_source, depth, p.leaf_size)?;
    let compile_s = now.elapsed().as_secs_f64();
    let mut report = json!({"schema":1,"action":"prove","status":"running","backend_revision":REVISION,"scheme":"fors","signatures":p.signatures,"leaf_size":p.leaf_size,"real_leaves":real,"leaf_slots":slots,"padding_slots":slots-real,"depth":depth,"merge_count":slots-1,"terminal_evaluations":depth,"original_tree_edges":2*(slots-1),"public_claim_derivation_s":claim_s,"program_compile_s":compile_s,"families":family_report(&families),"threads_env":std::env::var("LEANVM_NUM_THREADS").ok(),"leaf_reports":[],"merge_reports":[],"zero_knowledge":false});
    save(out.join("report.json"), &report)?;
    let mut proofs = Vec::new();
    let mut total_leaf = 0.;
    let mut total_merge = 0.;
    let mut native_reduction = 0.;
    let mut wrapper_stark = 0.;
    for (i, state) in states.iter().enumerate() {
        eprintln!("prove real FORS leaf {}/{real}", i + 1);
        let input: Input =
            serde_json::from_slice(&fs::read(inputs.join(format!("leaf-{i}.input.json")))?)?;
        if input.source != p.leaf_source
            || input.public_input.map(|a| F192::new(a[0], a[1], a[2])) != state.claim_digest
        {
            return Err("leaf fixture differs from intended source/claims".into());
        }
        let mut program = families[0].program.clone();
        for (name, rows) in input.witness {
            program.set_witness(
                name,
                rows.into_iter()
                    .map(|r| r.into_iter().map(|a| F192::new(a[0], a[1], a[2])).collect())
                    .collect(),
            );
        }
        let now = Instant::now();
        let (proof, stats) = cpu::prove(&program, state.claim_digest, 1)?;
        let prove_s = now.elapsed().as_secs_f64();
        cpu::verify(&families[0].program, &state.claim_digest, &proof)
            .map_err(|e| format!("leaf verification: {e:?}"))?;
        let encoded = bincode::serialize(&proof)?;
        fs::write(out.join(format!("leaf-{i}.proof")), &encoded)?;
        proofs.push(proof);
        total_leaf += prove_s;
        report["leaf_reports"].as_array_mut().unwrap().push(json!({"leaf":i,"signatures":p.leaf_size,"prove_s":prove_s,"proof_bytes":encoded.len(),"proof_sha256":hash(&encoded),"committed_words":stats.committed,"cycles":stats.cycles,"opcode_rows":stats.rows}));
        save(out.join("report.json"), &report)?;
    }
    proofs.resize(slots, proofs.last().unwrap().clone());
    states.resize(slots, states.last().unwrap().clone());
    let mut node = 0;
    for level in 1..=depth {
        let mut next_proofs = Vec::new();
        let mut next_states = Vec::new();
        for (i, (ps, ss)) in proofs
            .as_chunks::<2>()
            .0
            .iter()
            .zip(states.as_chunks::<2>().0.iter())
            .enumerate()
        {
            eprintln!(
                "level {level}/{depth} node {}/{}: verify children and prove sumchecks",
                i + 1,
                proofs.len() / 2
            );
            let now = Instant::now();
            let prepared = pipeline::prepare(policy, &families[..level], ss, ps)?;
            let prepare_s = now.elapsed().as_secs_f64();
            let mut program = families[level].program.clone();
            for (name, rows) in prepared.streams {
                program.set_witness(name, rows);
            }
            eprintln!("level {level} node {}: prove constrained wrapper", i + 1);
            let now = Instant::now();
            let (proof, stats) = cpu::prove(&program, prepared.public_input, 1)?;
            let stark_s = now.elapsed().as_secs_f64();
            cpu::verify(&families[level].program, &prepared.public_input, &proof)
                .map_err(|e| format!("wrapper verification: {e:?}"))?;
            let encoded = bincode::serialize(&proof)?;
            fs::write(out.join(format!("merge-{node}.proof")), &encoded)?;
            save(
                out.join(format!("merge-{node}.state.json")),
                &prepared.state,
            )?;
            report["merge_reports"].as_array_mut().unwrap().push(json!({"node":node,"level":level,"prepare_s":prepare_s,"native_reduction_prove_s":prepared.reduction_prove_s,"wrapper_stark_prove_s":stark_s,"total_prove_s":prepare_s+stark_s,"proof_bytes":encoded.len(),"proof_sha256":hash(&encoded),"committed_words":stats.committed,"cycles":stats.cycles,"opcode_rows":stats.rows,"terminal_families":level}));
            total_merge += prepare_s + stark_s;
            native_reduction += prepared.reduction_prove_s;
            wrapper_stark += stark_s;
            next_proofs.push(proof);
            next_states.push(prepared.state);
            node += 1;
            save(out.join("report.json"), &report)?;
        }
        proofs = next_proofs;
        states = next_states;
    }
    let envelope = Envelope {
        magic: receipt::MAGIC,
        signatures: p.signatures,
        slots,
        depth,
        policy,
        leaf_seed: families[0].seed,
        root_seed: families[depth].seed,
        state: states.pop().unwrap(),
        proof: proofs.pop().unwrap(),
    };
    let bytes = receipt::encode(&envelope)?;
    let decoded = receipt::decode(&bytes)?;
    let verifier = Verifier::new(policy, &families, semantic, p.signatures, slots)?;
    let now = Instant::now();
    let checked = verifier.verify(&decoded)?;
    let verify_s = now.elapsed().as_secs_f64();
    fs::write(out.join("root.proof"), &bytes)?;
    save(out.join("root-state.json"), &envelope.state)?;
    let core = bincode::serialize(&envelope.proof)?;
    report["status"] = json!("accepted");
    report["verified"] = json!(true);
    report["all_reduced_claims_settled"] = json!(true);
    report["leaf_prove_s"] = json!(total_leaf);
    report["merge_prove_s"] = json!(total_merge);
    report["native_reduction_prove_s"] = json!(native_reduction);
    report["wrapper_stark_prove_s"] = json!(wrapper_stark);
    report["total_prove_s"] = json!(total_leaf + total_merge);
    report["root_proof_bytes"] = json!(bytes.len());
    report["root_core_bytes"] = json!(core.len());
    report["root_auxiliary_bytes"] = json!(bytes.len() - core.len());
    report["root_proof_sha256"] = json!(hash(&bytes));
    report["full_verify_s"] = json!(verify_s);
    report["verification_components"] = json!(checked);
    report["pipeline_elapsed_s"] = json!(pipeline_start.elapsed().as_secs_f64());
    report["peak_rss_bytes"] = json!(bench::peak_rss_bytes());
    save(out.join("report.json"), &report)?;
    Ok(report)
}
fn main() -> Result<()> {
    leanvm_core::init_prover();
    let mut args = std::env::args().skip(1);
    let action = args.next().ok_or("expected plan,prove,verify")?;
    let mut opts = BTreeMap::new();
    while let Some(k) = args.next() {
        if ![
            "--public",
            "--out",
            "--inputs",
            "--proof",
            "--expect-public-sha256",
            "--expect-leaf-guest-hash",
            "--repeat",
        ]
        .contains(&k.as_str())
        {
            return Err(format!("unknown option {k}").into());
        }
        let v = args.next().ok_or("option value")?;
        if opts.insert(k, v).is_some() {
            return Err("duplicate option".into());
        }
    }
    let get = |k: &str| {
        opts.get(k)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {k}"))
    };
    let public = PathBuf::from(get("--public")?);
    let raw = fs::read(&public)?;
    let p: Public = serde_json::from_slice(&raw)?;
    let out = PathBuf::from(get("--out")?);
    if action == "verify" && hash(&raw) != get("--expect-public-sha256")? {
        return Err("caller-trusted public statement digest mismatch".into());
    }
    let mut report = match action.as_str() {
        "plan" => {
            let (_, _, slots, depth) = public_claims(&p)?;
            let now = Instant::now();
            let (policy, families) = wrapper::build(&p.leaf_source, depth, p.leaf_size)?;
            json!({"schema":1,"action":"plan","backend_revision":REVISION,"signatures":p.signatures,"leaf_size":p.leaf_size,"real_leaves":p.signatures/p.leaf_size,"leaf_slots":slots,"depth":depth,"terminal_evaluations":depth,"policy":policy,"leaf_guest_hash":hex(&cpu::public_input_bytes(&families[0].seed)),"root_guest_hash":hex(&cpu::public_input_bytes(&families[depth].seed)),"families":family_report(&families),"compile_s":now.elapsed().as_secs_f64()})
        }
        "prove" => prove(
            &p,
            Path::new(
                opts.get("--inputs")
                    .map(String::as_str)
                    .unwrap_or_else(|| public.parent().unwrap().to_str().unwrap()),
            ),
            &out,
        )?,
        "verify" => {
            let bytes = fs::read(get("--proof")?)?;
            let envelope = receipt::decode(&bytes)?;
            let repeat = opts.get("--repeat").map_or(Ok(3usize), |x| x.parse())?;
            if repeat == 0 {
                return Err("positive repeat".into());
            }
            let mut r = verify_public(&p, &envelope, repeat, get("--expect-leaf-guest-hash")?)?;
            r["root_proof_bytes"] = json!(bytes.len());
            r["root_proof_sha256"] = json!(hash(&bytes));
            r["caller_leaf_guest_hash"] = json!(get("--expect-leaf-guest-hash")?);
            r["statement_pinned"] = json!(true);
            r
        }
        _ => return Err("expected plan,prove,verify".into()),
    };
    report["public_sha256"] = json!(hash(&raw));
    report["leaf_source_sha256"] = json!(hash(p.leaf_source.as_bytes()));
    save(
        if action == "prove" {
            out.join("report.json")
        } else {
            out.clone()
        },
        &report,
    )?;
    println!(
        "{}",
        json!({"action":action,"signatures":p.signatures,"verified":report.get("verified"),"status":report.get("status"),"total_prove_s":report.get("total_prove_s"),"root_proof_bytes":report.get("root_proof_bytes"),"terminal_evaluations":report.get("terminal_evaluations")})
    );
    Ok(())
}
