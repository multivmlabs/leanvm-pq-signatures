//! Complete, pinned recursive-tree benchmark. No backend modifications.
use bench::{Counting, Jemalloc};
use leanvm::aggregate::{Kind, Leaf, LeafShape, Tree, TreeProof, TreeShape};
use leanvm::{Output, PerTable, Program, Proof, Prover, Rate, Stats, TableId};
use leanvm_guest::{PublicValues, Run};
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
static ALLOCATOR: Counting<Jemalloc> = Counting(Jemalloc);
const REVISION: &str = "06e5c9cd6981103786f9d0a17324241b559a50d3";
type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    schema: u32,
    backend_revision: String,
    scheme: String,
    signatures: usize,
    elf_sha256: String,
    leaf_size: usize,
    actual_leaves: usize,
    leaf_slots: usize,
    arity_0: usize,
    arity: usize,
    log_inverse_rate: u8,
    table_rows: Vec<usize>,
    expected_leaf_outputs: Vec<[u64; 4]>,
    public_records: Vec<Value>,
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
fn field(r: &Value, name: &str) -> Result<Vec<u8>> {
    unhex(
        r.get(name)
            .and_then(Value::as_str)
            .ok_or("missing public record field")?,
    )
}
fn save(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    let path = path.as_ref();
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn median(v: &[f64]) -> f64 {
    let mut v = v.to_vec();
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}
fn elf(scheme: &str) -> Result<&'static [u8]> {
    match scheme {
        "falcon" => Ok(falcon_host::ELF),
        "mldsa" => Ok(mldsa_riscv_host::ELF),
        _ => Err("unsupported scheme".into()),
    }
}
fn expected(scheme: &str, records: &[Value]) -> Result<[u64; 4]> {
    if records.is_empty() || records.len() > 100 {
        return Err("a leaf must contain between one and 100 public claims".into());
    }
    match scheme {
        "falcon" => {
            let mut p = PublicValues::new();
            for r in records {
                let pk = field(r, "public_key")?;
                let msg = field(r, "message")?;
                if pk.len() != 897 || pk[0] != 9 || msg.len() != 32 {
                    return Err("invalid Falcon public record".into());
                }
                let key: [u64; 112] = std::array::from_fn(|i| {
                    u64::from_be_bytes(pk[1 + i * 8..1 + i * 8 + 8].try_into().unwrap())
                });
                let msg: [u64; 4] = std::array::from_fn(|i| {
                    u64::from_le_bytes(msg[i * 8..i * 8 + 8].try_into().unwrap())
                });
                p.commit(&key).commit(&msg);
            }
            Ok(p.digest())
        }
        "mldsa" => {
            let records = records
                .iter()
                .map(|r| {
                    Ok(mldsa_riscv_host::PublicRecord {
                        public_key: field(r, "public_key")?
                            .try_into()
                            .map_err(|_| "ML-DSA key length")?,
                        message: field(r, "message")?
                            .try_into()
                            .map_err(|_| "ML-DSA message length")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(mldsa_riscv_host::expected_output(&records))
        }
        _ => Err("unsupported scheme".into()),
    }
}

/// Prepare all 100 distinct records once; never included in proving timers.
fn corpus(scheme: &str, leaf_size: usize) -> Result<(Vec<Run>, Vec<Value>)> {
    let mut runs = Vec::new();
    let mut public = Vec::new();
    match scheme {
        "falcon" => {
            let all = falcon_host::batch(100);
            if all.advice.len() != 1 + 100 * 201 {
                return Err("Falcon advice length".into());
            }
            for group in all.advice[1..].chunks_exact(leaf_size * 201) {
                let mut claims = Vec::new();
                for record in group.as_chunks::<201>().0 {
                    let mut key = vec![9];
                    key.extend(record[..112].iter().flat_map(|w| w.to_be_bytes()));
                    let msg: Vec<_> = record[112..116]
                        .iter()
                        .flat_map(|w| w.to_le_bytes())
                        .collect();
                    claims.push(json!({"public_key":hex(&key),"message":hex(&msg)}));
                }
                let mut advice = vec![leaf_size as u64];
                advice.extend_from_slice(group);
                runs.push(Run {
                    advice,
                    expected: expected(scheme, &claims)?,
                });
                public.extend(claims);
            }
        }
        "mldsa" => {
            for start in (0..100).step_by(leaf_size) {
                let records = mldsa_riscv_host::records(start, leaf_size);
                let claims:Vec<_>=records.iter().map(|r|json!({"public_key":hex(&r.public.public_key),"message":hex(&r.public.message)})).collect();
                let run = mldsa_riscv_host::run_from_records(&records);
                if run.expected != expected(scheme, &claims)? {
                    return Err("ML-DSA public expected output mismatch".into());
                }
                runs.push(run);
                public.extend(claims);
            }
        }
        _ => return Err("unsupported scheme".into()),
    }
    let keys: BTreeSet<_> = public
        .iter()
        .map(|r| r["public_key"].as_str().unwrap())
        .collect();
    if keys.len() != 100 {
        return Err("corpus must contain 100 distinct public keys".into());
    }
    Ok((runs, public))
}
fn stats_json(s: &Stats) -> Value {
    json!({"cycles":s.cycles(),"committed_words":s.committed,"proven_rows":s.proven_rows,"rows":s.base_counts.iter().map(|(t,n)|(t.name(),*n)).collect::<BTreeMap<_,_>>(),"padded_rows":s.counts.iter().map(|(t,n)|(t.name(),*n)).collect::<BTreeMap<_,_>>()})
}
fn circuit_json(tree: &Tree<'_>, kind: Kind) -> Value {
    let s = tree.stats(kind);
    json!({"committed_words":s.committed,"tables":s.tables.iter().map(|t|json!({"name":t.name,"rows":t.rows,"height_log":t.height_log})).collect::<Vec<_>>()})
}

/// Public API adapter: LeafShape's constructor takes Stats, whose constructor is
/// private. Obtain a Stats container from a harmless exit-only program, then set
/// its public table heights from the caller-trusted descriptor. No signature,
/// advice witness or child proof is used. LeafShape::measured reads counts only.
fn trusted_shape(s: &Statement) -> Result<LeafShape> {
    if s.table_rows.len() != TableId::ALL.len()
        || s.table_rows
            .iter()
            .any(|&n| !n.is_power_of_two() || n > (1usize << 28))
    {
        return Err("invalid trusted table heights".into());
    }
    let text = leanvm::asm::Asm::new().exit().finish();
    let p = Program::new(&text, leanvm::Region::TEXT.base(), vec![], 0, 0)?;
    let mut stats = p.measure(&[])?;
    stats.counts = PerTable::from_fn(|t: TableId| s.table_rows[t.index()]);
    Ok(LeafShape::measured(&stats, Rate::new(s.log_inverse_rate)?))
}
fn tree_shape(s: &Statement) -> Result<TreeShape> {
    Ok(TreeShape {
        leaf: trusted_shape(s)?,
        arity_0: s.arity_0,
        arity: s.arity,
        rate: Rate::new(s.log_inverse_rate)?,
        claims: None,
    })
}
fn public_outputs(s: &Statement) -> Result<Vec<Output>> {
    if s.schema != 1
        || s.backend_revision != REVISION
        || ![1, 2, 5, 10].contains(&s.leaf_size)
        || s.signatures == 0
        || s.signatures > 100
        || !s.signatures.is_multiple_of(s.leaf_size)
        || s.public_records.len() != s.signatures
        || s.actual_leaves != s.signatures / s.leaf_size
        || s.leaf_slots != s.actual_leaves.next_power_of_two().max(2)
        || s.arity_0 != 2
        || s.arity != 2
        || s.leaf_slots < 2
        || s.expected_leaf_outputs.len() != s.actual_leaves
        || hash(elf(&s.scheme)?) != s.elf_sha256
    {
        return Err("invalid trusted tree configuration".into());
    }
    let keys: BTreeSet<_> = s
        .public_records
        .iter()
        .map(|r| field(r, "public_key"))
        .collect::<Result<_>>()?;
    if keys.len() != s.signatures {
        return Err("repeated public key in intended records".into());
    }
    let actual = s
        .public_records
        .chunks_exact(s.leaf_size)
        .map(|r| expected(&s.scheme, r))
        .collect::<Result<Vec<_>>>()?;
    if actual != s.expected_leaf_outputs {
        return Err("cached leaf output differs from intended public records".into());
    }
    let mut outputs: Vec<_> = actual.into_iter().map(Output::new).collect();
    outputs.resize(s.leaf_slots, *outputs.last().ok_or("no actual leaf")?);
    Ok(outputs)
}

fn plan(scheme: &str, n: usize, leaf_size: usize, rate: Rate, out: &Path) -> Result<Value> {
    if ![1, 2, 5, 10].contains(&leaf_size) || !n.is_multiple_of(leaf_size) {
        return Err("invalid leaf size".into());
    }
    if ![10, 30, 70, 100].contains(&n) {
        return Err("supported signature counts: 10,30,70,100".into());
    }
    let now = Instant::now();
    let (runs, public) = corpus(scheme, leaf_size)?;
    let fixture_s = now.elapsed().as_secs_f64();
    let now = Instant::now();
    let program = Program::from_elf(elf(scheme)?)?;
    let load_s = now.elapsed().as_secs_f64();
    let mut reports = Vec::new();
    let mut shapes = Vec::new();
    let mut first_stats = None;
    for (i, run) in runs.iter().enumerate() {
        eprintln!("measure {scheme} corpus leaf {}/{}", i + 1, runs.len());
        let now = Instant::now();
        let stats = program.measure(&run.advice)?;
        let shape = LeafShape::measured(&stats, rate);
        shapes.push(shape);
        reports.push(json!({"leaf":i,"measure_s":now.elapsed().as_secs_f64(),"execution":stats_json(&stats),"expected_output":run.expected}));
        if first_stats.is_none() {
            first_stats = Some(stats);
        }
    }
    let stats = first_stats.unwrap();
    let shapes_match = shapes.iter().all(|s| *s == shapes[0]);
    let count = n / leaf_size;
    let statement = Statement {
        schema: 1,
        backend_revision: REVISION.into(),
        scheme: scheme.into(),
        signatures: n,
        elf_sha256: hash(elf(scheme)?),
        leaf_size,
        actual_leaves: count,
        leaf_slots: count.next_power_of_two().max(2),
        arity_0: 2,
        arity: 2,
        log_inverse_rate: rate.log_inv_rate(),
        table_rows: TableId::ALL.iter().map(|&t| stats.counts[t]).collect(),
        expected_leaf_outputs: runs[..count].iter().map(|r| r.expected).collect(),
        public_records: public[..n].to_vec(),
    };
    save(out.join("statement.json"), &statement)?;
    let mut report = json!({"schema":1,"action":"plan","scheme":scheme,"signatures":n,"backend_revision":REVISION,"elf_sha256":statement.elf_sha256,"fixture_s":fixture_s,"program_load_s":load_s,"all_100_corpus_leaf_shapes_match":shapes_match,"leaf_size":leaf_size,"actual_leaves":count,"leaf_slots":statement.leaf_slots,"padding_slots":statement.leaf_slots-count,"leaf_measurements":reports});
    if !shapes_match {
        report["status"] = json!("leaf_shape_mismatch");
        save(out.join("plan.json"), &report)?;
        return Err("corpus leaves have different padded table heights; see plan.json".into());
    }
    let now = Instant::now();
    eprintln!("build {scheme} recursion tree key");
    match Tree::new(&program, tree_shape(&statement)?) {
        Ok(tree) => {
            report["tree_setup_s"] = json!(now.elapsed().as_secs_f64());
            report["first_circuit"] = circuit_json(&tree, Kind::First);
            report["node_circuit"] = circuit_json(&tree, Kind::Node);
            report["status"] = json!("accepted");
        }
        Err(e) => {
            report["status"] = json!("rejected");
            report["error"] = json!(format!("{e:?}"));
            save(out.join("plan.json"), &report)?;
            return Err(e.into());
        }
    }
    report["statement_sha256"] = json!(hash(&fs::read(out.join("statement.json"))?));
    report["peak_rss_bytes"] = json!(bench::peak_rss_bytes());
    save(out.join("plan.json"), &report)?;
    Ok(report)
}

fn prepared_verify(tree: &Tree<'_>, bytes: &[u8], outputs: &[Output]) -> Result<Vec<f64>> {
    let mut samples = Vec::new();
    for pass in 0..4 {
        let now = Instant::now();
        let root = TreeProof::from_bytes(bytes)?;
        tree.verify(&root, outputs)?;
        if pass > 0 {
            samples.push(now.elapsed().as_secs_f64());
        }
    }
    Ok(samples)
}

fn verify_public(statement: &Statement, bytes: &[u8], controls: bool) -> Result<Value> {
    let now = Instant::now();
    let outputs = public_outputs(statement)?;
    let claim_s = now.elapsed().as_secs_f64();
    let now = Instant::now();
    let program = Program::from_elf(elf(&statement.scheme)?)?;
    let load_s = now.elapsed().as_secs_f64();
    let now = Instant::now();
    let tree = Tree::new(&program, tree_shape(statement)?)?;
    let setup_s = now.elapsed().as_secs_f64();
    let now = Instant::now();
    let root = TreeProof::from_bytes(bytes)?;
    tree.verify(&root, &outputs)?;
    let first_s = now.elapsed().as_secs_f64();
    let times = prepared_verify(&tree, bytes, &outputs)?;
    let mut report = json!({"schema":1,"action":"verify","verified":true,"statement_pinned":true,"backend_revision":REVISION,"scheme":statement.scheme,"signatures":statement.signatures,"actual_leaves":statement.actual_leaves,"leaf_slots":statement.leaf_slots,"public_claim_derivation_s":claim_s,"program_load_s":load_s,"tree_setup_s":setup_s,"first_complete_verify_s":first_s,"cold_complete_verify_s":load_s+setup_s+first_s,"prepared_complete_verify_s":times,"prepared_complete_verify_median_s":median(&times),"root_proof_bytes":bytes.len(),"root_proof_sha256":hash(bytes),"verification_uses_child_proofs":false,"verification_uses_signatures":false,"all_folded_claims_settled":true,"zero_knowledge":false,"peak_rss_bytes":bench::peak_rss_bytes()});
    if controls {
        let mut outcomes = BTreeMap::new();
        let mut wrong = outputs.clone();
        let mut words = *wrong[0].words();
        words[0] ^= 1;
        wrong[0] = Output::new(words);
        outcomes.insert("wrong_output", tree.verify(&root, &wrong).is_err());
        if statement.actual_leaves >= 2 {
            let mut wrong = outputs.clone();
            wrong.swap(0, 1);
            outcomes.insert("reordered_leaves", tree.verify(&root, &wrong).is_err());
        } else {
            report["controls_not_applicable"] = json!([
                "reordered_leaves: one actual leaf, all slots contain the same canonical output"
            ]);
        }
        let mut wrong = outputs.clone();
        wrong.pop();
        outcomes.insert("wrong_leaf_count", tree.verify(&root, &wrong).is_err());
        let mut corrupt = bytes.to_vec();
        let middle = corrupt.len() / 2;
        corrupt[middle] ^= 1;
        outcomes.insert(
            "corrupt_root",
            TreeProof::from_bytes(&corrupt).map_or(true, |p| tree.verify(&p, &outputs).is_err()),
        );
        let mut trailing = bytes.to_vec();
        trailing.push(255);
        outcomes.insert(
            "trailing_byte",
            TreeProof::from_bytes(&trailing).map_or(true, |p| tree.verify(&p, &outputs).is_err()),
        );
        let mut changed = statement.clone();
        let mut pk = field(&changed.public_records[0], "public_key")?;
        let i = pk.len() - 1;
        pk[i] ^= 1;
        changed.public_records[0]["public_key"] = json!(hex(&pk));
        changed.expected_leaf_outputs[0] = expected(
            &changed.scheme,
            &changed.public_records[..statement.leaf_size],
        )?;
        let changed_outputs = public_outputs(&changed)?;
        outcomes.insert(
            "changed_key_recommitted",
            tree.verify(&root, &changed_outputs).is_err(),
        );
        let mut changed = statement.clone();
        let mut msg = field(&changed.public_records[0], "message")?;
        msg[0] ^= 1;
        changed.public_records[0]["message"] = json!(hex(&msg));
        changed.expected_leaf_outputs[0] = expected(
            &changed.scheme,
            &changed.public_records[..statement.leaf_size],
        )?;
        let changed_outputs = public_outputs(&changed)?;
        outcomes.insert(
            "changed_message_recommitted",
            tree.verify(&root, &changed_outputs).is_err(),
        );
        if outcomes.values().any(|v| !*v) {
            return Err(format!("a root consumer negative control accepted: {outcomes:?}").into());
        }
        report["controls"] = json!(outcomes);
    }
    Ok(report)
}

fn prove(
    scheme: &str,
    n: usize,
    leaf_size: usize,
    rate: Rate,
    out: &Path,
    sample: &str,
) -> Result<Value> {
    if ![10, 30, 70, 100].contains(&n)
        || ![1, 2, 5, 10].contains(&leaf_size)
        || !n.is_multiple_of(leaf_size)
    {
        return Err("invalid signature count or leaf size".into());
    }
    let pipeline = Instant::now();
    let now = Instant::now();
    let (all_runs, all_public) = corpus(scheme, leaf_size)?;
    let fixture_s = now.elapsed().as_secs_f64();
    let statement: Statement = serde_json::from_slice(&fs::read(out.join("statement.json"))?)?;
    if statement.scheme != scheme
        || statement.signatures != n
        || statement.leaf_size != leaf_size
        || statement.log_inverse_rate != rate.log_inv_rate()
        || statement.public_records != all_public[..n]
    {
        return Err(
            "prepared statement does not match deterministic intended corpus/config".into(),
        );
    }
    let outputs = public_outputs(&statement)?;
    let now = Instant::now();
    let program = Program::from_elf(elf(scheme)?)?;
    let load_s = now.elapsed().as_secs_f64();
    let shape = tree_shape(&statement)?;
    let now = Instant::now();
    let tree = Tree::new(&program, shape)?;
    let setup_s = now.elapsed().as_secs_f64();
    let prover = Prover::new(rate);
    let run_dir = out.join(sample);
    if run_dir.exists() {
        return Err(
            "sample directory exists; choose a new sample to avoid cached proof reuse".into(),
        );
    }
    fs::create_dir_all(&run_dir)?;
    let mut report = json!({"schema":1,"action":"prove","status":"running","backend_revision":REVISION,"scheme":scheme,"signatures":n,"sample":sample,"elf_sha256":statement.elf_sha256,"statement_sha256":hash(&fs::read(out.join("statement.json"))?),"leaf_size":leaf_size,"actual_leaves":statement.actual_leaves,"leaf_slots":statement.leaf_slots,"padding_slots":statement.leaf_slots-statement.actual_leaves,"padding_policy":"Repeat final real leaf proof in canonical padding slots; no extra signatures counted. All merge proofs freshly produced and charged.","arity_0":2,"arity":2,"log_inverse_rate":rate.log_inv_rate(),"fixture_s":fixture_s,"program_load_s":load_s,"tree_setup_s":setup_s,"first_circuit":circuit_json(&tree,Kind::First),"node_circuit":circuit_json(&tree,Kind::Node),"leaf_reports":[],"merge_reports":[],"zero_knowledge":false});
    save(run_dir.join("report.json"), &report)?;
    let mut leaf_proofs = Vec::new();
    let mut leaf_times = Vec::new();
    for (i, run) in all_runs.iter().take(statement.actual_leaves).enumerate() {
        eprintln!(
            "{scheme} N={n} {sample}: prove leaf {}/{}",
            i + 1,
            statement.actual_leaves
        );
        let now = Instant::now();
        let made = prover.prove(&program, &run.advice)?;
        let prove_s = now.elapsed().as_secs_f64();
        if made.output != outputs[i] || LeafShape::of(&made.proof)? != shape.leaf {
            return Err("leaf output or shape mismatch".into());
        }
        let bytes = made.proof.to_bytes();
        let now = Instant::now();
        let decoded = Proof::from_bytes(&bytes)?;
        program.verify(outputs[i], &decoded)?;
        let verify_s = now.elapsed().as_secs_f64();
        fs::write(run_dir.join(format!("leaf-{i}.proof")), &bytes)?;
        report["leaf_reports"].as_array_mut().unwrap().push(json!({"leaf":i,"signatures":leaf_size,"prove_s":prove_s,"verify_s":verify_s,"proof_bytes":bytes.len(),"proof_sha256":hash(&bytes),"execution":stats_json(&made.stats)}));
        leaf_times.push(prove_s);
        leaf_proofs.push(decoded);
        save(run_dir.join("report.json"), &report)?;
    }
    let leaves: Vec<_> = (0..statement.leaf_slots)
        .map(|i| {
            let real = i.min(statement.actual_leaves - 1);
            Leaf::new(&leaf_proofs[real], outputs[i])
        })
        .collect();
    let mut level = Vec::new();
    let mut merge_times = Vec::new();
    let mut node_index = 0usize;
    for (index, chunk) in leaves.chunks(2).enumerate() {
        eprintln!(
            "{scheme} N={n} {sample}: first-level merge {}/{}",
            index + 1,
            leaves.len() / 2
        );
        let now = Instant::now();
        let made = tree.prove_first(chunk)?;
        let elapsed = now.elapsed().as_secs_f64();
        let bytes = made.to_bytes();
        let decoded = TreeProof::from_bytes(&bytes)?;
        fs::write(run_dir.join(format!("merge-{node_index}.proof")), &bytes)?;
        report["merge_reports"].as_array_mut().unwrap().push(json!({"node":node_index,"level":0,"kind":"first","children":2,"prove_s":elapsed,"proof_bytes":bytes.len(),"proof_sha256":hash(&bytes)}));
        merge_times.push(elapsed);
        level.push(decoded);
        node_index += 1;
        save(run_dir.join("report.json"), &report)?;
    }
    let mut depth = 1;
    while level.len() > 1 {
        let mut next = Vec::new();
        for (index, chunk) in level.chunks(2).enumerate() {
            eprintln!(
                "{scheme} N={n} {sample}: level {depth} merge {}/{}",
                index + 1,
                level.len() / 2
            );
            let now = Instant::now();
            let made = tree.prove_node(chunk)?;
            let elapsed = now.elapsed().as_secs_f64();
            let bytes = made.to_bytes();
            let decoded = TreeProof::from_bytes(&bytes)?;
            fs::write(run_dir.join(format!("merge-{node_index}.proof")), &bytes)?;
            report["merge_reports"].as_array_mut().unwrap().push(json!({"node":node_index,"level":depth,"kind":"node","children":2,"prove_s":elapsed,"proof_bytes":bytes.len(),"proof_sha256":hash(&bytes)}));
            merge_times.push(elapsed);
            next.push(decoded);
            node_index += 1;
            save(run_dir.join("report.json"), &report)?;
        }
        level = next;
        depth += 1;
    }
    let root = level.pop().ok_or("no root")?;
    let bytes = root.to_bytes();
    fs::write(run_dir.join("root.proof"), &bytes)?;
    let verify_s = prepared_verify(&tree, &bytes, &outputs)?;
    report["status"] = json!("accepted");
    report["verified"] = json!(true);
    report["all_folded_claims_settled"] = json!(true);
    report["leaf_prove_s"] = json!(leaf_times.iter().sum::<f64>());
    report["merge_prove_s"] = json!(merge_times.iter().sum::<f64>());
    report["total_prove_s"] = json!(leaf_times.iter().chain(&merge_times).sum::<f64>());
    report["root_proof_bytes"] = json!(bytes.len());
    report["root_proof_sha256"] = json!(hash(&bytes));
    report["prepared_complete_verify_s"] = json!(verify_s);
    report["merge_count"] = json!(node_index);
    report["depth"] = json!(depth);
    report["peak_rss_bytes"] = json!(bench::peak_rss_bytes());
    report["pipeline_elapsed_s"] = json!(pipeline.elapsed().as_secs_f64());
    save(run_dir.join("report.json"), &report)?;
    Ok(report)
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let action = args.next().ok_or("expected plan,prove,verify")?;
    let mut opts = BTreeMap::new();
    while let Some(k) = args.next() {
        if ![
            "--scheme",
            "--n",
            "--outdir",
            "--sample",
            "--threads",
            "--rate",
            "--statement",
            "--proof",
            "--expect-statement-sha256",
            "--expect-elf-sha256",
            "--controls",
            "--leaf-size",
        ]
        .contains(&k.as_str())
        {
            return Err(format!("unknown option {k}").into());
        }
        let v = args.next().ok_or("missing option value")?;
        if opts.insert(k, v).is_some() {
            return Err("duplicate option".into());
        }
    }
    let get = |k: &str| {
        opts.get(k)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {k}"))
    };
    let number =
        |k: &str, d: usize| -> Result<usize> { Ok(opts.get(k).map_or(Ok(d), |s| s.parse())?) };
    let out = PathBuf::from(get("--outdir")?);
    fs::create_dir_all(&out)?;
    let threads = number("--threads", 8)?;
    parallel::init_with_threads(std::num::NonZeroUsize::new(threads).ok_or("zero threads")?)
        .map_err(|e| format!("threads: {e:?}"))?;
    let rate = Rate::new(number("--rate", 1)?.try_into()?)?;
    let result = match action.as_str() {
        "plan" => plan(
            get("--scheme")?,
            number("--n", 10)?,
            number(
                "--leaf-size",
                if get("--scheme")? == "falcon" { 10 } else { 5 },
            )?,
            rate,
            &out,
        ),
        "prove" => prove(
            get("--scheme")?,
            number("--n", 10)?,
            number(
                "--leaf-size",
                if get("--scheme")? == "falcon" { 10 } else { 5 },
            )?,
            rate,
            &out,
            opts.get("--sample")
                .map(String::as_str)
                .unwrap_or("sample-0"),
        ),
        "verify" => {
            let statement_path = opts
                .get("--statement")
                .map(PathBuf::from)
                .unwrap_or_else(|| out.join("statement.json"));
            let raw = fs::read(&statement_path)?;
            if hash(&raw) != get("--expect-statement-sha256")? {
                return Err("caller-trusted statement digest mismatch".into());
            }
            let s: Statement = serde_json::from_slice(&raw)?;
            if s.elf_sha256 != get("--expect-elf-sha256")?
                || hash(elf(&s.scheme)?) != get("--expect-elf-sha256")?
            {
                return Err("caller-trusted ELF digest mismatch".into());
            }
            if let Some(scheme) = opts.get("--scheme")
                && *scheme != s.scheme
            {
                return Err("CLI scheme mismatch".into());
            }
            let proof_path = opts
                .get("--proof")
                .map(PathBuf::from)
                .ok_or("verify needs --proof")?;
            let bytes = fs::read(proof_path)?;
            let mut report = verify_public(
                &s,
                &bytes,
                opts.get("--controls").is_some_and(|v| v == "true"),
            )?;
            report["statement_sha256"] = json!(hash(&raw));
            report["elf_sha256"] = json!(s.elf_sha256);
            save(out.join("verification.json"), &report)?;
            Ok(report)
        }
        _ => Err("expected plan,prove,verify".into()),
    };
    match result {
        Ok(mut report) => {
            report["threads_requested"] = json!(threads);
            match action.as_str() {
                "plan" => save(out.join("plan.json"), &report)?,
                "prove" => save(
                    out.join(
                        opts.get("--sample")
                            .map(String::as_str)
                            .unwrap_or("sample-0"),
                    )
                    .join("report.json"),
                    &report,
                )?,
                "verify" => save(out.join("verification.json"), &report)?,
                _ => (),
            };
            let summary = json!({"action":action,"status":report.get("status"),"scheme":report.get("scheme"),"signatures":report.get("signatures"),"verified":report.get("verified"),"root_proof_bytes":report.get("root_proof_bytes"),"total_prove_s":report.get("total_prove_s"),"outdir":out});
            println!("{summary}");
            Ok(())
        }
        Err(e) => {
            save(
                out.join("error.json"),
                &json!({"action":action,"error":e.to_string(),"backend_revision":REVISION}),
            )?;
            Err(e)
        }
    }
}
