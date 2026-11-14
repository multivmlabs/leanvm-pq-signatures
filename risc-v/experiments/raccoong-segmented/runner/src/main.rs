//! Complete authenticated-part Raccoon-G trees. The receiver trusts no witness digest.
use bench::{Counting, Jemalloc};
use host::{Binding, PARTS_PER_SIGNATURE, PublicRecord, ROW_COUNT, ROWS_PER_LEAF};
use leanvm::aggregate::{Kind, Leaf, LeafShape, Tree, TreeProof, TreeShape};
use leanvm::{Output, PerTable, Program, Proof, Prover, Rate, Stats, TableId};
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
const MAGIC: &[u8; 8] = b"RGSTK001";
const MAX_RECEIPT: usize = 16 * 1024 * 1024;
const PROFILE: &str = "raccoong-hd-authors-poc-strict-segmented-v1";
const BUILD_MANIFEST: &str = include_str!("../../build-manifest.json");
type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicBytes {
    public_key: String,
    message: String,
}

/// Caller-authenticated policy and original public claims. No D or witness here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    schema: u32,
    backend_revision: String,
    scheme: String,
    profile: String,
    signatures: usize,
    elf_sha256: String,
    parts_per_signature: usize,
    rows_per_leaf: usize,
    rows_per_signature: usize,
    actual_leaves: usize,
    leaf_slots: usize,
    arity_0: usize,
    arity: usize,
    log_inverse_rate: u8,
    table_rows: Vec<usize>,
    public_records: Vec<PublicBytes>,
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
fn public_record(p: &PublicBytes) -> Result<PublicRecord> {
    Ok(PublicRecord {
        public_key: unhex(&p.public_key)?
            .try_into()
            .map_err(|_| "public key must have 16144 bytes")?,
        message: unhex(&p.message)?
            .try_into()
            .map_err(|_| "message must have 32 bytes")?,
    })
}
fn public_bytes(p: &PublicRecord) -> PublicBytes {
    PublicBytes {
        public_key: hex(&p.public_key),
        message: hex(&p.message),
    }
}
fn save(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    let path = path.as_ref();
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn median(xs: &[f64]) -> f64 {
    let mut xs = xs.to_vec();
    xs.sort_by(f64::total_cmp);
    xs[xs.len() / 2]
}
fn allowed_n(n: usize) -> bool {
    [1, 2, 10, 30, 70, 100].contains(&n)
}
fn identity() -> Result<Value> {
    let manifest: Value = serde_json::from_str(BUILD_MANIFEST)?;
    let elf_hash = hash(host::ELF);
    if manifest["elf_sha256"].as_str() != Some(&elf_hash) {
        return Err("embedded guest differs from embedded build manifest".into());
    }
    Ok(
        json!({"schema":1,"action":"identity","backend_revision":REVISION,"profile":PROFILE,
        "embedded_elf_sha256":elf_hash,"embedded_elf_bytes":host::ELF.len(),
        "embedded_build_manifest_sha256":hash(BUILD_MANIFEST.as_bytes()),
        "parts_per_signature":PARTS_PER_SIGNATURE,"rows_per_leaf":ROWS_PER_LEAF,"rows_per_signature":ROW_COUNT,
        "executes_guest":false,"produces_proof":false}),
    )
}
fn slots(n: usize) -> usize {
    (n * PARTS_PER_SIGNATURE).next_power_of_two().max(2)
}
fn stats_json(s: &Stats) -> Value {
    json!({"cycles":s.cycles(),"committed_words":s.committed,"proven_rows":s.proven_rows,
        "rows":s.base_counts.iter().map(|(t,n)|(t.name(),*n)).collect::<BTreeMap<_,_>>(),
        "padded_rows":s.counts.iter().map(|(t,n)|(t.name(),*n)).collect::<BTreeMap<_,_>>()})
}
fn circuit_json(tree: &Tree<'_>, kind: Kind) -> Value {
    let s = tree.stats(kind);
    json!({"committed_words":s.committed,"tables":s.tables.iter().map(|t|json!({"name":t.name,"rows":t.rows,"height_log":t.height_log})).collect::<Vec<_>>()})
}

fn validate_statement(s: &Statement) -> Result<Vec<PublicRecord>> {
    if s.schema != 1
        || s.backend_revision != REVISION
        || s.scheme != "raccoon-g"
        || s.profile != PROFILE
        || !allowed_n(s.signatures)
        || s.elf_sha256 != hash(host::ELF)
        || s.parts_per_signature != PARTS_PER_SIGNATURE
        || s.rows_per_leaf != ROWS_PER_LEAF
        || s.rows_per_signature != ROW_COUNT
        || s.actual_leaves != s.signatures * PARTS_PER_SIGNATURE
        || s.leaf_slots != slots(s.signatures)
        || s.arity_0 != 2
        || s.arity != 2
        || s.log_inverse_rate != 1
        || s.public_records.len() != s.signatures
        || s.table_rows.len() != TableId::ALL.len()
        || s.table_rows
            .iter()
            .any(|&n| !n.is_power_of_two() || n > (1usize << 28))
    {
        return Err("invalid caller-authorized segmented tree statement".into());
    }
    let public = s
        .public_records
        .iter()
        .map(public_record)
        .collect::<Result<Vec<_>>>()?;
    let distinct: BTreeSet<_> = public.iter().map(|p| p.public_key.as_slice()).collect();
    if distinct.len() != s.signatures {
        return Err("benchmark statement must contain distinct public keys".into());
    }
    Ok(public)
}

fn shape(s: &Statement) -> Result<TreeShape> {
    // The pinned public LeafShape API reads only Stats.counts. The actual Tree
    // always receives the approved signature program, never this container stub.
    let text = leanvm::asm::Asm::new().exit().finish();
    let stub = Program::new(&text, leanvm::Region::TEXT.base(), vec![], 0, 0)?;
    let mut stats = stub.measure(&[])?;
    stats.counts = PerTable::from_fn(|t: TableId| s.table_rows[t.index()]);
    let rate = Rate::new(s.log_inverse_rate)?;
    Ok(TreeShape {
        leaf: LeafShape::measured(&stats, rate),
        arity_0: 2,
        arity: 2,
        rate,
        claims: None,
    })
}

/// Sender-controlled auxiliary data. The authenticated statement never contains these D values.
#[derive(Clone)]
struct Envelope {
    bindings: Vec<Binding>,
    core: Vec<u8>,
}
impl Envelope {
    fn encode(&self, s: &Statement) -> Result<Vec<u8>> {
        if self.bindings.len() != s.signatures {
            return Err("binding count".into());
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        for n in [s.signatures, s.parts_per_signature, s.leaf_slots] {
            bytes.extend_from_slice(&u32::try_from(n)?.to_le_bytes());
        }
        bytes.extend(unhex(&s.elf_sha256)?);
        for binding in &self.bindings {
            for word in binding {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&u64::try_from(self.core.len())?.to_le_bytes());
        bytes.extend_from_slice(&self.core);
        if bytes.len() > MAX_RECEIPT {
            return Err("receipt size bound".into());
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8], s: &Statement) -> Result<Self> {
        fn take<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<[u8; N]> {
            let end = at.checked_add(N).ok_or("receipt offset overflow")?;
            let value = bytes
                .get(*at..end)
                .ok_or("truncated receipt")?
                .try_into()
                .unwrap();
            *at = end;
            Ok(value)
        }
        if bytes.len() > MAX_RECEIPT {
            return Err("receipt size bound".into());
        }
        let mut at = 0;
        if &take::<8>(bytes, &mut at)? != MAGIC {
            return Err("receipt magic".into());
        }
        for expected in [s.signatures, s.parts_per_signature, s.leaf_slots] {
            if u32::from_le_bytes(take(bytes, &mut at)?) as usize != expected {
                return Err("receipt policy/count mismatch".into());
            }
        }
        if take::<32>(bytes, &mut at)?.as_slice() != unhex(&s.elf_sha256)? {
            return Err("receipt guest mismatch".into());
        }
        let mut bindings = Vec::with_capacity(s.signatures);
        for _ in 0..s.signatures {
            let mut binding = [0; 8];
            for word in &mut binding {
                *word = u64::from_le_bytes(take(bytes, &mut at)?);
            }
            bindings.push(binding);
        }
        let length = usize::try_from(u64::from_le_bytes(take(bytes, &mut at)?))?;
        let end = at.checked_add(length).ok_or("receipt length overflow")?;
        if end != bytes.len() {
            return Err("truncated receipt or trailing bytes".into());
        }
        Ok(Self {
            bindings,
            core: bytes.get(at..end).ok_or("truncated proof")?.to_vec(),
        })
    }
}

fn outputs(s: &Statement, public: &[PublicRecord], bindings: &[Binding]) -> Result<Vec<Output>> {
    if public.len() != s.signatures || bindings.len() != s.signatures {
        return Err("incomplete original-pair or binding coverage".into());
    }
    let mut values = Vec::with_capacity(s.leaf_slots);
    // Exactly every canonical part, in order, with one common D per original pair.
    // No sender-provided row list or cached expected output is accepted.
    for (pair, binding) in public.iter().zip(bindings) {
        for part in 0..PARTS_PER_SIGNATURE {
            values.push(Output::new(host::expected_row_output(pair, part, binding)));
        }
    }
    values.resize(s.leaf_slots, *values.last().ok_or("empty public claims")?);
    Ok(values)
}

fn verify_full(
    tree: &Tree<'_>,
    s: &Statement,
    public: &[PublicRecord],
    bytes: &[u8],
) -> Result<()> {
    let envelope = Envelope::decode(bytes, s)?;
    let expected = outputs(s, public, &envelope.bindings)?;
    let root = TreeProof::from_bytes(&envelope.core)?;
    tree.verify(&root, &expected)?;
    Ok(())
}

fn plan(n: usize, out: &Path) -> Result<Value> {
    if !allowed_n(n) {
        return Err("count must be 1,2,10,30,70,100".into());
    }
    if out.join("statement.json").exists() {
        return Err("refusing to replace existing plan".into());
    }
    let start = Instant::now();
    let records = host::records(0, 100);
    let fixture_s = start.elapsed().as_secs_f64();
    let public: Vec<_> = records
        .iter()
        .take(n)
        .map(|r| public_bytes(&r.public))
        .collect();
    let program = Program::from_elf(host::ELF)?;
    let rate = Rate::new(1)?;
    let mut measurements = Vec::new();
    let mut reference = None;
    let mut table_rows = Vec::new();
    let mut failures = Vec::new();
    let mut preparation = 0.0;
    for (index, record) in records.iter().enumerate() {
        let start = Instant::now();
        let prepared = host::prepare(record);
        preparation += start.elapsed().as_secs_f64();
        for part in 0..PARTS_PER_SIGNATURE {
            let run = host::row_run(&prepared, part);
            let start = Instant::now();
            match program.measure(&run.advice) {
                Ok(stats) => {
                    let measured = LeafShape::measured(&stats, rate);
                    if let Some(first) = reference {
                        if first != measured {
                            failures.push(json!({"signature":index,"part":part,"error":"leaf_shape_mismatch"}));
                        }
                    } else {
                        reference = Some(measured);
                        table_rows = TableId::ALL.iter().map(|&t| stats.counts[t]).collect();
                    }
                    measurements.push(json!({"signature":index,"part":part,"measure_s":start.elapsed().as_secs_f64(),"execution":stats_json(&stats),"expected_output":run.expected}));
                }
                Err(error) => failures
                    .push(json!({"signature":index,"part":part,"error":format!("{error:?}")})),
            }
        }
        eprintln!("measure segmented G corpus signature {}/100", index + 1);
    }
    let mut report = json!({"schema":1,"action":"plan","scheme":"raccoon-g","profile":PROFILE,"backend_revision":REVISION,"elf_sha256":hash(host::ELF),"signatures":n,"parts_per_signature":PARTS_PER_SIGNATURE,"rows_per_leaf":ROWS_PER_LEAF,"rows_per_signature":ROW_COUNT,"fixture_s":fixture_s,"diagnostic_native_prepare_s":preparation,"leaf_measurements":measurements,"failures":failures,"all_100_corpus_leaf_shapes_match":failures.is_empty()});
    if !failures.is_empty() {
        report["status"] = json!("rejected");
        save(out.join("plan.json"), &report)?;
        return Err("one or more corpus parts cannot share the selected proof shape".into());
    }
    let statement = Statement {
        schema: 1,
        backend_revision: REVISION.into(),
        scheme: "raccoon-g".into(),
        profile: PROFILE.into(),
        signatures: n,
        elf_sha256: hash(host::ELF),
        parts_per_signature: PARTS_PER_SIGNATURE,
        rows_per_leaf: ROWS_PER_LEAF,
        rows_per_signature: ROW_COUNT,
        actual_leaves: n * PARTS_PER_SIGNATURE,
        leaf_slots: slots(n),
        arity_0: 2,
        arity: 2,
        log_inverse_rate: 1,
        table_rows,
        public_records: public,
    };
    validate_statement(&statement)?;
    let start = Instant::now();
    let tree = Tree::new(&program, shape(&statement)?)?;
    report["status"] = json!("accepted");
    report["tree_setup_s"] = json!(start.elapsed().as_secs_f64());
    report["first_circuit"] = circuit_json(&tree, Kind::First);
    report["node_circuit"] = circuit_json(&tree, Kind::Node);
    report["actual_leaves"] = json!(statement.actual_leaves);
    report["leaf_slots"] = json!(statement.leaf_slots);
    save(out.join("statement.json"), &statement)?;
    save(out.join("plan.json"), &report)?;
    Ok(report)
}

fn prove(n: usize, out: &Path, sample: &str) -> Result<Value> {
    let pipeline = Instant::now();
    let raw = fs::read(out.join("statement.json"))?;
    let s: Statement = serde_json::from_slice(&raw)?;
    let public = validate_statement(&s)?;
    if s.signatures != n {
        return Err("count differs from prepared statement".into());
    }
    let run_dir = out.join(sample);
    if run_dir.exists() {
        return Err("sample exists; no cross-sample reuse".into());
    }
    fs::create_dir_all(&run_dir)?;
    let start = Instant::now();
    let records = host::records(0, n);
    let fixture_s = start.elapsed().as_secs_f64();
    if records.iter().zip(&public).any(|(a, b)| a.public != *b) {
        return Err("deterministic corpus differs from authorized original pairs".into());
    }
    let mut runs = Vec::with_capacity(s.actual_leaves);
    let mut bindings = Vec::with_capacity(n);
    let mut prepare_samples = Vec::new();
    for record in &records {
        let start = Instant::now();
        let prepared = host::prepare(record);
        for part in 0..PARTS_PER_SIGNATURE {
            runs.push(host::row_run(&prepared, part));
        }
        bindings.push(prepared.binding);
        prepare_samples.push(start.elapsed().as_secs_f64());
    }
    let native_prepare_s: f64 = prepare_samples.iter().sum();
    let expected = outputs(&s, &public, &bindings)?;
    if runs
        .iter()
        .zip(&expected)
        .any(|(run, expected)| run.expected != *expected.words())
    {
        return Err("prepared row output differs from public-only derivation".into());
    }
    let start = Instant::now();
    let program = Program::from_elf(host::ELF)?;
    let program_load_s = start.elapsed().as_secs_f64();
    let shape = shape(&s)?;
    let start = Instant::now();
    let tree = Tree::new(&program, shape)?;
    let setup_s = start.elapsed().as_secs_f64();
    let prover = Prover::new(Rate::new(1)?);
    let mut leaf_proofs = Vec::new();
    let mut report = json!({"schema":1,"action":"prove","status":"running","scheme":"raccoon-g","profile":PROFILE,"backend_revision":REVISION,"elf_sha256":s.elf_sha256,"statement_sha256":hash(&raw),"signatures":n,"sample":sample,"parts_per_signature":PARTS_PER_SIGNATURE,"rows_per_leaf":ROWS_PER_LEAF,"rows_per_signature":ROW_COUNT,"actual_leaves":s.actual_leaves,"leaf_slots":s.leaf_slots,"padding_slots":s.leaf_slots-s.actual_leaves,"arity_0":2,"arity":2,"log_inverse_rate":1,"fixture_s":fixture_s,"native_prepare_s":native_prepare_s,"native_prepare_samples_s":prepare_samples,"program_load_s":program_load_s,"tree_setup_s":setup_s,"leaf_reports":[],"merge_reports":[],"zero_knowledge":false});
    save(run_dir.join("report.json"), &report)?;
    for (index, run) in runs.iter().enumerate() {
        eprintln!(
            "G N={n} {sample}: partial leaf {}/{}",
            index + 1,
            runs.len()
        );
        let start = Instant::now();
        let made = prover.prove(&program, &run.advice)?;
        let elapsed = start.elapsed().as_secs_f64();
        if made.output != run.expected || LeafShape::of(&made.proof)? != shape.leaf {
            return Err("row output or leaf shape differs from approved plan".into());
        }
        let bytes = made.proof.to_bytes();
        let decoded = Proof::from_bytes(&bytes)?;
        program.verify(Output::new(run.expected), &decoded)?;
        fs::write(run_dir.join(format!("leaf-{index}.proof")), &bytes)?;
        report["leaf_reports"].as_array_mut().unwrap().push(json!({"leaf":index,"signature":index/PARTS_PER_SIGNATURE,"part":index%PARTS_PER_SIGNATURE,"prove_s":elapsed,"proof_bytes":bytes.len(),"proof_sha256":hash(&bytes),"execution":stats_json(&made.stats)}));
        leaf_proofs.push(decoded);
        save(run_dir.join("report.json"), &report)?;
    }
    let leaves: Vec<_> = (0..s.leaf_slots)
        .map(|index| {
            Leaf::new(
                &leaf_proofs[index.min(s.actual_leaves - 1)],
                expected[index],
            )
        })
        .collect();
    let mut level = Vec::new();
    let mut node = 0;
    for chunk in leaves.chunks(2) {
        let start = Instant::now();
        let made = tree.prove_first(chunk)?;
        let elapsed = start.elapsed().as_secs_f64();
        let bytes = made.to_bytes();
        fs::write(run_dir.join(format!("merge-{node}.proof")), &bytes)?;
        report["merge_reports"].as_array_mut().unwrap().push(json!({"node":node,"level":0,"kind":"first","children":2,"prove_s":elapsed,"proof_bytes":bytes.len(),"proof_sha256":hash(&bytes)}));
        level.push(TreeProof::from_bytes(&bytes)?);
        node += 1;
        save(run_dir.join("report.json"), &report)?;
    }
    let mut depth = 1;
    while level.len() > 1 {
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            eprintln!("G N={n} {sample}: merge {}/{}", node + 1, s.leaf_slots - 1);
            let start = Instant::now();
            let made = tree.prove_node(chunk)?;
            let elapsed = start.elapsed().as_secs_f64();
            let bytes = made.to_bytes();
            fs::write(run_dir.join(format!("merge-{node}.proof")), &bytes)?;
            report["merge_reports"].as_array_mut().unwrap().push(json!({"node":node,"level":depth,"kind":"node","children":2,"prove_s":elapsed,"proof_bytes":bytes.len(),"proof_sha256":hash(&bytes)}));
            next.push(TreeProof::from_bytes(&bytes)?);
            node += 1;
            save(run_dir.join("report.json"), &report)?;
        }
        level = next;
        depth += 1;
    }
    let core = level.pop().ok_or("no root")?.to_bytes();
    let receipt = Envelope { bindings, core }.encode(&s)?;
    verify_full(&tree, &s, &public, &receipt)?;
    fs::write(run_dir.join("root.proof"), &receipt)?;
    let leaves: f64 = report["leaf_reports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["prove_s"].as_f64().unwrap())
        .sum();
    let merges: f64 = report["merge_reports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["prove_s"].as_f64().unwrap())
        .sum();
    let envelope = Envelope::decode(&receipt, &s)?;
    report["status"] = json!("accepted");
    report["verified"] = json!(true);
    report["all_folded_claims_settled"] = json!(true);
    report["leaf_prove_s"] = json!(leaves);
    report["merge_prove_s"] = json!(merges);
    report["total_prove_s"] = json!(native_prepare_s + leaves + merges);
    report["root_proof_bytes"] = json!(receipt.len());
    report["root_core_bytes"] = json!(envelope.core.len());
    report["auxiliary_bytes"] = json!(receipt.len() - envelope.core.len());
    report["root_proof_sha256"] = json!(hash(&receipt));
    report["root_core_sha256"] = json!(hash(&envelope.core));
    report["merge_count"] = json!(node);
    report["depth"] = json!(depth);
    report["peak_rss_bytes"] = json!(bench::peak_rss_bytes());
    report["pipeline_elapsed_s"] = json!(pipeline.elapsed().as_secs_f64());
    save(run_dir.join("report.json"), &report)?;
    Ok(report)
}

fn verify_public(s: &Statement, bytes: &[u8], controls: bool) -> Result<Value> {
    let start = Instant::now();
    let public = validate_statement(s)?;
    let public_configuration_prepare_s = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let envelope = Envelope::decode(bytes, s)?;
    let expected = outputs(s, &public, &envelope.bindings)?;
    let claim_s = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let program = Program::from_elf(host::ELF)?;
    let load_s = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let tree = Tree::new(&program, shape(s)?)?;
    let setup_s = start.elapsed().as_secs_f64();
    let start = Instant::now();
    verify_full(&tree, s, &public, bytes)?;
    let first_s = start.elapsed().as_secs_f64();
    let mut full_times = Vec::new();
    let mut core_times = Vec::new();
    for pass in 0..4 {
        let start = Instant::now();
        verify_full(&tree, s, &public, bytes)?;
        if pass > 0 {
            full_times.push(start.elapsed().as_secs_f64());
        }
        let start = Instant::now();
        let root = TreeProof::from_bytes(&envelope.core)?;
        tree.verify(&root, &expected)?;
        if pass > 0 {
            core_times.push(start.elapsed().as_secs_f64());
        }
    }
    let mut report = json!({"schema":1,"action":"verify","scheme":"raccoon-g","profile":PROFILE,"backend_revision":REVISION,"signatures":s.signatures,"parts_per_signature":PARTS_PER_SIGNATURE,"rows_per_leaf":ROWS_PER_LEAF,"rows_per_signature":ROW_COUNT,"actual_leaves":s.actual_leaves,"leaf_slots":s.leaf_slots,"verified":true,"statement_pinned":true,"elf_sha256":s.elf_sha256,"root_proof_bytes":bytes.len(),"root_core_bytes":envelope.core.len(),"auxiliary_bytes":bytes.len()-envelope.core.len(),"root_proof_sha256":hash(bytes),"all_folded_claims_settled":true,"verification_uses_signatures":false,"verification_uses_child_proofs":false,"witness_bindings_are_untrusted_auxiliary":true,"public_configuration_prepare_s":public_configuration_prepare_s,"public_claim_derivation_s":claim_s,"program_load_s":load_s,"tree_setup_s":setup_s,"first_complete_verify_s":first_s,"cold_complete_verify_s":public_configuration_prepare_s+load_s+setup_s+first_s,"prepared_complete_verify_s":full_times,"prepared_core_verify_s":core_times,"prepared_complete_verify_median_s":median(&full_times),"prepared_complete_scope":"Envelope decode, all original-pair/part commitments from untrusted D, TreeProof decode and complete Tree::verify","prepared_core_scope":"TreeProof decode and complete Tree::verify with already derived expected outputs","zero_knowledge":false,"peak_rss_bytes":bench::peak_rss_bytes()});
    if controls {
        let root = TreeProof::from_bytes(&envelope.core)?;
        let mut checks = BTreeMap::new();
        let mut bad = bytes.to_vec();
        bad.push(0);
        checks.insert(
            "trailing_byte",
            verify_full(&tree, s, &public, &bad).is_err(),
        );
        let mut bad = bytes.to_vec();
        bad.pop();
        checks.insert(
            "truncated_receipt",
            verify_full(&tree, s, &public, &bad).is_err(),
        );
        let mut changed = envelope.clone();
        changed.bindings[0][7] ^= 1;
        checks.insert(
            "changed_binding",
            verify_full(&tree, s, &public, &changed.encode(s)?).is_err(),
        );
        let mut changed = envelope.clone();
        changed.core[envelope.core.len() / 2] ^= 1;
        checks.insert(
            "corrupt_root",
            verify_full(&tree, s, &public, &changed.encode(s)?).is_err(),
        );
        let mut wrong = expected.clone();
        wrong.pop();
        checks.insert("wrong_leaf_count", tree.verify(&root, &wrong).is_err());
        let mut wrong = expected.clone();
        wrong.swap(0, 1);
        checks.insert("reordered_parts", tree.verify(&root, &wrong).is_err());
        let mut wrong = expected.clone();
        wrong[1] = wrong[0];
        checks.insert(
            "duplicated_part_missing_coverage",
            tree.verify(&root, &wrong).is_err(),
        );
        let mut wrong_public = public.clone();
        let last = wrong_public[0].public_key.len() - 1;
        wrong_public[0].public_key[last] ^= 1;
        checks.insert(
            "changed_key_recommitted",
            verify_full(&tree, s, &wrong_public, bytes).is_err(),
        );
        let mut wrong_public = public.clone();
        wrong_public[0].message[31] ^= 1;
        checks.insert(
            "changed_message_recommitted",
            verify_full(&tree, s, &wrong_public, bytes).is_err(),
        );
        let mut bad = bytes.to_vec();
        bad[8] ^= 1;
        checks.insert(
            "changed_signature_count",
            verify_full(&tree, s, &public, &bad).is_err(),
        );
        let mut bad = bytes.to_vec();
        bad[12] ^= 1;
        checks.insert(
            "changed_parts_policy",
            verify_full(&tree, s, &public, &bad).is_err(),
        );
        if checks.values().any(|x| !*x) {
            return Err(format!("a negative control accepted: {checks:?}").into());
        }
        report["controls"] = json!(checks);
    }
    Ok(report)
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let action = args.next().ok_or("expected identity,plan,prove,verify")?;
    let mut opts = BTreeMap::new();
    while let Some(flag) = args.next() {
        if ![
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
        ]
        .contains(&flag.as_str())
        {
            return Err(format!("unknown option {flag}").into());
        }
        let value = args.next().ok_or("missing option value")?;
        if opts.insert(flag, value).is_some() {
            return Err("duplicate option".into());
        }
    }
    let number = |key: &str, default: usize| -> Result<usize> {
        Ok(opts.get(key).map_or(Ok(default), |s| s.parse())?)
    };
    let out = PathBuf::from(opts.get("--outdir").ok_or("missing --outdir")?);
    fs::create_dir_all(&out)?;
    let executable_identity = identity()?;
    if action == "identity" {
        let report = executable_identity;
        save(out.join("identity.json"), &report)?;
        println!("{report}");
        return Ok(());
    }
    let threads = number("--threads", 8)?;
    if threads == 0 || number("--rate", 1)? != 1 {
        return Err("positive workers and rate one required".into());
    }
    parallel::init_with_threads(std::num::NonZeroUsize::new(threads).unwrap())
        .map_err(|e| format!("threads: {e:?}"))?;
    let result = match action.as_str() {
        "plan" => plan(number("--n", 10)?, &out),
        "prove" => prove(
            number("--n", 10)?,
            &out,
            opts.get("--sample")
                .map(String::as_str)
                .unwrap_or("sample-0"),
        ),
        "verify" => {
            let raw = fs::read(opts.get("--statement").ok_or("missing --statement")?)?;
            if hash(&raw)
                != *opts
                    .get("--expect-statement-sha256")
                    .ok_or("missing intended statement hash")?
            {
                return Err("caller-authorized statement hash mismatch".into());
            }
            let s: Statement = serde_json::from_slice(&raw)?;
            if s.elf_sha256
                != *opts
                    .get("--expect-elf-sha256")
                    .ok_or("missing approved ELF hash")?
                || s.elf_sha256 != hash(host::ELF)
            {
                return Err("caller-approved program hash mismatch".into());
            }
            let proof_path = opts.get("--proof").ok_or("missing --proof")?;
            if fs::metadata(proof_path)?.len() > MAX_RECEIPT as u64 {
                return Err("receipt size bound".into());
            }
            let bytes = fs::read(proof_path)?;
            let mut report = verify_public(
                &s,
                &bytes,
                opts.get("--controls").is_some_and(|s| s == "true"),
            )?;
            report["statement_sha256"] = json!(hash(&raw));
            Ok(report)
        }
        _ => Err("unknown action".into()),
    };
    match result {
        Ok(mut report) => {
            report["threads_requested"] = json!(threads);
            report["embedded_build_manifest_sha256"] =
                executable_identity["embedded_build_manifest_sha256"].clone();
            let file = match action.as_str() {
                "plan" => out.join("plan.json"),
                "prove" => out
                    .join(
                        opts.get("--sample")
                            .map(String::as_str)
                            .unwrap_or("sample-0"),
                    )
                    .join("report.json"),
                _ => out.join("verification.json"),
            };
            save(file, &report)?;
            println!(
                "{}",
                json!({"action":action,"status":report.get("status"),"signatures":report.get("signatures"),"verified":report.get("verified"),"root_proof_bytes":report.get("root_proof_bytes"),"total_prove_s":report.get("total_prove_s")})
            );
            Ok(())
        }
        Err(error) => {
            save(
                out.join("error.json"),
                &json!({"schema":1,"action":action,"error":error.to_string(),"backend_revision":REVISION,"profile":PROFILE}),
            )?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn statement() -> Statement {
        Statement {
            schema: 1,
            backend_revision: REVISION.into(),
            scheme: "raccoon-g".into(),
            profile: PROFILE.into(),
            signatures: 1,
            elf_sha256: hash(host::ELF),
            parts_per_signature: PARTS_PER_SIGNATURE,
            rows_per_leaf: ROWS_PER_LEAF,
            rows_per_signature: ROW_COUNT,
            actual_leaves: PARTS_PER_SIGNATURE,
            leaf_slots: slots(1),
            arity_0: 2,
            arity: 2,
            log_inverse_rate: 1,
            table_rows: vec![8; TableId::ALL.len()],
            public_records: vec![PublicBytes {
                public_key: "00".repeat(16144),
                message: "00".repeat(32),
            }],
        }
    }
    #[test]
    fn strict_envelope_codec_rejects_count_policy_truncation_and_trailers() {
        let s = statement();
        let e = Envelope {
            bindings: vec![[7; 8]],
            core: vec![1, 2, 3],
        };
        let bytes = e.encode(&s).unwrap();
        assert_eq!(Envelope::decode(&bytes, &s).unwrap().bindings, e.bindings);
        assert_eq!(Envelope::decode(&bytes, &s).unwrap().core, e.core);
        for offset in [0, 8, 12, 16, 20] {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            assert!(Envelope::decode(&bad, &s).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(Envelope::decode(&bad, &s).is_err());
        for n in [0, 7, 8, 20, 51, bytes.len() - 1] {
            assert!(Envelope::decode(&bytes[..n], &s).is_err());
        }
    }
    #[test]
    fn complete_coverage_binds_original_pairs_and_untrusted_common_digest() {
        let s = statement();
        let public = validate_statement(&s).unwrap();
        let d = vec![[7; 8]];
        let all = outputs(&s, &public, &d).unwrap();
        assert_eq!(all.len(), s.leaf_slots);
        let mut distinct = BTreeSet::new();
        for output in all.iter().take(PARTS_PER_SIGNATURE) {
            distinct.insert(*output.words());
        }
        assert_eq!(distinct.len(), PARTS_PER_SIGNATURE);
        for index in PARTS_PER_SIGNATURE..s.leaf_slots {
            assert_eq!(all[index].words(), all[PARTS_PER_SIGNATURE - 1].words());
        }
        let mut changed = d.clone();
        changed[0][7] ^= 1;
        assert_ne!(
            outputs(&s, &public, &changed).unwrap()[0].words(),
            all[0].words()
        );
        let mut changed = public.clone();
        changed[0].public_key[16143] ^= 1;
        assert_ne!(
            outputs(&s, &changed, &d).unwrap()[0].words(),
            all[0].words()
        );
        let mut changed = public.clone();
        changed[0].message[31] ^= 1;
        assert_ne!(
            outputs(&s, &changed, &d).unwrap()[0].words(),
            all[0].words()
        );
        assert!(outputs(&s, &public, &[]).is_err());
        let mut bad = s.clone();
        bad.parts_per_signature += 1;
        assert!(validate_statement(&bad).is_err());
    }
    #[test]
    fn embedded_guest_and_profile_match_build_manifest() {
        let identity = identity().unwrap();
        assert_eq!(identity["embedded_elf_sha256"], hash(host::ELF));
        assert_eq!(identity["parts_per_signature"], PARTS_PER_SIGNATURE);
    }
}
