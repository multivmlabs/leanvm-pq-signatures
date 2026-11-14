//! Bounded-depth recursive trees, authenticated by an independently trusted plan.
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
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
#[path = "../tree_guest.rs"]
mod tree_guest;

#[global_allocator]
static ALLOCATOR: bench::Jemalloc = bench::Jemalloc;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
type Streams = BTreeMap<String, Vec<Vec<F192>>>;
type Cell = [u64; 3];
const PLAN_DOMAIN: &[u8] = b"pqbench/tree-plan/v1\0";

#[derive(Clone, Deserialize)]
struct ProgramSpec {
    id: String,
    source_file: PathBuf,
    expected_guest_hash: String,
    #[serde(default = "minimum_commitment")]
    min_log_committed: usize,
}
fn minimum_commitment() -> usize {
    22
}

#[derive(Clone, Deserialize)]
struct LeafSpec {
    program_id: String,
    signatures: usize,
    public_input_hex: String,
    input_file: PathBuf,
}

#[derive(Clone, Deserialize)]
struct Manifest {
    schema_version: u32,
    scheme: String,
    signatures: usize,
    leaf_capacity: usize,
    fan_in: usize,
    programs: Vec<ProgramSpec>,
    leaves: Vec<LeafSpec>,
}

#[derive(Deserialize)]
struct Input {
    source: String,
    public_input: [Cell; 2],
    witness: BTreeMap<String, Vec<Vec<Cell>>>,
}

#[derive(Serialize)]
struct CanonicalLeaf {
    signatures: usize,
    guest_hash: String,
    public_input_hex: String,
    min_log_committed: usize,
}
#[derive(Serialize)]
struct CanonicalPlan<'a> {
    format: &'static str,
    schema_version: u32,
    scheme: &'a str,
    signatures: usize,
    leaf_capacity: usize,
    fan_in: usize,
    leaves: Vec<CanonicalLeaf>,
}

struct Node {
    program: Arc<Program>,
    children: Vec<usize>,
    leaf: Option<usize>,
    depth: usize,
    signatures: usize,
}
struct Plan {
    manifest: Manifest,
    base: PathBuf,
    hash: [u8; 32],
    semantic: Value,
    nodes: Vec<Node>,
    root: usize,
    leaf_pi: Vec<[F192; 2]>,
    leaf_sources: BTreeMap<String, String>,
    compile_s: f64,
}

/// There is one point per edge, grouped by merge node in canonical node order.
/// Values are deliberately absent: the receiver derives every one from code.
#[derive(Clone, Serialize, Deserialize)]
struct Envelope {
    version: u32,
    plan_hash: [u8; 32],
    root_guest_hash: [u8; 32],
    deferred_points_by_merge: Vec<Vec<Vec<F192>>>,
    proof: Proof,
}

fn wire() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(64 << 20)
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
fn bytes32(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return Err("expected exactly 32 hex bytes".into());
    }
    let bytes: Vec<_> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16))
        .collect::<std::result::Result<_, _>>()?;
    Ok(bytes.try_into().unwrap())
}
fn seed(program: &Program) -> [u8; 32] {
    cpu::public_input_bytes(&cpu::fs_seed(program))
}
fn kbc(program: &Program) -> usize {
    program.prog.len().ilog2() as usize
}
fn at(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.into()
    } else {
        base.join(path)
    }
}

/// Level-wise ordered chunks; an unmatched singleton advances without a proof.
fn topology(leaves: usize, fan_in: usize) -> (Vec<Vec<usize>>, usize) {
    let mut current: Vec<_> = (0..leaves).collect();
    let mut groups = Vec::new();
    let mut next_id = leaves;
    while current.len() > 1 {
        let mut next = Vec::new();
        for chunk in current.chunks(fan_in) {
            if chunk.len() == 1 {
                next.push(chunk[0]);
            } else {
                groups.push(chunk.to_vec());
                next.push(next_id);
                next_id += 1;
            }
        }
        current = next;
    }
    (groups, current[0])
}

fn load_plan(path: &Path) -> Result<Plan> {
    let started = Instant::now();
    let manifest: Manifest = read_json(path)?;
    if manifest.schema_version != 1
        || manifest.scheme.is_empty()
        || manifest.signatures == 0
        || manifest.leaf_capacity == 0
        || ![2, 4, 8].contains(&manifest.fan_in)
        || manifest.leaves.is_empty()
        || manifest.leaves.len() > 4096
    {
        return Err("invalid tree manifest configuration".into());
    }
    let base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let mut programs = BTreeMap::new();
    let mut sources = BTreeMap::new();
    let mut specs = BTreeMap::new();
    for specification in &manifest.programs {
        if specification.id.is_empty()
            || programs.contains_key(&specification.id)
            || !(22..=28).contains(&specification.min_log_committed)
        {
            return Err("duplicate program id or unsupported commitment floor".into());
        }
        let source = fs::read_to_string(at(&base, &specification.source_file))?;
        let mut program = lean_compiler::compile(&lean_compiler::parse(&source)?);
        if seed(&program) != bytes32(&specification.expected_guest_hash)? {
            return Err(format!(
                "program {} differs from its trusted source pin",
                specification.id
            )
            .into());
        }
        program.min_log_committed = specification.min_log_committed;
        programs.insert(specification.id.clone(), Arc::new(program));
        sources.insert(specification.id.clone(), source);
        specs.insert(specification.id.clone(), specification);
    }
    let mut leaves = Vec::new();
    let mut leaf_pi = Vec::new();
    let mut nodes = Vec::new();
    let mut total = 0usize;
    for (i, leaf) in manifest.leaves.iter().enumerate() {
        if leaf.signatures == 0
            || leaf.signatures > manifest.leaf_capacity
            || (i + 1 < manifest.leaves.len() && leaf.signatures != manifest.leaf_capacity)
        {
            return Err("only the final leaf may be a partial positive batch".into());
        }
        total = total
            .checked_add(leaf.signatures)
            .ok_or("signature count overflow")?;
        let program = programs
            .get(&leaf.program_id)
            .ok_or("unknown leaf program id")?
            .clone();
        let public = bytes32(&leaf.public_input_hex)?;
        leaves.push(CanonicalLeaf {
            signatures: leaf.signatures,
            guest_hash: hex(&seed(&program)),
            public_input_hex: hex(&public),
            min_log_committed: specs[&leaf.program_id].min_log_committed,
        });
        leaf_pi.push(tree_guest::halves(public));
        nodes.push(Node {
            program,
            children: Vec::new(),
            leaf: Some(i),
            depth: 0,
            signatures: leaf.signatures,
        });
    }
    if total != manifest.signatures {
        return Err("leaf counts do not cover exactly the intended signature count".into());
    }
    let canonical = CanonicalPlan {
        format: "pqbench/tree-v1/all-edges/level-chunks",
        schema_version: 1,
        scheme: &manifest.scheme,
        signatures: manifest.signatures,
        leaf_capacity: manifest.leaf_capacity,
        fan_in: manifest.fan_in,
        leaves,
    };
    let encoded = serde_json::to_vec(&canonical)?;
    let hash = primitives::hash::hash(&[PLAN_DOMAIN, &encoded].concat());
    let semantic = serde_json::to_value(&canonical)?;
    let (groups, root) = topology(nodes.len(), manifest.fan_in);
    let mut compiled: BTreeMap<Vec<u8>, Arc<Program>> = BTreeMap::new();
    for children in groups {
        let child_programs: Vec<_> = children
            .iter()
            .map(|&n| tree_guest::Child {
                kbc: kbc(&nodes[n].program),
                seed: cpu::fs_seed(&nodes[n].program),
            })
            .collect();
        let cache_key = children
            .iter()
            .flat_map(|&n| seed(&nodes[n].program))
            .collect::<Vec<_>>();
        let program = if let Some(program) = compiled.get(&cache_key) {
            program.clone()
        } else {
            let mut program = tree_guest::compile(tree_guest::halves(hash), &child_programs)?;
            program.min_log_committed = 22;
            let program = Arc::new(program);
            compiled.insert(cache_key, program.clone());
            program
        };
        let depth = children.iter().map(|&n| nodes[n].depth).max().unwrap() + 1;
        let signatures = children.iter().map(|&n| nodes[n].signatures).sum();
        nodes.push(Node {
            program,
            children,
            leaf: None,
            depth,
            signatures,
        });
    }
    Ok(Plan {
        manifest,
        base,
        hash,
        semantic,
        nodes,
        root,
        leaf_pi,
        leaf_sources: sources,
        compile_s: started.elapsed().as_secs_f64(),
    })
}

fn description(plan: &Plan) -> Value {
    let mut table = BTreeMap::new();
    for node in &plan.nodes {
        table.entry(format!("{}-m{}", hex(&seed(&node.program)), node.program.min_log_committed)).or_insert_with(|| json!({
            "guest_hash":hex(&seed(&node.program)), "bytecode_log":kbc(&node.program),
            "bytecode_instructions":node.program.code_len(), "padded_bytecode_instructions":node.program.prog.len(),
            "min_log_committed":node.program.min_log_committed,
        }));
    }
    json!({"schema_version":1,"plan_hash":hex(&plan.hash),"scheme":plan.manifest.scheme,
        "signatures":plan.manifest.signatures,"leaf_capacity":plan.manifest.leaf_capacity,
        "fan_in":plan.manifest.fan_in,"leaf_count":plan.manifest.leaves.len(),
        "merge_count":plan.nodes.len()-plan.manifest.leaves.len(),
        "edge_count":plan.nodes.iter().map(|n| n.children.len()).sum::<usize>(),
        "depth":plan.nodes[plan.root].depth,"root_guest_hash":hex(&seed(&plan.nodes[plan.root].program)),
        "compile_plan_s":plan.compile_s,"semantic_plan":plan.semantic,"source_table":table.into_values().collect::<Vec<_>>(),
        "nodes":plan.nodes.iter().enumerate().map(|(i,n)|json!({"node":i,"leaf":n.leaf,
            "children":n.children,"depth":n.depth,"signatures":n.signatures,"guest_hash":hex(&seed(&n.program))})).collect::<Vec<_>>()})
}

fn child_specs(plan: &Plan, node: &Node) -> Vec<tree_guest::Child> {
    node.children
        .iter()
        .map(|&i| tree_guest::Child {
            kbc: kbc(&plan.nodes[i].program),
            seed: cpu::fs_seed(&plan.nodes[i].program),
        })
        .collect()
}

struct Evaluators {
    tables: BTreeMap<[u8; 32], verifier::Bytecode>,
    prepare_s: f64,
}
impl Evaluators {
    fn new(plan: &Plan) -> Self {
        let started = Instant::now();
        let mut tables = BTreeMap::new();
        for node in &plan.nodes {
            if node.children.is_empty() {
                continue;
            }
            for &child in &node.children {
                let program = &plan.nodes[child].program;
                tables.entry(seed(program)).or_insert_with(|| {
                    let table: Vec<_> = cpu::bytecode_table(&program.prog)
                        .iter()
                        .map(|x| x.0)
                        .collect();
                    verifier::Bytecode::new(&table)
                });
            }
        }
        Self {
            tables,
            prepare_s: started.elapsed().as_secs_f64(),
        }
    }
    fn evaluate(&self, program: &Program, point: &[F192]) -> Result<F192> {
        if point.len() != kbc(program) + leanvm_core::leaf::N_BYTECODE_SELECTORS {
            return Err("incorrect deferred point dimension".into());
        }
        self.tables[&seed(program)]
            .evaluate(&point.iter().map(cpu::to_scalar).collect::<Vec<_>>())
            .map(cpu::from_scalar)
            .map_err(|e| format!("native bytecode evaluation: {e:?}").into())
    }
}

fn expected_root_input(
    plan: &Plan,
    points: &[Vec<Vec<F192>>],
    evaluators: &Evaluators,
) -> Result<[F192; 2]> {
    if points.len() != plan.nodes.len() - plan.manifest.leaves.len() {
        return Err("one complete set of deferred edge points per merge required".into());
    }
    let mut public = plan.leaf_pi.clone();
    for (node, points) in plan.nodes[public.len()..].iter().zip(points) {
        if node.children.len() != points.len() {
            return Err("incorrect deferred edge count".into());
        }
        let values: Vec<_> = node
            .children
            .iter()
            .zip(points)
            .map(|(&i, p)| evaluators.evaluate(&plan.nodes[i].program, p))
            .collect::<Result<_>>()?;
        let pi: Vec<_> = node.children.iter().map(|&i| public[i]).collect();
        public.push(tree_guest::public_input(
            tree_guest::halves(plan.hash),
            &child_specs(plan, node),
            &pi,
            points,
            &values,
        )?);
    }
    Ok(public[plan.root])
}

fn verify(plan: &Plan, envelope: &Envelope, repeat: usize, warmup: usize) -> Result<Value> {
    let start = Instant::now();
    if envelope.version != 1
        || envelope.plan_hash != plan.hash
        || envelope.root_guest_hash != seed(&plan.nodes[plan.root].program)
    {
        return Err("root envelope differs from trusted plan".into());
    }
    let evaluators = Evaluators::new(plan);
    let mut evaluation_s = Vec::new();
    let mut core_s = Vec::new();
    let mut expected = [F192::ZERO; 2];
    for pass in 0..warmup + repeat {
        let now = Instant::now();
        expected = expected_root_input(plan, &envelope.deferred_points_by_merge, &evaluators)?;
        let evaluation = now.elapsed().as_secs_f64();
        let now = Instant::now();
        // cpu::verify is the honest cold root-core operation (includes root
        // bytecode preparation). Cached portable-core timing is added below.
        cpu::verify(&plan.nodes[plan.root].program, &expected, &envelope.proof)
            .map_err(|e| format!("root proof verification: {e:?}"))?;
        if pass >= warmup {
            evaluation_s.push(evaluation);
            core_s.push(now.elapsed().as_secs_f64());
        }
    }
    let now = Instant::now();
    let table: Vec<_> = cpu::bytecode_table(&plan.nodes[plan.root].program.prog)
        .iter()
        .map(|x| x.0)
        .collect();
    let bytecode = verifier::Bytecode::new(&table);
    let root_prepare_s = now.elapsed().as_secs_f64();
    let public = cpu::public_input_bytes(&expected);
    let scalar = cpu::scalar_proof(&envelope.proof);
    let mut cached_s = Vec::new();
    for pass in 0..warmup + repeat {
        let now = Instant::now();
        verifier::verify_execution(&bytecode, &public, &scalar)
            .map_err(|e| format!("cached root verification: {e:?}"))?;
        if pass >= warmup {
            cached_s.push(now.elapsed().as_secs_f64());
        }
    }
    Ok(
        json!({"verified":true,"statement_pinned":true,"plan_hash":hex(&plan.hash),
        "public_input_hex":hex(&public),"root_guest_hash":hex(&envelope.root_guest_hash),
        "compile_plan_s":plan.compile_s,"deferred_bytecode_prepare_s":evaluators.prepare_s,
        "deferred_evaluation_s":evaluation_s,"root_core_verify_cold_s":core_s,
        "root_bytecode_prepare_s":root_prepare_s,"root_core_verify_cached_s":cached_s,
        "verification_operation_total_s":start.elapsed().as_secs_f64(),
        "deferred_program_count":evaluators.tables.len(),
        "deferred_edge_count":envelope.deferred_points_by_merge.iter().map(Vec::len).sum::<usize>(),
        "root_core_proof_bytes":wire().serialized_size(&envelope.proof)?,
        "aggregate_wire_bytes":wire().serialized_size(envelope)?,
        "zero_knowledge":false,"verification_uses_child_proofs":false,"verification_uses_signatures":false}),
    )
}

fn set_streams(program: &mut Program, streams: Streams) {
    for (name, entries) in streams {
        program.set_witness(name, entries);
    }
}

fn prove(
    plan: &Plan,
    cache: &Path,
    out: &Path,
    rate: usize,
    repeat: usize,
    warmup: usize,
    fresh: bool,
) -> Result<Value> {
    fs::create_dir_all(cache)?;
    fs::create_dir_all(out)?;
    let pipeline = Instant::now();
    let mut leaf_proofs = Vec::new();
    let mut leaf_reports = Vec::new();
    for (i, leaf) in plan.manifest.leaves.iter().enumerate() {
        let program = &plan.nodes[i].program;
        let pi = plan.leaf_pi[i];
        let label = format!(
            "{}-{}-r{rate}-m{}",
            hex(&seed(program)),
            hex(&cpu::public_input_bytes(&pi)),
            program.min_log_committed
        );
        let proof_path = cache.join(format!("{label}.proof"));
        let report_path = cache.join(format!("{label}.json"));
        let now = Instant::now();
        let (proof, report) = if !fresh && proof_path.exists() {
            let proof: Proof = wire().deserialize(&fs::read(&proof_path)?)?;
            let summary = cpu::verify(program, &pi, &proof)
                .map_err(|e| format!("invalid cached leaf {i}: {e:?}"))?;
            if summary.log_inv_rate != rate {
                return Err(format!("cached leaf {i} has a different PCS rate").into());
            }
            let report = json!({"leaf":i,"reused":true,"cache_load_verify_s":now.elapsed().as_secs_f64(),
                "guest_hash":hex(&seed(program)),"public_input_hex":hex(&cpu::public_input_bytes(&pi)),
                "proof_bytes":wire().serialized_size(&proof)?,"rate":summary.log_inv_rate,
                "proof_stream_scalars":proof.stream.len(),
                "original_report":if report_path.exists(){read_json::<Value>(&report_path)?}else{Value::Null}});
            (proof, report)
        } else {
            let input: Input = read_json(&at(&plan.base, &leaf.input_file))?;
            if input.source != plan.leaf_sources[&leaf.program_id]
                || input.public_input.map(|x| F192::new(x[0], x[1], x[2])) != pi
            {
                return Err(
                    format!("leaf {i} input differs from expected source/statement").into(),
                );
            }
            let mut proving = (**program).clone();
            for (name, entries) in input.witness {
                proving.set_witness(
                    name,
                    entries
                        .into_iter()
                        .map(|r| r.into_iter().map(|x| F192::new(x[0], x[1], x[2])).collect())
                        .collect(),
                );
            }
            let input_prepare_s = now.elapsed().as_secs_f64();
            let now = Instant::now();
            let (proof, stats) =
                cpu::prove(&proving, pi, rate).map_err(|e| format!("leaf {i} proof: {e:?}"))?;
            let prove_s = now.elapsed().as_secs_f64();
            let now = Instant::now();
            cpu::verify(program, &pi, &proof)
                .map_err(|e| format!("leaf {i} self verification: {e:?}"))?;
            let self_verify_s = now.elapsed().as_secs_f64();
            fs::write(&proof_path, wire().serialize(&proof)?)?;
            let report = json!({"leaf":i,"reused":false,"signatures":leaf.signatures,
                "guest_hash":hex(&seed(program)),"public_input_hex":hex(&cpu::public_input_bytes(&pi)),
                "input_prepare_s":input_prepare_s,"prove_s":prove_s,"self_verify_s":self_verify_s,
                "proof_bytes":wire().serialized_size(&proof)?,"committed_cells":stats.committed,
                "cycles":stats.cycles,"opcode_rows":stats.rows,"memory_cells":stats.mem_used,
                "proof_stream_scalars":proof.stream.len(),"log_committed":stats.committed.next_power_of_two().ilog2(),
                "log_memory_cells":stats.log_mem,"min_log_committed":program.min_log_committed,"rate":rate});
            save(&report_path, &report)?;
            (proof, report)
        };
        println!(
            "leaf {i}: {}",
            if report["reused"] == true {
                "reused"
            } else {
                "proved"
            }
        );
        leaf_proofs.push(proof);
        leaf_reports.push(report);
    }
    let mut passes = Vec::new();
    let mut last = None;
    for pass in 0..warmup + repeat {
        let pass_start = Instant::now();
        let mut proofs = leaf_proofs.clone();
        let mut public = plan.leaf_pi.clone();
        let mut all_points = Vec::new();
        let mut node_reports = Vec::new();
        for (node_id, node) in plan
            .nodes
            .iter()
            .enumerate()
            .skip(plan.manifest.leaves.len())
        {
            let mut streams: Streams = BTreeMap::new();
            let mut points = Vec::new();
            let mut values = Vec::new();
            let mut child_pi = Vec::new();
            let now = Instant::now();
            for &child in &node.children {
                let prepared = recursion_support::child_witness(
                    &plan.nodes[child].program,
                    public[child],
                    &proofs[child],
                )?;
                for (name, entries) in prepared.streams {
                    streams.entry(name).or_default().extend(entries);
                }
                points.push(prepared.bytecode_point);
                values.push(prepared.bytecode_value);
                child_pi.push(public[child]);
            }
            streams.insert(
                "tree_child_pi".into(),
                child_pi.iter().map(|x| x.to_vec()).collect(),
            );
            let prepare_s = now.elapsed().as_secs_f64();
            let pi = tree_guest::public_input(
                tree_guest::halves(plan.hash),
                &child_specs(plan, node),
                &child_pi,
                &points,
                &values,
            )?;
            let mut proving = (*node.program).clone();
            set_streams(&mut proving, streams);
            let now = Instant::now();
            let (proof, stats) = cpu::prove(&proving, pi, rate)
                .map_err(|e| format!("merge {node_id} proof: {e:?}"))?;
            let prove_s = now.elapsed().as_secs_f64();
            let now = Instant::now();
            cpu::verify(&node.program, &pi, &proof)
                .map_err(|e| format!("merge {node_id} self verification: {e:?}"))?;
            let self_verify_s = now.elapsed().as_secs_f64();
            if pass + 1 == warmup + repeat {
                fs::write(
                    out.join(format!("node-{node_id}.proof")),
                    wire().serialize(&proof)?,
                )?;
            }
            node_reports.push(json!({"node":node_id,"children":node.children,"depth":node.depth,
                "signatures":node.signatures,"prepare_s":prepare_s,"prove_s":prove_s,"self_verify_s":self_verify_s,
                "guest_hash":hex(&seed(&node.program)),"public_input_hex":hex(&cpu::public_input_bytes(&pi)),
                "proof_bytes":wire().serialized_size(&proof)?,"committed_cells":stats.committed,
                "cycles":stats.cycles,"opcode_rows":stats.rows,"memory_cells":stats.mem_used,
                "proof_stream_scalars":proof.stream.len(),"log_committed":stats.committed.next_power_of_two().ilog2(),
                "log_memory_cells":stats.log_mem,"min_log_committed":22,"rate":rate}));
            proofs.push(proof);
            public.push(pi);
            all_points.push(points);
            println!("pass {pass} merge {node_id}: {prove_s:.6}s");
        }
        if pass >= warmup {
            passes.push(json!({"pass":pass-warmup,"elapsed_s":pass_start.elapsed().as_secs_f64(),"nodes":node_reports}));
        }
        last = Some(Envelope {
            version: 1,
            plan_hash: plan.hash,
            root_guest_hash: seed(&plan.nodes[plan.root].program),
            deferred_points_by_merge: all_points,
            proof: proofs[plan.root].clone(),
        });
    }
    let envelope = last.ok_or("no measured passes")?;
    let verification = verify(plan, &envelope, 1, 0)?;
    fs::write(out.join("aggregate.proof"), wire().serialize(&envelope)?)?;
    fs::write(
        out.join("aggregate.core.proof"),
        wire().serialize(&envelope.proof)?,
    )?;
    let mut report = description(plan);
    report["action"] = json!("prove");
    report["statement_pinned"] = json!(true);
    report["rate"] = json!(rate);
    report["repeat"] = json!(repeat);
    report["warmup"] = json!(warmup);
    report["leaf_reports"] = json!(leaf_reports);
    report["merge_passes"] = json!(passes);
    report["leaf_reuse_count"] = json!(leaf_reports.iter().filter(|r| r["reused"] == true).count());
    report["merge_reuse_count"] = json!(0);
    report["verification"] = verification;
    report["pipeline_elapsed_s"] = json!(pipeline.elapsed().as_secs_f64());
    report["process_peak_rss_bytes"] = json!(bench::peak_rss_bytes());
    report["zero_knowledge"] = json!(false);
    report["repeat_scope"] =
        json!("all merge nodes; leaves prepared once, cache reuse explicitly reported");
    save(&out.join("report.json"), &report)?;
    save(&out.join("plan.json"), &description(plan))?;
    Ok(report)
}

fn main() -> Result<()> {
    leanvm_core::init_prover();
    let args: Vec<_> = std::env::args().skip(1).collect();
    let action = args
        .first()
        .map(String::as_str)
        .ok_or("usage: aggregate-tree inspect|prove|verify --manifest FILE [options]")?;
    let mut options = BTreeMap::new();
    let mut fresh = false;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--fresh-leaves" {
            fresh = true;
            i += 1;
            continue;
        }
        if !args[i].starts_with("--") || i + 1 == args.len() {
            return Err("options require --name value".into());
        }
        if options
            .insert(args[i].clone(), args[i + 1].clone())
            .is_some()
        {
            return Err("duplicate option".into());
        }
        i += 2;
    }
    for key in options.keys() {
        if ![
            "--manifest",
            "--expect-plan-hash",
            "--leaf-cache-dir",
            "--out-dir",
            "--rate",
            "--repeat",
            "--warmup",
            "--proof",
            "--report",
        ]
        .contains(&key.as_str())
        {
            return Err(format!("unknown option {key}").into());
        }
    }
    let manifest = options.get("--manifest").ok_or("--manifest required")?;
    let plan = load_plan(Path::new(manifest))?;
    if action != "inspect"
        && bytes32(
            options
                .get("--expect-plan-hash")
                .ok_or("--expect-plan-hash required from independently trusted intended claims")?,
        )? != plan.hash
    {
        return Err("trusted plan hash mismatch".into());
    }
    let number = |key: &str, default: usize| -> Result<usize> {
        Ok(options
            .get(key)
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(default))
    };
    let repeat = number("--repeat", 1)?;
    let warmup = number("--warmup", 0)?;
    let rate = number("--rate", 1)?;
    if repeat == 0 || repeat > 100 || warmup > 100 || !(1..=4).contains(&rate) {
        return Err("invalid repeat/warmup/rate".into());
    }
    let report = match action {
        "inspect" => description(&plan),
        "prove" => prove(
            &plan,
            Path::new(
                options
                    .get("--leaf-cache-dir")
                    .ok_or("--leaf-cache-dir required")?,
            ),
            Path::new(options.get("--out-dir").ok_or("--out-dir required")?),
            rate,
            repeat,
            warmup,
            fresh,
        )?,
        "verify" => {
            let encoded = fs::read(options.get("--proof").ok_or("--proof required")?)?;
            let envelope: Envelope = wire().deserialize(&encoded)?;
            let mut report = verify(&plan, &envelope, repeat, warmup)?;
            report["action"] = json!("verify");
            report["process_peak_rss_bytes"] = json!(bench::peak_rss_bytes());
            report
        }
        _ => return Err("expected inspect, prove or verify".into()),
    };
    if let Some(path) = options.get("--report") {
        save(Path::new(path), &report)?;
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn topology_covers_every_leaf_exactly_once_and_carries_singletons() {
        for b in [2, 4, 8] {
            for leaves in 1..=100 {
                let (groups, root) = topology(leaves, b);
                let mut covered: Vec<Vec<usize>> = (0..leaves).map(|i| vec![i]).collect();
                for children in &groups {
                    assert!((2..=b).contains(&children.len()));
                    covered.push(children.iter().flat_map(|&i| covered[i].clone()).collect());
                }
                assert_eq!(covered[root], (0..leaves).collect::<Vec<_>>());
                assert_eq!(
                    groups.iter().map(Vec::len).sum::<usize>(),
                    leaves + groups.len() - 1
                );
            }
        }
    }

    #[test]
    #[ignore = "produces a small padded toy tree; run explicitly without concurrent benchmark proving"]
    fn toy_three_level_tree_preserves_all_inherited_obligations() {
        leanvm_core::init_prover();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("pqbench-tree-{}-{unique}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        // This toy relation only binds two hinted public cells. It exercises
        // proof composition and carries no signature-security interpretation.
        let source = "from snark_lib import *\n\ndef main():\n    values = StackBuf(2)\n    hint_witness(values, \"toy\")\n    public = GEN ** 0\n    public[1] = values[0]\n    public[GEN] = values[1]\n    return\n";
        fs::write(directory.join("leaf.py"), source).unwrap();
        let program = lean_compiler::compile(&lean_compiler::parse(source).unwrap());
        let hash = hex(&seed(&program));
        let mut leaves = Vec::new();
        for i in 0..5 {
            let pi = [F192::new(i + 1, 17, 0), F192::new(23, i + 29, 0)];
            let name = format!("input-{i}.json");
            save(
                &directory.join(&name),
                &json!({"source":source,
                "public_input":pi.map(|x|[x.c0,x.c1,x.c2]),
                "witness":{"toy":[pi.map(|x|[x.c0,x.c1,x.c2])]}}),
            )
            .unwrap();
            leaves.push(json!({"program_id":"toy","signatures":if i==4{1}else{2},
                "public_input_hex":hex(&cpu::public_input_bytes(&pi)),"input_file":name}));
        }
        let manifest = directory.join("manifest.json");
        save(&manifest,&json!({"schema_version":1,"scheme":"toy-public-cell-relation",
            "signatures":9,"leaf_capacity":2,"fan_in":2,
            "programs":[{"id":"toy","source_file":"leaf.py","expected_guest_hash":hash,"min_log_committed":22}],
            "leaves":leaves})).unwrap();
        let plan = load_plan(&manifest).unwrap();
        assert_eq!(plan.nodes[plan.root].depth, 3);
        assert!(
            plan.nodes[plan.root]
                .children
                .iter()
                .map(|&n| kbc(&plan.nodes[n].program))
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                > 1
        );
        let cache = directory.join("cache");
        let output = directory.join("proofs");
        let report = prove(&plan, &cache, &output, 1, 1, 0, false).unwrap();
        assert_eq!(report["verification"]["verified"], true);
        let envelope: Envelope = wire()
            .deserialize(&fs::read(output.join("aggregate.proof")).unwrap())
            .unwrap();
        assert_eq!(envelope.deferred_points_by_merge.len(), 4);
        assert_eq!(
            envelope
                .deferred_points_by_merge
                .iter()
                .map(Vec::len)
                .sum::<usize>(),
            8
        );
        let mut bad = envelope.clone();
        bad.deferred_points_by_merge[0][0][0].c2 ^= 1;
        assert!(
            verify(&plan, &bad, 1, 0).is_err(),
            "an inherited lowest-level obligation must be checked"
        );
        let mut bad = envelope.clone();
        bad.deferred_points_by_merge.pop();
        assert!(verify(&plan, &bad, 1, 0).is_err());
        let mut bad = envelope.clone();
        bad.root_guest_hash[0] ^= 1;
        assert!(verify(&plan, &bad, 1, 0).is_err());
        // Final checking only needs trusted sources/expected public claims and
        // the root envelope, even when every child proof/input is unavailable.
        fs::remove_dir_all(&cache).unwrap();
        for i in 0..5 {
            fs::remove_file(directory.join(format!("input-{i}.json"))).unwrap();
        }
        for node in 5..9 {
            fs::remove_file(output.join(format!("node-{node}.proof"))).unwrap();
        }
        let reloaded = load_plan(&manifest).unwrap();
        assert_eq!(reloaded.hash, plan.hash);
        assert_eq!(
            verify(&reloaded, &envelope, 1, 0).unwrap()["verified"],
            true
        );
        let mut trailing = wire().serialize(&envelope).unwrap();
        trailing.push(0);
        assert!(wire().deserialize::<Envelope>(&trailing).is_err());
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&json!({"test":"toy_three_level_tree",
            "plan_hash":hex(&plan.hash),"depth":3,"edges":8,
            "lowest_inherited_point_mutation_rejected":true,"missing_points_rejected":true,
            "source_only_reload_verified":true,"result_directory":directory}))
            .unwrap()
        );
    }

    #[test]
    #[ignore = "proves a bounded malicious-prover control through two wrappers; run after benchmark proving finishes"]
    fn forged_bytecode_is_rejected_through_two_wrapper_levels() {
        use leanvm_core::cpu::Op;
        use primitives::field::g_pow;

        fn prove_merge(
            plan: &Plan,
            id: usize,
            prepared: Vec<recursion_support::PreparedChild>,
        ) -> (Proof, [F192; 2], Vec<Vec<F192>>, Vec<F192>) {
            let node = &plan.nodes[id];
            let mut streams: Streams = BTreeMap::new();
            let mut points = Vec::new();
            let mut values = Vec::new();
            let mut public = Vec::new();
            for child in prepared {
                for (name, entries) in child.streams {
                    streams.entry(name).or_default().extend(entries);
                }
                points.push(child.bytecode_point);
                values.push(child.bytecode_value);
                public.push(child.public_input);
            }
            streams.insert(
                "tree_child_pi".into(),
                public.iter().map(|p| p.to_vec()).collect(),
            );
            let pi = tree_guest::public_input(
                tree_guest::halves(plan.hash),
                &child_specs(plan, node),
                &public,
                &points,
                &values,
            )
            .unwrap();
            let mut program = (*node.program).clone();
            set_streams(&mut program, streams);
            let execution = program.execute(pi).unwrap();
            assert!(execution.unconstrained_reads.is_empty());
            let (proof, _) = cpu::prove(&program, pi, 1).unwrap();
            cpu::verify(&node.program, &pi, &proof).unwrap();
            (proof, pi, points, values)
        }

        leanvm_core::init_prover();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "pqbench-forged-tree-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        // A's relation requires first public cell = 1; its second public cell
        // is an arbitrary public tag. No signature-security claim is involved.
        let source = "from snark_lib import *\n\ndef main():\n    public = GEN ** 0\n    public[1] = 1\n    return\n";
        fs::write(directory.join("leaf.py"), source).unwrap();
        let expected = lean_compiler::compile(&lean_compiler::parse(source).unwrap());
        let expected_seed = seed(&expected);
        let honest_pi: Vec<_> = (0..3)
            .map(|i| [F192::ONE, F192::new(101 + i, 0, 0)])
            .collect();
        let false_pi = [F192::new(2, 0, 0), honest_pi[0][1]];
        assert!(
            expected.execute(false_pi).is_err(),
            "A really excludes the false public input"
        );
        let mut leaves = Vec::new();
        for (i, pi) in honest_pi.iter().enumerate() {
            let input = format!("leaf-{i}.json");
            save(
                &directory.join(&input),
                &json!({"source":source,
                "public_input":pi.map(|x|[x.c0,x.c1,x.c2]),"witness":{}}),
            )
            .unwrap();
            leaves.push(json!({"program_id":"expected-A","signatures":1,
                "public_input_hex":hex(&cpu::public_input_bytes(pi)),"input_file":input}));
        }
        let mut manifest = json!({"schema_version":1,"scheme":"toy-first-cell-equals-one",
            "signatures":3,"leaf_capacity":1,"fan_in":2,
            "programs":[{"id":"expected-A","source_file":"leaf.py",
                "expected_guest_hash":hex(&expected_seed),"min_log_committed":22}],"leaves":leaves});
        let manifest_path = directory.join("honest.json");
        save(&manifest_path, &manifest).unwrap();
        let honest = load_plan(&manifest_path).unwrap();
        assert_eq!(honest.nodes[honest.root].depth, 2);
        let cache = directory.join("cache");
        let positive = prove(
            &honest,
            &cache,
            &directory.join("honest-proofs"),
            1,
            1,
            0,
            false,
        )
        .unwrap();
        assert_eq!(positive["verification"]["verified"], true);
        let honest_proofs: Vec<Proof> = honest_pi
            .iter()
            .map(|pi| {
                let label = format!(
                    "{}-{}-r1-m22.proof",
                    hex(&expected_seed),
                    hex(&cpu::public_input_bytes(pi))
                );
                wire()
                    .deserialize(&fs::read(cache.join(label)).unwrap())
                    .unwrap()
            })
            .collect();

        manifest["leaves"][0]["public_input_hex"] = json!(hex(&cpu::public_input_bytes(&false_pi)));
        let negative_path = directory.join("false-claim.json");
        save(&negative_path, &manifest).unwrap();
        let plan = load_plan(&negative_path).unwrap();
        assert_eq!(plan.nodes[plan.root].depth, 2);
        assert_eq!(plan.nodes[3].children, [0, 1]);
        assert_eq!(plan.nodes[4].children, [3, 2]);

        // B only halts. Its normal native proof accepts the false public input,
        // whereas A's constraints reject it. The malicious prover next supplies
        // B's bytecode while retaining A's cached Fiat–Shamir seed, exactly the
        // deferral boundary used by the earlier single-wrapper control.
        let mut malicious = expected.clone();
        malicious.prog.fill(Op::Xor { a: 0, b: 0, c: 0 });
        malicious.prog[0] = Op::Set {
            o: 50_000,
            k: F192::from(g_pow(malicious.prog.len() - 1)),
        };
        malicious.prog[1] = Op::Set {
            o: 50_001,
            k: F192::ONE,
        };
        malicious.prog[2] = Op::Jump {
            oc: 50_001,
            od: 50_000,
            of: 50_001,
        };
        malicious.min_log_committed = 22;
        let mut normal_b = Program::assemble(malicious.prog.clone(), Default::default(), 50_010);
        normal_b.min_log_committed = 22;
        let (normal_b_proof, _) = cpu::prove(&normal_b, false_pi, 1).unwrap();
        cpu::verify(&normal_b, &false_pi, &normal_b_proof).unwrap();
        assert_ne!(seed(&normal_b), expected_seed);
        assert_eq!(seed(&malicious), expected_seed);
        assert_eq!(malicious.execute(false_pi).unwrap().cycles, 3);
        let (malicious_proof, _) = cpu::prove(&malicious, false_pi, 1).unwrap();
        let child_rejection = cpu::verify(&expected, &false_pi, &malicious_proof)
            .expect_err("native A verification must reject B's cached-seed execution");
        let table: Vec<_> = cpu::bytecode_table(&expected.prog)
            .iter()
            .map(|x| x.0)
            .collect();
        let bytecode = verifier::Bytecode::new(&table);
        let forged = recursion_support::child_witness_replay_unchecked_for_test(
            &malicious,
            &bytecode,
            false_pi,
            &malicious_proof,
        )
        .unwrap();
        let correct = cpu::from_scalar(
            bytecode
                .evaluate(
                    &forged
                        .bytecode_point
                        .iter()
                        .map(cpu::to_scalar)
                        .collect::<Vec<_>>(),
                )
                .unwrap(),
        );
        assert_ne!(forged.bytecode_value, correct);
        let forged_value = forged.bytecode_value;
        let honest_second =
            recursion_support::child_witness(&expected, honest_pi[1], &honest_proofs[1]).unwrap();
        let (wrapper1, wrapper1_pi, points1, _) =
            prove_merge(&plan, 3, vec![forged, honest_second]);

        // Above wrapper1, use only checked production advice preparation. Its
        // proof is valid for its actual bytecode and advertised (dishonest) PI.
        // Thus every immediate bytecode obligation at wrapper2 is honest.
        let first =
            recursion_support::child_witness(&plan.nodes[3].program, wrapper1_pi, &wrapper1)
                .unwrap();
        let third =
            recursion_support::child_witness(&expected, honest_pi[2], &honest_proofs[2]).unwrap();
        let (root_proof, prover_pi, points2, values2) = prove_merge(&plan, 4, vec![first, third]);
        let envelope = Envelope {
            version: 1,
            plan_hash: plan.hash,
            root_guest_hash: seed(&plan.nodes[4].program),
            deferred_points_by_merge: vec![points1, points2.clone()],
            proof: root_proof,
        };
        let evaluators = Evaluators::new(&plan);
        for ((&child, point), value) in plan.nodes[4].children.iter().zip(&points2).zip(&values2) {
            assert_eq!(
                evaluators
                    .evaluate(&plan.nodes[child].program, point)
                    .unwrap(),
                *value
            );
        }
        let authorized_pi =
            expected_root_input(&plan, &envelope.deferred_points_by_merge, &evaluators).unwrap();
        assert_ne!(
            authorized_pi, prover_pi,
            "inherited evaluation changes the required root statement"
        );
        cpu::verify(&plan.nodes[4].program, &prover_pi, &envelope.proof).unwrap();
        let root_rejection = cpu::verify(&plan.nodes[4].program, &authorized_pi, &envelope.proof)
            .expect_err("native all-edge discharge must reject the twice-wrapped false claim");
        assert!(
            verify(&plan, &envelope, 1, 0).is_err(),
            "the unchanged production verdict must reject"
        );
        let evidence = json!({"test":"forged_bytecode_through_two_wrapper_levels","depth":2,
            "honest_positive_verified":true,"false_input_rejected_by_A_execution":true,
            "normal_B_native_proof_accepts_false_input":true,
            "malicious_cached_seed_child_native_A_rejection":format!("{child_rejection:?}"),
            "wrapper1_partial_verifier_proof_accepts":true,"wrapper2_proof_native_accepts_prover_statement":true,
            "all_root_immediate_bytecode_evaluations_correct":true,
            "all_edge_recomputed_statement_differs":true,
            "production_root_verifier_rejects":true,"native_root_rejection":format!("{root_rejection:?}"),
            "expected_leaf_value":[correct.c0,correct.c1,correct.c2],
            "forged_leaf_value":[forged_value.c0,forged_value.c1,forged_value.c2],
            "root_core_proof_bytes":wire().serialized_size(&envelope.proof).unwrap(),
            "scope":"test-only malicious-prover control; no production verification checks disabled; not a backend soundness attack",
            "result_directory":directory});
        save(
            &directory.join("deferred-boundary-two-level.json"),
            &evidence,
        )
        .unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&evidence).unwrap());
    }
}
