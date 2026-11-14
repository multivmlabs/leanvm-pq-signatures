//! Binary bounded-depth wrappers. One authenticated accumulator per program family.
use crate::{recursion_guest, reduction::Reduced};
use lean_compiler::Ast;
use leanvm_core::cpu::{self, Program};
use primitives::field::{F64, F192};
use serde::{Deserialize, Serialize};

pub const STATE_DOMAIN: &[u8; 16] = b"pq-red-state/v1\0";
pub const CLAIM_DOMAIN: &[u8; 16] = b"pq-red-claim/v1\0";
pub const CONTEXT_DOMAIN: &[u8; 16] = b"pq-red-ctx/v1\0\0\0";

#[derive(Clone)]
pub struct Family {
    pub program: Program,
    pub seed: [F192; 2],
    pub dimensions: usize,
    pub table: Vec<F64>,
}

impl Family {
    pub fn new(mut program: Program) -> Self {
        program.min_log_committed = 22;
        let seed = cpu::fs_seed(&program);
        let table = cpu::bytecode_table(&program.prog);
        let dimensions = table.len().ilog2() as usize;
        Self {
            program,
            seed,
            dimensions,
            table,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub claim_digest: [F192; 2],
    pub accumulators: Vec<Reduced>,
}

pub fn halves(bytes: [u8; 32]) -> [F192; 2] {
    let w = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
    [F192::new(w(0), w(8), 0), F192::new(w(16), w(24), 0)]
}
pub fn digest_bytes(x: &[F192; 2]) -> Result<[u8; 32], String> {
    if x.iter().any(|w| w.c2 != 0) {
        return Err("noncanonical digest".into());
    }
    Ok(cpu::public_input_bytes(x))
}
pub fn policy(seed: [F192; 2], leaf_size: usize) -> [F192; 2] {
    let mut b = b"pqbench/leanISA/reduced-tree/v1\0".to_vec();
    b.extend(digest_bytes(&seed).unwrap());
    b.extend((leaf_size as u128).to_le_bytes());
    b.extend(2u128.to_le_bytes());
    halves(primitives::hash::hash(&b))
}
pub fn claim_digest(children: &[[F192; 2]]) -> Result<[F192; 2], String> {
    if children.len() != 2 {
        return Err("binary claims require two children".into());
    }
    let mut b = CLAIM_DOMAIN.to_vec();
    b.extend(2u128.to_le_bytes());
    for x in children {
        b.extend(digest_bytes(x)?);
    }
    Ok(halves(primitives::hash::hash(&b)))
}
pub fn context(
    policy: [F192; 2],
    depth: usize,
    claim: [F192; 2],
    child_pi: &[[F192; 2]],
) -> Result<[F192; 2], String> {
    if child_pi.len() != 2 {
        return Err("binary context requires two children".into());
    }
    let mut b = CONTEXT_DOMAIN.to_vec();
    b.extend(digest_bytes(&policy)?);
    b.extend((depth as u128).to_le_bytes());
    b.extend(digest_bytes(&claim)?);
    for x in child_pi {
        b.extend(digest_bytes(x)?);
    }
    Ok(halves(primitives::hash::hash(&b)))
}
pub fn state_input(
    policy: [F192; 2],
    families: &[Family],
    state: &State,
) -> Result<[F192; 2], String> {
    digest_bytes(&state.claim_digest)?;
    if families.is_empty() {
        if !state.accumulators.is_empty() {
            return Err("leaf accumulators".into());
        }
        return Ok(state.claim_digest);
    }
    if families.len() != state.accumulators.len() {
        return Err("one accumulator per required family".into());
    }
    let mut b = STATE_DOMAIN.to_vec();
    b.extend(digest_bytes(&policy)?);
    b.extend((families.len() as u128).to_le_bytes());
    b.extend((1u128 << families.len()).to_le_bytes());
    b.extend(digest_bytes(&state.claim_digest)?);
    for (f, a) in families.iter().zip(&state.accumulators) {
        if a.point.len() != f.dimensions {
            return Err("accumulator dimension".into());
        }
        b.extend(digest_bytes(&f.seed)?);
        b.extend((f.dimensions as u128).to_le_bytes());
        let fields: Vec<_> = a.point.iter().copied().chain([a.value]).collect();
        for x in &fields {
            b.extend(x.c0.to_le_bytes());
            b.extend(x.c1.to_le_bytes());
            b.extend(x.c2.to_le_bytes());
        }
        if fields.len() % 2 == 1 {
            b.extend([0u8; 24]);
        }
    }
    Ok(halves(primitives::hash::hash(&b)))
}
pub fn state_fields(state: &State) -> Vec<F192> {
    state
        .claim_digest
        .into_iter()
        .chain(
            state
                .accumulators
                .iter()
                .flat_map(|a| a.point.iter().copied().chain([a.value])),
        )
        .collect()
}
fn lit(x: F192) -> String {
    format!("f192({},{},{})", x.c0, x.c1, x.c2)
}
fn dsl_domain(d: &[u8; 16]) -> u128 {
    u128::from_le_bytes(*d)
}

fn state_hash_source(policy: [F192; 2], families: &[Family]) -> String {
    let cells = 7 + families
        .iter()
        .map(|f| 3 + 3 * (f.dimensions + 1).div_ceil(2))
        .sum::<usize>();
    let state_fields = 2 + families.iter().map(|f| f.dimensions + 1).sum::<usize>();
    let mut s = format!(
        "\ndef reduced_state_hash(state: StackBuf({state_fields})):\n    cells = StackBuf({cells})\n    cells[0] = {}\n    cells[1] = {}\n    cells[2] = {}\n    cells[3] = {}\n    cells[4] = {}\n    cells[5] = state[0]\n    cells[6] = state[1]\n",
        dsl_domain(STATE_DOMAIN),
        lit(policy[0]),
        lit(policy[1]),
        families.len(),
        1usize << families.len()
    );
    let (mut at, mut field) = (7, 2);
    for f in families {
        s.push_str(&format!(
            "    cells[{at}] = {}\n    cells[{}] = {}\n    cells[{}] = {}\n",
            lit(f.seed[0]),
            at + 1,
            lit(f.seed[1]),
            at + 2,
            f.dimensions
        ));
        at += 3;
        for pair in 0..(f.dimensions + 1).div_ceil(2) {
            let right = if 2 * pair + 1 < f.dimensions + 1 {
                format!("state[{}]", field + 2 * pair + 1)
            } else {
                "0".into()
            };
            s.push_str(&format!(
                "    red_pack_pair(cells, {}, state[{}], {right})\n",
                at + 3 * pair,
                field + 2 * pair
            ));
        }
        field += f.dimensions + 1;
        at += 3 * (f.dimensions + 1).div_ceil(2);
    }
    s.push_str("    out = StackBuf(2)\n    keccak_cells(cells, out)\n    return out\n");
    s
}

/// Compile level `families.len()`, depending only on already-built descendants.
pub fn compile(policy: [F192; 2], families: &[Family]) -> Result<Program, String> {
    if families.is_empty() || families.len() > 8 {
        return Err("supported wrapper depth 1..8".into());
    }
    let child = families.last().unwrap();
    let kbc = child.program.prog.len().ilog2() as usize;
    let mut ast = lean_compiler::parse_with_replacements(
        &recursion_guest::source(),
        &recursion_guest::replacements(kbc, [F192::ZERO; 2], 1)?,
    )?;
    ast.funcs.retain(|f| f.name != "main");
    let mut primitive = lean_compiler::parse(include_str!("../guest/sumcheck.py"))?;
    ast.funcs.append(&mut primitive.funcs);
    ast.const_arrays.append(&mut primitive.const_arrays);
    let prior = &families[..families.len() - 1];
    if !prior.is_empty() {
        ast.funcs
            .extend(lean_compiler::parse(&state_hash_source(policy, prior))?.funcs);
    }
    let fields = 2 + prior.iter().map(|f| f.dimensions + 1).sum::<usize>();
    let outfields = 2 + families.iter().map(|f| f.dimensions + 1).sum::<usize>();
    let defer_size = crate::recursion_support::replacements(kbc)["DEFER_SIZE_PLACEHOLDER"].clone();
    let mut main = format!(
        "\ndef main():\n    logs, squares = exponent_tables()\n    output = StackBuf({outfields})\n"
    );
    for i in 0..2 {
        main.push_str(&format!("    child{i} = StackBuf({fields})\n    hint_witness(child{i}, \"reduced_child_state\")\n    pi{i} = StackBuf(2)\n"));
        if prior.is_empty() {
            main.push_str(&format!(
                "    pi{i}[0] = child{i}[0]\n    pi{i}[1] = child{i}[1]\n"
            ));
        } else {
            main.push_str(&format!("    pi{i} = reduced_state_hash(child{i})\n"));
        }
        main.push_str(&format!("    deferred{i} = HeapBuf({defer_size})\n    verify_sub(pi{i}[0], pi{i}[1], {}, {}, logs, squares, deferred{i})\n",lit(child.seed[0]),lit(child.seed[1])));
    }
    main.push_str(&format!("    claims = StackBuf(6)\n    claims[0] = {}\n    claims[1] = 2\n    claims[2] = child0[0]\n    claims[3] = child0[1]\n    claims[4] = child1[0]\n    claims[5] = child1[1]\n    claim = StackBuf(2)\n    keccak_cells(claims, claim)\n    output[0] = claim[0]\n    output[1] = claim[1]\n    header = StackBuf(10)\n    header[0] = {}\n    header[1] = {}\n    header[2] = {}\n    header[3] = {}\n    header[4] = claim[0]\n    header[5] = claim[1]\n    header[6] = pi0[0]\n    header[7] = pi0[1]\n    header[8] = pi1[0]\n    header[9] = pi1[1]\n    ctx = StackBuf(2)\n    keccak_cells(header, ctx)\n",dsl_domain(CLAIM_DOMAIN),dsl_domain(CONTEXT_DOMAIN),lit(policy[0]),lit(policy[1]),families.len()));
    let (mut inherited_at, mut out_at) = (2, 2);
    for (j, f) in families.iter().enumerate() {
        let n = f.dimensions;
        main.push_str(&format!("    points{j} = HeapBuf({})\n    values{j} = HeapBuf(2)\n    reduced{j} = HeapBuf({n})\n",2*n));
        for i in 0..2 {
            for d in 0..n {
                let read = if j + 1 == families.len() {
                    format!("deferred{i}[GEN ** {d}]")
                } else {
                    format!("child{i}[{}]", inherited_at + d)
                };
                main.push_str(&format!("    points{j}[GEN ** {}] = {read}\n", i * n + d));
            }
            let read = if j + 1 == families.len() {
                format!("deferred{i}[GEN ** {n}]")
            } else {
                format!("child{i}[{}]", inherited_at + n)
            };
            main.push_str(&format!("    values{j}[GEN ** {i}] = {read}\n"));
        }
        main.push_str(&format!("    value{j} = red_reduce_claims({}, {}, ctx[0], ctx[1], points{j}, values{j}, reduced{j}, {n}, 2)\n",lit(f.seed[0]),lit(f.seed[1])));
        for d in 0..n {
            main.push_str(&format!(
                "    output[{}] = reduced{j}[GEN ** {d}]\n",
                out_at + d
            ));
        }
        main.push_str(&format!("    output[{}] = value{j}\n", out_at + n));
        inherited_at += n + 1;
        out_at += n + 1;
    }
    // The output statement has all current families; the child helper has fewer.
    let output_hash =
        state_hash_source(policy, families).replace("reduced_state_hash", "reduced_output_hash");
    ast.funcs.extend(lean_compiler::parse(&output_hash)?.funcs);
    main.push_str("    digest = reduced_output_hash(output)\n    public = GEN ** 0\n    public[1] = digest[0]\n    public[GEN] = digest[1]\n    return\n");
    let mut extra: Ast = lean_compiler::parse(&main)?;
    ast.funcs.append(&mut extra.funcs);
    let mut program = lean_compiler::compile(&ast);
    program.min_log_committed = 22;
    Ok(program)
}

pub fn build(
    leaf_source: &str,
    depth: usize,
    leaf_size: usize,
) -> Result<([F192; 2], Vec<Family>), String> {
    if !(1..=8).contains(&depth) {
        return Err("supported depth 1..8".into());
    }
    let leaf = Family::new(lean_compiler::compile(&lean_compiler::parse(leaf_source)?));
    let policy = policy(leaf.seed, leaf_size);
    let mut families = vec![leaf];
    for _ in 0..depth {
        let p = compile(policy, &families)?;
        families.push(Family::new(p));
    }
    Ok((policy, families))
}
