//! Generic, bounded-depth recursion with every bytecode obligation retained.
//!
//! The verifier functions retain the pinned upstream MIT attribution in
//! `recursion_guest.rs` and `third_party/leanvm-MIT.txt`. Each distinct child
//! bytecode size receives a namespaced parsed AST, with no protocol changes.

use std::collections::{BTreeMap, BTreeSet};

use lean_compiler::{Ast, Expr, ForBound, LtBound, Stmt, StmtKind};
use leanvm_core::cpu::Program;
use primitives::field::F192;

pub const DOMAIN: &[u8; 16] = b"pqbench/tree/v1\0";

#[derive(Clone, Copy, Debug)]
pub struct Child {
    pub kbc: usize,
    pub seed: [F192; 2],
}

fn rename(name: &mut String, names: &BTreeMap<String, String>) {
    if let Some(replacement) = names.get(name) {
        *name = replacement.clone();
    }
}

fn rename_expr(expr: &mut Expr, names: &BTreeMap<String, String>) {
    match expr {
        Expr::Var(name) => rename(name, names),
        Expr::Call(name, args) => {
            rename(name, names);
            args.iter_mut().for_each(|x| rename_expr(x, names));
        }
        Expr::GenPow(a) | Expr::HeapBufDyn(a) => rename_expr(a, names),
        Expr::Pow(a, b)
        | Expr::Add(a, b)
        | Expr::Mul(a, b)
        | Expr::Sub(a, b)
        | Expr::Div(a, b)
        | Expr::Mod(a, b)
        | Expr::FieldDiv(a, b)
        | Expr::Index(a, b) => {
            rename_expr(a, names);
            rename_expr(b, names);
        }
        Expr::Slice(a, b, c) | Expr::ListComp(a, _, b, c) => {
            rename_expr(a, names);
            rename_expr(b, names);
            rename_expr(c, names);
        }
        Expr::ListLit(args) => args.iter_mut().for_each(|x| rename_expr(x, names)),
        Expr::Lit(_) | Expr::Gen | Expr::GPow(_) | Expr::HeapBuf(_) | Expr::StackBuf(_) => {}
    }
}

fn rename_stmts(stmts: &mut [Stmt], names: &BTreeMap<String, String>) {
    for stmt in stmts {
        match &mut stmt.kind {
            StmtKind::Let(_, e) | StmtKind::Print { value: e, .. } => rename_expr(e, names),
            StmtKind::LetTuple(_, name, args) | StmtKind::Call(name, args) => {
                rename(name, names);
                args.iter_mut().for_each(|e| rename_expr(e, names));
            }
            StmtKind::AssertEq(a, b) | StmtKind::AssertNe(a, b) => {
                rename_expr(a, names);
                rename_expr(b, names);
            }
            StmtKind::AssertLt(a, bound) => {
                rename_expr(a, names);
                if let LtBound::Runtime(b) = bound {
                    rename_expr(b, names);
                }
            }
            StmtKind::HintWitness { dest, .. } => rename_expr(dest, names),
            StmtKind::LetHintWitness { .. } => {}
            StmtKind::If {
                lhs,
                rhs,
                then,
                els,
                ..
            } => {
                rename_expr(lhs, names);
                rename_expr(rhs, names);
                rename_stmts(then, names);
                rename_stmts(els, names);
            }
            StmtKind::Match { targets, x, arms } => {
                rename_expr(x, names);
                targets
                    .iter_mut()
                    .chain(arms)
                    .for_each(|e| rename_expr(e, names));
            }
            StmtKind::Store(a, b, c) => {
                rename_expr(a, names);
                rename_expr(b, names);
                rename_expr(c, names);
            }
            StmtKind::For { hi, body, .. } => {
                if let ForBound::Runtime(e) = hi {
                    rename_expr(e, names);
                }
                rename_stmts(body, names);
            }
            StmtKind::Unroll { lo, hi, body, .. } => {
                rename_expr(lo, names);
                rename_expr(hi, names);
                rename_stmts(body, names);
            }
            StmtKind::Return(args) => args.iter_mut().for_each(|e| rename_expr(e, names)),
            StmtKind::CallIfNe(a, b, name, args) => {
                rename_expr(a, names);
                rename_expr(b, names);
                rename(name, names);
                args.iter_mut().for_each(|e| rename_expr(e, names));
            }
        }
    }
}

fn verifier_ast(kbc: usize) -> Result<Ast, String> {
    let mut ast = lean_compiler::parse_with_replacements(
        &crate::recursion_guest::source(),
        &crate::recursion_guest::replacements(kbc, [F192::ZERO; 2], 1)?,
    )?;
    ast.funcs.retain(|f| f.name != "main");
    let names: BTreeMap<_, _> = ast
        .funcs
        .iter()
        .map(|f| &f.name)
        .chain(ast.const_arrays.iter().map(|(name, _)| name))
        .map(|name| (name.clone(), format!("bc{kbc}_{name}")))
        .collect();
    for function in &mut ast.funcs {
        rename(&mut function.name, &names);
        rename_stmts(&mut function.body, &names);
    }
    for (name, _) in &mut ast.const_arrays {
        rename(name, &names);
    }
    Ok(ast)
}

fn literal(x: F192) -> String {
    format!("f192({},{},{})", x.c0, x.c1, x.c2)
}

fn canonical(x: F192) -> Result<(), String> {
    if x.c2 != 0 {
        return Err("digest cells must be canonical 128-bit values".into());
    }
    Ok(())
}

fn build_ast(plan: [F192; 2], children: &[Child]) -> Result<Ast, String> {
    if !(2..=8).contains(&children.len()) {
        return Err("tree merge arity must be 2..=8".into());
    }
    canonical(plan[0])?;
    canonical(plan[1])?;
    let mut ast = Ast {
        funcs: Vec::new(),
        const_arrays: Vec::new(),
    };
    for kbc in children.iter().map(|c| c.kbc).collect::<BTreeSet<_>>() {
        let verifier = verifier_ast(kbc)?;
        ast.funcs.extend(verifier.funcs);
        ast.const_arrays.extend(verifier.const_arrays);
    }
    let cells = 4 + children
        .iter()
        .map(|c| {
            let fields = c.kbc + leanvm_core::leaf::N_BYTECODE_SELECTORS + 1;
            4 + 3 * fields.div_ceil(2)
        })
        .sum::<usize>();
    let mut main = format!(
        "from snark_lib import *\n\ndef main():\n    statement = StackBuf({cells})\n    statement[0] = {}\n    statement[1] = {}\n    statement[2] = {}\n    statement[3] = {}\n",
        u128::from_le_bytes(*DOMAIN),
        children.len(),
        literal(plan[0]),
        literal(plan[1]),
    );
    for kbc in children.iter().map(|c| c.kbc).collect::<BTreeSet<_>>() {
        main.push_str(&format!(
            "    logs{kbc}, squares{kbc} = bc{kbc}_exponent_tables()\n"
        ));
    }
    let mut offset = 4;
    for (i, child) in children.iter().enumerate() {
        canonical(child.seed[0])?;
        canonical(child.seed[1])?;
        let kbc = child.kbc;
        let fields = kbc + leanvm_core::leaf::N_BYTECODE_SELECTORS + 1;
        // DEFER_SIZE may exceed the public point/value length for upstream's
        // internal allocation layout; obtain the exact structural replacement.
        let replacements = crate::recursion_support::replacements(kbc);
        let defer_size = &replacements["DEFER_SIZE_PLACEHOLDER"];
        main.push_str(&format!(
            "    pi{i} = StackBuf(2)\n    hint_witness(pi{i}, \"tree_child_pi\")\n    deferred{i} = HeapBuf({defer_size})\n    bc{kbc}_verify_sub(pi{i}[0], pi{i}[1], {}, {}, logs{kbc}, squares{kbc}, deferred{i})\n    statement[{offset}] = {}\n    statement[{}] = {}\n    statement[{}] = pi{i}[0]\n    statement[{}] = pi{i}[1]\n",
            literal(child.seed[0]), literal(child.seed[1]), literal(child.seed[0]),
            offset + 1, literal(child.seed[1]), offset + 2, offset + 3,
        ));
        for pair in 0..fields.div_ceil(2) {
            let a = format!("deferred{i}[GEN ** {}]", 2 * pair);
            let b = if 2 * pair + 1 == fields {
                "0".into()
            } else {
                format!("deferred{i}[GEN ** {}]", 2 * pair + 1)
            };
            main.push_str(&format!(
                "    bc{kbc}_pack_pair(statement, {}, {a}, {b})\n",
                offset + 4 + 3 * pair
            ));
        }
        offset += 4 + 3 * fields.div_ceil(2);
    }
    main.push_str("    digest = StackBuf(2)\n    keccak_cells(statement, digest)\n    public = GEN ** 0\n    public[1] = digest[0]\n    public[GEN] = digest[1]\n    return\n");
    ast.funcs.extend(lean_compiler::parse(&main)?.funcs);
    Ok(ast)
}

pub fn compile(plan: [F192; 2], children: &[Child]) -> Result<Program, String> {
    Ok(lean_compiler::compile(&build_ast(plan, children)?))
}

pub fn statement_preimage(
    plan: [F192; 2],
    children: &[Child],
    public: &[[F192; 2]],
    points: &[Vec<F192>],
    values: &[F192],
) -> Result<Vec<u8>, String> {
    if children.len() < 2
        || children.len() > 8
        || public.len() != children.len()
        || points.len() != children.len()
        || values.len() != children.len()
    {
        return Err("one public input and deferred point/value per tree child required".into());
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&(children.len() as u128).to_le_bytes());
    let digest = |bytes: &mut Vec<u8>, value: F192| -> Result<(), String> {
        canonical(value)?;
        bytes.extend_from_slice(&value.c0.to_le_bytes());
        bytes.extend_from_slice(&value.c1.to_le_bytes());
        Ok(())
    };
    for value in plan {
        digest(&mut bytes, value)?;
    }
    for (((child, pi), point), value) in children.iter().zip(public).zip(points).zip(values) {
        let variables = child.kbc + leanvm_core::leaf::N_BYTECODE_SELECTORS;
        if point.len() != variables {
            return Err("incorrect deferred point dimension".into());
        }
        for value in child.seed.into_iter().chain(*pi) {
            digest(&mut bytes, value)?;
        }
        for value in point.iter().copied().chain(std::iter::once(*value)) {
            bytes.extend_from_slice(&value.c0.to_le_bytes());
            bytes.extend_from_slice(&value.c1.to_le_bytes());
            bytes.extend_from_slice(&value.c2.to_le_bytes());
        }
        if !(variables + 1).is_multiple_of(2) {
            bytes.extend_from_slice(&[0; 24]);
        }
    }
    Ok(bytes)
}

pub fn public_input(
    plan: [F192; 2],
    children: &[Child],
    public: &[[F192; 2]],
    points: &[Vec<F192>],
    values: &[F192],
) -> Result<[F192; 2], String> {
    Ok(halves(primitives::hash::hash(&statement_preimage(
        plan, children, public, points, values,
    )?)))
}

pub fn halves(bytes: [u8; 32]) -> [F192; 2] {
    let word = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
    [
        F192::new(word(0), word(8), 0),
        F192::new(word(16), word(24), 0),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heterogeneous_encoding_keeps_full_fields() {
        let children = [
            Child {
                kbc: 17,
                seed: [F192::ZERO; 2],
            },
            Child {
                kbc: 18,
                seed: [F192::ONE; 2],
            },
        ];
        let mut points = vec![vec![F192::ZERO; 21], vec![F192::ZERO; 22]];
        let values = [F192::new(1, 2, 3), F192::new(4, 5, 6)];
        let a = public_input(
            [F192::ZERO; 2],
            &children,
            &[[F192::ZERO; 2]; 2],
            &points,
            &values,
        )
        .unwrap();
        points[0][0].c2 = 7;
        let b = public_input(
            [F192::ZERO; 2],
            &children,
            &[[F192::ZERO; 2]; 2],
            &points,
            &values,
        )
        .unwrap();
        assert_ne!(a, b);
        points[1].pop();
        assert!(
            public_input(
                [F192::ZERO; 2],
                &children,
                &[[F192::ZERO; 2]; 2],
                &points,
                &values
            )
            .is_err()
        );
    }

    #[test]
    fn heterogeneous_verifier_compiles() {
        let children = [
            Child {
                kbc: 17,
                seed: [F192::ZERO; 2],
            },
            Child {
                kbc: 18,
                seed: [F192::ONE; 2],
            },
        ];
        let program = compile([F192::ZERO; 2], &children).unwrap();
        assert!(
            program
                .fn_ranges
                .iter()
                .any(|(name, _, _)| name == "bc17_verify_sub")
        );
        assert!(
            program
                .fn_ranges
                .iter()
                .any(|(name, _, _)| name == "bc18_verify_sub")
        );
    }

    #[test]
    fn actual_heterogeneous_main_matches_native_encoding() {
        let children = [
            Child {
                kbc: 17,
                seed: [F192::new(11, 13, 0); 2],
            },
            Child {
                kbc: 18,
                seed: [F192::new(17, 19, 0); 2],
            },
        ];
        let plan = [F192::new(23, 29, 0), F192::new(31, 37, 0)];
        let public = [
            [F192::new(41, 43, 0), F192::new(47, 53, 0)],
            [F192::new(59, 61, 0), F192::new(67, 71, 0)],
        ];
        let points: Vec<_> = children
            .iter()
            .map(|c| {
                (0..c.kbc + 4)
                    .map(|i| F192::new(i as u64 + 73, 79, 83))
                    .collect::<Vec<_>>()
            })
            .collect();
        let values = [F192::new(89, 97, 101), F192::new(103, 107, 109)];
        let expected = public_input(plan, &children, &public, &points, &values).unwrap();
        let mut ast = build_ast(plan, &children).unwrap();
        for child in &children {
            let fields = child.kbc + 5;
            let source = format!(
                "from snark_lib import *\n\ndef stub(a,b,c,d,logs,squares,deferred):\n    hint_witness(deferred[0:{fields}], \"test_deferred_{}\")\n    return\n",
                child.kbc
            );
            let stub = lean_compiler::parse(&source).unwrap().funcs.remove(0);
            let function = ast
                .funcs
                .iter_mut()
                .find(|f| f.name == format!("bc{}_verify_sub", child.kbc))
                .unwrap();
            function.params = stub.params;
            function.body = stub.body;
        }
        let mut program = lean_compiler::compile(&ast);
        program.set_witness("tree_child_pi", public.iter().map(|x| x.to_vec()).collect());
        for ((child, point), value) in children.iter().zip(&points).zip(values) {
            let mut fields = point.clone();
            fields.push(value);
            program.set_witness(format!("test_deferred_{}", child.kbc), vec![fields]);
        }
        let execution = program.execute(expected).unwrap();
        assert!(execution.unconstrained_reads.is_empty());
    }
}
