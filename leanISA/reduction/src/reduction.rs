//! Fiat-Shamir sumcheck reduction of bytecode evaluations for one trusted table.
//!
//! A valid link proof reduces every input `P(q_i) = v_i` to `P(r) = u`.
//! `verify_link` checks only that implication. The final receiver MUST also
//! evaluate its trusted table at `r` with `check_terminal`, or include the
//! reduced claim in a further proved reduction that eventually does so.

use std::collections::BTreeMap;

use primitives::field::{F64, F192, F192Unreduced};
use primitives::multilinear::{eq_eval, eq_table, mle_eval_par};
use serde::{Deserialize, Serialize};

pub const INSTANCE_DOMAIN: &[u8; 16] = b"pq-red-inst/v1\0\0";
pub const ROUND_DOMAIN: &[u8; 16] = b"pq-red-round/v1\0";
pub const MAX_VARIABLES: usize = 32;
pub const MAX_CLAIMS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// LSB-first multilinear coordinates, every full 192-bit field element.
    pub point: Vec<F192>,
    pub value: F192,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Round {
    pub c0: F192,
    pub c2: F192,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reduced {
    pub point: Vec<F192>,
    pub value: F192,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReductionWitness {
    pub rounds: Vec<Round>,
    pub reduced: Reduced,
}

impl ReductionWitness {
    /// One entry for each call of the Python reduction verifier. Callers append
    /// entries in the same fixed family order as the generated guest.
    pub fn streams(&self) -> BTreeMap<String, Vec<Vec<F192>>> {
        BTreeMap::from([
            (
                "reduce_rounds".into(),
                vec![self.rounds.iter().flat_map(|r| [r.c0, r.c2]).collect()],
            ),
            ("reduce_value".into(), vec![vec![self.reduced.value]]),
        ])
    }
}

fn dimensions(claims: &[Claim]) -> Result<usize, String> {
    if !(1..=MAX_CLAIMS).contains(&claims.len()) {
        return Err(format!("reduction needs 1..={MAX_CLAIMS} claims"));
    }
    let n = claims[0].point.len();
    if !(1..=MAX_VARIABLES).contains(&n) || claims.iter().any(|c| c.point.len() != n) {
        return Err("reduction claims have inconsistent or unsupported dimensions".into());
    }
    Ok(n)
}

fn append_canonical(bytes: &mut Vec<u8>, words: [F192; 2]) -> Result<(), String> {
    for word in words {
        if word.c2 != 0 {
            return Err("program identity and context must be canonical 256-bit digests".into());
        }
        bytes.extend(word.c0.to_le_bytes());
        bytes.extend(word.c1.to_le_bytes());
    }
    Ok(())
}

pub fn append_field(bytes: &mut Vec<u8>, value: F192) {
    bytes.extend(value.c0.to_le_bytes());
    bytes.extend(value.c1.to_le_bytes());
    bytes.extend(value.c2.to_le_bytes());
}

pub fn digest(bytes: &[u8]) -> [F192; 2] {
    let bytes = primitives::hash::hash(bytes);
    let word = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
    [
        F192::new(word(0), word(8), 0),
        F192::new(word(16), word(24), 0),
    ]
}

/// The exact initial Keccak preimage the DSL verifier constructs. Full fields
/// are flattened globally, then padded by ONE zero field if their count is odd.
/// Thus each pair is exactly the old `pack_pair`'s three canonical 128-bit cells.
pub fn instance_preimage(
    program: [F192; 2],
    context: [F192; 2],
    claims: &[Claim],
) -> Result<Vec<u8>, String> {
    let n = dimensions(claims)?;
    let mut bytes = Vec::with_capacity(112 + 24 * (claims.len() * (n + 1) + 1));
    bytes.extend(INSTANCE_DOMAIN);
    bytes.extend((n as u128).to_le_bytes());
    bytes.extend((claims.len() as u128).to_le_bytes());
    append_canonical(&mut bytes, program)?;
    append_canonical(&mut bytes, context)?;
    for claim in claims {
        for &coordinate in &claim.point {
            append_field(&mut bytes, coordinate);
        }
        append_field(&mut bytes, claim.value);
    }
    if !(claims.len() * (n + 1)).is_multiple_of(2) {
        append_field(&mut bytes, F192::ZERO);
    }
    Ok(bytes)
}

pub fn initial_state(
    program: [F192; 2],
    context: [F192; 2],
    claims: &[Claim],
) -> Result<[F192; 2], String> {
    Ok(digest(&instance_preimage(program, context, claims)?))
}

/// First 192 bits of the canonical Keccak-256 output. This is the DSL helper
/// `challenge_from_state`: state[0] + y^2 * state[1].c0.
pub fn challenge(state: [F192; 2]) -> F192 {
    debug_assert!(state.iter().all(|s| s.c2 == 0));
    F192::new(state[0].c0, state[0].c1, state[1].c0)
}

pub fn round_state(state: [F192; 2], index: usize, round: Round) -> [F192; 2] {
    let mut bytes = Vec::with_capacity(112);
    bytes.extend(ROUND_DOMAIN);
    bytes.extend((index as u128).to_le_bytes());
    append_canonical(&mut bytes, state).expect("hash state is canonical");
    append_field(&mut bytes, round.c0);
    append_field(&mut bytes, round.c2);
    debug_assert_eq!(bytes.len(), 112);
    digest(&bytes)
}

fn powers(theta: F192, m: usize) -> Vec<F192> {
    let mut next = F192::ONE;
    (0..m)
        .map(|_| {
            let result = next;
            next *= theta;
            result
        })
        .collect()
}

fn original_target(claims: &[Claim], weights: &[F192]) -> F192 {
    claims
        .iter()
        .zip(weights)
        .fold(F192::ZERO, |sum, (c, &w)| sum + w * c.value)
}

fn advance(target: F192, round: Round, r: F192) -> F192 {
    // Characteristic two: g(0)+g(1)=c1+c2=target, hence c1=target+c2.
    round.c0 + r * (target + round.c2) + (r * r) * round.c2
}

/// Make a real sumcheck proof from the trusted `K`-valued bytecode table.
/// Honest input claims are checked here for clear errors; this producer-side
/// check is not a substitute for guest reduction or native terminal checking.
pub fn prove(
    table: &[F64],
    program: [F192; 2],
    context: [F192; 2],
    claims: &[Claim],
) -> Result<ReductionWitness, String> {
    let n = dimensions(claims)?;
    if table.len() != 1usize << n {
        return Err("bytecode table length differs from claim dimension".into());
    }
    for (i, c) in claims.iter().enumerate() {
        if mle_eval_par(table, &c.point) != c.value {
            return Err(format!("false original bytecode claim {i}"));
        }
    }
    let mut state = initial_state(program, context, claims)?;
    let weights = powers(challenge(state), claims.len());
    let mut target = original_target(claims, &weights);
    let mut p: Vec<_> = table.iter().copied().map(F192::from).collect();
    let mut w = vec![F192::ZERO; table.len()];
    for (claim, &weight) in claims.iter().zip(&weights) {
        let equality = eq_table(&claim.point);
        for (out, &e) in w.iter_mut().zip(&equality) {
            *out += weight * e;
        }
    }
    let mut point = Vec::with_capacity(n);
    let mut rounds = Vec::with_capacity(n);
    for index in 0..n {
        let mut c0 = F192Unreduced::ZERO;
        let mut c2 = F192Unreduced::ZERO;
        let half = p.len() / 2;
        for i in 0..half {
            let (p0, p1) = (p[2 * i], p[2 * i + 1]);
            let (w0, w1) = (w[2 * i], w[2 * i + 1]);
            c0 ^= w0.mul_unreduced(p0);
            c2 ^= (w0 + w1).mul_unreduced(p0 + p1);
        }
        let round = Round {
            c0: c0.reduce(),
            c2: c2.reduce(),
        };
        state = round_state(state, index, round);
        let r = challenge(state);
        target = advance(target, round, r);
        // In-place folding is deliberately sequential: parallel writes to the
        // lower half could race another task's not-yet-read source pair.
        for i in 0..half {
            p[i] = p[2 * i] + r * (p[2 * i] + p[2 * i + 1]);
            w[i] = w[2 * i] + r * (w[2 * i] + w[2 * i + 1]);
        }
        p.truncate(half);
        w.truncate(half);
        point.push(r);
        rounds.push(round);
    }
    if target != w[0] * p[0] {
        return Err("honest sumcheck terminal identity failed".into());
    }
    let proof = ReductionWitness {
        rounds,
        reduced: Reduced { point, value: p[0] },
    };
    verify_link(program, context, claims, &proof)?;
    check_terminal(table, &proof.reduced)?;
    Ok(proof)
}

/// Check only the proved reduction implication. This deliberately does NOT
/// establish that the original claims are true without eventual exact checking
/// of the resulting `Reduced` against its approved program table.
pub fn verify_link(
    program: [F192; 2],
    context: [F192; 2],
    claims: &[Claim],
    proof: &ReductionWitness,
) -> Result<(), String> {
    let n = dimensions(claims)?;
    if proof.rounds.len() != n || proof.reduced.point.len() != n {
        return Err("wrong number of sumcheck rounds or output coordinates".into());
    }
    let mut state = initial_state(program, context, claims)?;
    let weights = powers(challenge(state), claims.len());
    let mut target = original_target(claims, &weights);
    let mut derived = Vec::with_capacity(n);
    for (index, &round) in proof.rounds.iter().enumerate() {
        state = round_state(state, index, round);
        let r = challenge(state);
        target = advance(target, round, r);
        derived.push(r);
    }
    if proof.reduced.point != derived {
        return Err("reduced point differs from Fiat-Shamir challenges".into());
    }
    let final_weight = claims
        .iter()
        .zip(&weights)
        .fold(F192::ZERO, |sum, (claim, &w)| {
            sum + w * eq_eval(&claim.point, &derived)
        });
    if target != final_weight * proof.reduced.value {
        return Err("sumcheck terminal linking identity failed".into());
    }
    Ok(())
}

pub fn check_terminal(table: &[F64], reduced: &Reduced) -> Result<(), String> {
    if !(1..=MAX_VARIABLES).contains(&reduced.point.len())
        || table.len() != 1usize << reduced.point.len()
    {
        return Err("terminal bytecode table/point dimension mismatch".into());
    }
    if mle_eval_par(table, &reduced.point) != reduced.value {
        return Err("false reduced bytecode evaluation".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oracle(table: &[F64], point: &[F192]) -> F192 {
        table
            .iter()
            .enumerate()
            .fold(F192::ZERO, |sum, (index, &v)| {
                let weight = point.iter().enumerate().fold(F192::ONE, |p, (j, &r)| {
                    p * if index >> j & 1 == 0 {
                        F192::ONE + r
                    } else {
                        r
                    }
                });
                sum + weight.mul_base(v)
            })
    }

    fn fixture(n: usize, m: usize) -> (Vec<F64>, [F192; 2], [F192; 2], Vec<Claim>) {
        let table: Vec<_> = (0..1 << n)
            .map(|i| F64((i as u64).wrapping_mul(0x1234_5678_9abc_def1)))
            .collect();
        let claims = (0..m)
            .map(|i| {
                let point: Vec<_> = (0..n)
                    .map(|j| {
                        F192::new(
                            (i + j + 1) as u64,
                            (11 * i + j + 7) as u64,
                            (i + 17 * j + 5) as u64,
                        )
                    })
                    .collect();
                Claim {
                    value: oracle(&table, &point),
                    point,
                }
            })
            .collect();
        (
            table,
            [F192::new(1, 2, 0), F192::new(3, 4, 0)],
            [F192::new(5, 6, 0), F192::new(7, 8, 0)],
            claims,
        )
    }

    #[test]
    fn real_sumchecks_match_independent_boolean_weight_oracle() {
        for n in [1, 2, 3, 6, 9] {
            for m in [1, 2, 3, 8] {
                let (table, program, context, claims) = fixture(n, m);
                let proof = prove(&table, program, context, &claims).unwrap();
                verify_link(program, context, &claims, &proof).unwrap();
                assert_eq!(proof.reduced.value, oracle(&table, &proof.reduced.point));
                check_terminal(&table, &proof.reduced).unwrap();
            }
        }
    }

    #[test]
    fn transcript_binds_full_limbs_order_and_context() {
        let (_, program, context, claims) = fixture(4, 3);
        let original = initial_state(program, context, &claims).unwrap();
        let mut changed = claims.clone();
        changed[0].point[0].c2 ^= 1;
        assert_ne!(original, initial_state(program, context, &changed).unwrap());
        let mut changed = claims.clone();
        changed[0].value.c2 ^= 1;
        assert_ne!(original, initial_state(program, context, &changed).unwrap());
        let mut changed = claims.clone();
        changed.swap(0, 1);
        assert_ne!(original, initial_state(program, context, &changed).unwrap());
        let mut changed_context = context;
        changed_context[1].c1 ^= 1;
        assert_ne!(
            original,
            initial_state(program, changed_context, &claims).unwrap()
        );
        let mut changed_program = program;
        changed_program[0].c0 ^= 1;
        assert_ne!(
            original,
            initial_state(changed_program, context, &claims).unwrap()
        );
    }

    #[test]
    fn malformed_and_changed_link_proofs_are_refused() {
        let (table, program, context, claims) = fixture(5, 4);
        let original = prove(&table, program, context, &claims).unwrap();
        let mut changed = original.clone();
        changed.rounds[0].c0 += F192::ONE;
        assert!(verify_link(program, context, &claims, &changed).is_err());
        let mut changed = original.clone();
        changed.reduced.value += F192::ONE;
        assert!(verify_link(program, context, &claims, &changed).is_err());
        assert!(check_terminal(&table, &changed.reduced).is_err());
        let mut changed = original.clone();
        changed.reduced.point[0].c2 ^= 1;
        assert!(verify_link(program, context, &claims, &changed).is_err());
        let mut changed = original.clone();
        changed.rounds.pop();
        assert!(verify_link(program, context, &claims, &changed).is_err());
        let mut changed = claims.clone();
        changed[0].value += F192::ONE;
        assert!(prove(&table, program, context, &changed).is_err());
        assert!(verify_link(program, context, &changed, &original).is_err());
    }

    #[test]
    fn global_odd_padding_and_round_domains_are_exact() {
        let (_, program, context, claims) = fixture(2, 3);
        let bytes = instance_preimage(program, context, &claims).unwrap();
        assert_eq!(bytes.len(), 112 + 24 * 10);
        assert_eq!(&bytes[..16], INSTANCE_DOMAIN);
        assert_eq!(&bytes[bytes.len() - 24..], &[0; 24]);
        let mut bad_program = program;
        bad_program[0].c2 = 1;
        assert!(initial_state(bad_program, context, &claims).is_err());
        let round = Round {
            c0: F192::new(1, 2, 3),
            c2: F192::new(4, 5, 6),
        };
        assert_ne!(
            round_state(digest(&bytes), 0, round),
            round_state(digest(&bytes), 1, round)
        );
    }

    #[test]
    fn exact_transcripts_match_independent_python_field_and_keccak_oracle() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../review/oracle-vectors.json")).unwrap();
        let scalar = |v: &serde_json::Value| {
            F192::new(
                v[0].as_u64().unwrap(),
                v[1].as_u64().unwrap(),
                v[2].as_u64().unwrap(),
            )
        };
        let hash_words = |text: &str| {
            let bytes: Vec<_> = (0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect();
            let w = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
            [F192::new(w(0), w(8), 0), F192::new(w(16), w(24), 0)]
        };
        for case in vectors["vectors"].as_array().unwrap() {
            let table: Vec<_> = case["table"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    let s = scalar(v);
                    assert_eq!((s.c1, s.c2), (0, 0));
                    F64(s.c0)
                })
                .collect();
            let claims: Vec<_> = case["points"]
                .as_array()
                .unwrap()
                .iter()
                .zip(case["values"].as_array().unwrap())
                .map(|(p, v)| Claim {
                    point: p.as_array().unwrap().iter().map(scalar).collect(),
                    value: scalar(v),
                })
                .collect();
            let program = hash_words(case["poly_id_hex"].as_str().unwrap());
            let context = hash_words(case["context_hex"].as_str().unwrap());
            assert_eq!(
                initial_state(program, context, &claims).unwrap(),
                hash_words(case["instance_digest_hex"].as_str().unwrap())
            );
            let made = prove(&table, program, context, &claims).unwrap();
            let expected_rounds: Vec<_> = case["rounds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| Round {
                    c0: scalar(&r[0]),
                    c2: scalar(&r[1]),
                })
                .collect();
            let expected_point: Vec<_> = case["new_point"]
                .as_array()
                .unwrap()
                .iter()
                .map(scalar)
                .collect();
            assert_eq!(made.rounds, expected_rounds);
            assert_eq!(made.reduced.point, expected_point);
            assert_eq!(made.reduced.value, scalar(&case["new_value"]));
        }
    }
}
