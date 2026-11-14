//! Witness construction is not a trust boundary: the DSL verifies its inputs.
use crate::{
    recursion_support::{self, PreparedChild},
    reduction::{self, Claim},
    wrapper::{self, Family, State},
};
use leanvm_core::cpu::Proof;
use primitives::field::F192;
use std::{collections::BTreeMap, time::Instant};

pub type Streams = BTreeMap<String, Vec<Vec<F192>>>;
pub struct PreparedMerge {
    pub state: State,
    pub public_input: [F192; 2],
    pub streams: Streams,
    pub reduction_prove_s: f64,
}
fn append(to: &mut Streams, from: Streams) {
    for (name, rows) in from {
        to.entry(name).or_default().extend(rows);
    }
}

/// Construct the witness from ordinary checked children. The proof verifier in
/// the DSL still checks them again; this native precheck is only admission.
pub fn prepare(
    policy: [F192; 2],
    families: &[Family],
    states: &[State],
    proofs: &[Proof],
) -> Result<PreparedMerge, String> {
    if families.is_empty() || states.len() != 2 || proofs.len() != 2 {
        return Err("binary merge inputs".into());
    }
    let child = families.last().unwrap();
    let prior = &families[..families.len() - 1];
    let prepared = states
        .iter()
        .zip(proofs)
        .map(|(s, p)| {
            let pi = wrapper::state_input(policy, prior, s)?;
            recursion_support::child_witness(&child.program, pi, p)
        })
        .collect::<Result<Vec<_>, String>>()?;
    compose(policy, families, states, prepared)
}

/// Assemble arbitrary prover advice. It can contain false table claims: only
/// the constrained reduction AND the final consumer's trusted evaluations
/// establish their truth. Exposing this builder does not grant verifier trust.
pub fn compose(
    policy: [F192; 2],
    families: &[Family],
    states: &[State],
    prepared: Vec<PreparedChild>,
) -> Result<PreparedMerge, String> {
    if families.is_empty() || states.len() != 2 || prepared.len() != 2 {
        return Err("binary composition inputs".into());
    }
    let prior = &families[..families.len() - 1];
    let child_pi = states
        .iter()
        .map(|s| wrapper::state_input(policy, prior, s))
        .collect::<Result<Vec<_>, _>>()?;
    for (p, pi) in prepared.iter().zip(&child_pi) {
        if p.public_input != *pi {
            return Err("prepared child PI mismatch".into());
        }
    }
    let claim_digest =
        wrapper::claim_digest(&states.iter().map(|s| s.claim_digest).collect::<Vec<_>>())?;
    let context = wrapper::context(policy, families.len(), claim_digest, &child_pi)?;
    let mut streams: Streams = BTreeMap::new();
    let mut fresh = Vec::new();
    for p in prepared {
        fresh.push(Claim {
            point: p.bytecode_point,
            value: p.bytecode_value,
        });
        append(&mut streams, p.streams);
    }
    streams.insert(
        "reduced_child_state".into(),
        states.iter().map(wrapper::state_fields).collect(),
    );
    let mut accumulators = Vec::new();
    let mut reduction_prove_s = 0.;
    for (j, family) in families.iter().enumerate() {
        let claims = if j + 1 == families.len() {
            fresh.clone()
        } else {
            states
                .iter()
                .map(|s| {
                    let a = &s.accumulators[j];
                    Claim {
                        point: a.point.clone(),
                        value: a.value,
                    }
                })
                .collect()
        };
        let now = Instant::now();
        let witness = reduction::prove(&family.table, family.seed, context, &claims)?;
        reduction_prove_s += now.elapsed().as_secs_f64();
        append(&mut streams, witness.streams());
        accumulators.push(witness.reduced);
    }
    let state = State {
        claim_digest,
        accumulators,
    };
    let public_input = wrapper::state_input(policy, families, &state)?;
    Ok(PreparedMerge {
        state,
        public_input,
        streams,
        reduction_prove_s,
    })
}
