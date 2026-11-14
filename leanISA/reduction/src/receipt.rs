//! The complete production consumer: root STARK plus every final trusted-table evaluation.
use crate::wrapper::{self, Family, State};
use bincode::Options;
use leanvm_core::cpu::{self, Proof};
use primitives::field::F192;
use serde::{Deserialize, Serialize};
use std::time::Instant;

pub const MAGIC: [u8; 8] = *b"LIRDT001";
#[derive(Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub magic: [u8; 8],
    pub signatures: usize,
    pub slots: usize,
    pub depth: usize,
    pub policy: [F192; 2],
    pub leaf_seed: [F192; 2],
    pub root_seed: [F192; 2],
    pub state: State,
    pub proof: Proof,
}
fn wire() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(64 << 20)
}
pub fn encode(e: &Envelope) -> Result<Vec<u8>, String> {
    wire().serialize(e).map_err(|e| e.to_string())
}
pub fn decode(b: &[u8]) -> Result<Envelope, String> {
    wire().deserialize(b).map_err(|e| e.to_string())
}

pub struct Verifier<'a> {
    policy: [F192; 2],
    families: &'a [Family],
    semantic: [F192; 2],
    signatures: usize,
    slots: usize,
    bytecodes: Vec<verifier::Bytecode>,
}
#[derive(Clone, Serialize)]
pub struct Checked {
    pub root_pi_s: f64,
    pub root_core_s: f64,
    pub terminal_evaluation_s: f64,
    pub terminal_evaluations: usize,
}
impl<'a> Verifier<'a> {
    pub fn new(
        policy: [F192; 2],
        families: &'a [Family],
        semantic: [F192; 2],
        signatures: usize,
        slots: usize,
    ) -> Result<Self, String> {
        if families.len() < 2 || families.len() > 9 || slots != (1usize << (families.len() - 1)) {
            return Err("trusted tree shape".into());
        }
        wrapper::digest_bytes(&semantic)?;
        let bytecodes = families
            .iter()
            .map(|f| verifier::Bytecode::new(&f.table.iter().map(|x| x.0).collect::<Vec<_>>()))
            .collect();
        Ok(Self {
            policy,
            families,
            semantic,
            signatures,
            slots,
            bytecodes,
        })
    }
    pub fn verify(&self, e: &Envelope) -> Result<Checked, String> {
        let depth = self.families.len() - 1;
        if e.magic != MAGIC
            || e.depth != depth
            || e.signatures != self.signatures
            || e.slots != self.slots
            || e.policy != self.policy
            || e.leaf_seed != self.families[0].seed
            || e.root_seed != self.families[depth].seed
            || e.state.claim_digest != self.semantic
        {
            return Err("root differs from caller-trusted program/claims/shape".into());
        }
        let now = Instant::now();
        let pi = wrapper::state_input(self.policy, &self.families[..depth], &e.state)?;
        let root_pi_s = now.elapsed().as_secs_f64();
        let now = Instant::now();
        let summary = verifier::verify_execution(
            &self.bytecodes[depth],
            &cpu::public_input_bytes(&pi),
            &cpu::scalar_proof(&e.proof),
        )
        .map_err(|e| format!("root proof: {e:?}"))?;
        if summary.log_inv_rate != 1 {
            return Err("unexpected root commitment rate".into());
        }
        let root_core_s = now.elapsed().as_secs_f64();
        let now = Instant::now();
        for (j, a) in e.state.accumulators.iter().enumerate() {
            let point: Vec<_> = a.point.iter().map(cpu::to_scalar).collect();
            let got = cpu::from_scalar(
                self.bytecodes[j]
                    .evaluate(&point)
                    .map_err(|e| format!("terminal family {j}: {e:?}"))?,
            );
            if got != a.value {
                return Err(format!("terminal family {j} is false"));
            }
        }
        Ok(Checked {
            root_pi_s,
            root_core_s,
            terminal_evaluation_s: now.elapsed().as_secs_f64(),
            terminal_evaluations: depth,
        })
    }
}
