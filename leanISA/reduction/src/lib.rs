//! Guest-constrained reduction of leanISA recursive bytecode obligations.
pub mod pipeline;
pub mod receipt;
#[allow(dead_code)]
#[path = "../../src/recursion_guest.rs"]
pub mod recursion_guest;
#[allow(dead_code)]
#[path = "../../src/recursion_support.rs"]
pub mod recursion_support;
pub mod reduction;
pub mod wrapper;

#[cfg(test)]
#[path = "../guest/tests.rs"]
mod guest_tests;

#[cfg(test)]
#[path = "../review/proof_controls.rs"]
mod proof_controls;
