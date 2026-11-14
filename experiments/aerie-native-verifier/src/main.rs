//! A separate verifier-only consumer of public statement bytes and Aerie wire bytes.
//! No signer, witness or Aerie prover capability is linked by this crate.

use std::{error::Error, fs, path::PathBuf, time::Instant};

use aerie_verifier::{verify_aggregate, AggregationStatement, Falcon512, FalconVerifierSetup};
use serde_json::json;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let public_file = PathBuf::from(args.next().ok_or("expected public statement path")?);
    let proof_file = PathBuf::from(args.next().ok_or("expected Aerie proof path")?);
    let report_file = PathBuf::from(args.next().ok_or("expected report path")?);
    if args.next().is_some() {
        return Err("expected public statement, proof and report paths".into());
    }
    let public_bytes = fs::read(&public_file)?;
    let proof = fs::read(&proof_file)?;
    let start = Instant::now();
    let statement = AggregationStatement::<Falcon512>::parse_canonical(&public_bytes)?;
    let public_parse_s = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let setup = FalconVerifierSetup::<Falcon512>::new(statement.len())?;
    let verifier_setup_s = start.elapsed().as_secs_f64();
    let start = Instant::now();
    verify_aggregate(&setup, &statement, &proof)?;
    let verify_s = start.elapsed().as_secs_f64();
    let report = json!({"kind":"fresh native verifier-only Aerie consumer, not leanVM",
        "verified":true,"records":statement.len(),"wire_bytes":proof.len(),
        "public_statement_bytes":public_bytes.len(),"public_parse_s":public_parse_s,
        "verifier_setup_s":verifier_setup_s,"verify_s":verify_s,
        "timing_scope":"One correctness demonstration, not a benchmark curve; excludes file I/O. Scalar dependency profile, no signer/witness/prover/Rayon dependency.",
        "aerie_revision":"49b6c212c209286c536196f53618823ffdf0e899",
        "public_file":public_file,"proof_file":proof_file});
    if let Some(parent) = report_file.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(report_file, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
