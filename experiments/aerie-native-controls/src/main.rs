//! Public-verifier controls over exactly the upstream benchmark corpus.
//! This is native Aerie evidence. No leanVM verifier or proof is implemented here.

use std::{error::Error, fs, path::PathBuf};

use aerie::falcon::{
    prove_aggregate, verify_aggregate, AggregationRecord, AggregationStatement, AggregationWitness,
    Falcon512, FalconAggregateSetup,
};
use aerie_falcon::wire::{HEADER_BYTES, HEADER_RECORDS_OFFSET};
use serde_json::{json, Map, Value};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let fixture = PathBuf::from(args.next().ok_or("expected fixture .bin")?);
    let out = PathBuf::from(args.next().ok_or("expected output directory")?);
    if args.next().is_some() {
        return Err("expected only fixture and output directory".into());
    }
    let encoded = fs::read(&fixture)?;
    if encoded.len() < 12 || &encoded[..4] != b"AHF1" {
        return Err("bad upstream fixture envelope".into());
    }
    let statement_len = usize::try_from(u64::from_le_bytes(encoded[4..12].try_into()?))?;
    let boundary = 12_usize
        .checked_add(statement_len)
        .ok_or("length overflow")?;
    if boundary > encoded.len() {
        return Err("truncated upstream fixture".into());
    }
    let statement = AggregationStatement::<Falcon512>::parse_canonical(&encoded[12..boundary])?;
    let witness = AggregationWitness::<Falcon512>::parse_canonical(&encoded[boundary..])?;
    if statement.len() < 2 || statement.len() != witness.signatures().len() {
        return Err("controls require at least two matching records".into());
    }
    let setup = FalconAggregateSetup::<Falcon512>::new(statement.len())?;
    let proof = prove_aggregate(&setup, &statement, &witness)?;
    verify_aggregate(setup.verifier(), &statement, &proof)?;
    let mut controls: Map<String, Value> = Map::new();

    let reject = |label: &str,
                  public: &AggregationStatement<Falcon512>,
                  wire: &[u8],
                  controls: &mut Map<String, Value>|
     -> Result<(), Box<dyn Error>> {
        let error = verify_aggregate(setup.verifier(), public, wire)
            .expect_err("the unchanged public verifier must reject the modified input");
        controls.insert(
            label.into(),
            json!({"rejected":true,"error":format!("{error}")}),
        );
        Ok(())
    };

    let mut changed_message = statement.messages()[0].clone();
    changed_message.push(1);
    let mut records = statement.to_records();
    records[0] = AggregationRecord::new(statement.public_keys()[0].clone(), changed_message)?;
    reject(
        "changed_message",
        &AggregationStatement::new(records)?,
        &proof,
        &mut controls,
    )?;

    let mut records = statement.to_records();
    records[0] = AggregationRecord::new(
        statement.public_keys()[1].clone(),
        statement.messages()[0].clone(),
    )?;
    reject(
        "changed_canonical_public_key",
        &AggregationStatement::new(records)?,
        &proof,
        &mut controls,
    )?;

    let mut records = statement.to_records();
    records.swap(0, 1);
    reject(
        "reordered_public_records",
        &AggregationStatement::new(records)?,
        &proof,
        &mut controls,
    )?;

    let mut changed_salt = proof.clone();
    changed_salt[HEADER_BYTES] ^= 1;
    reject(
        "changed_first_public_salt",
        &statement,
        &changed_salt,
        &mut controls,
    )?;

    let mut changed_proof = proof.clone();
    let last = changed_proof.len() - 1;
    changed_proof[last] ^= 1;
    reject(
        "changed_proof_body",
        &statement,
        &changed_proof,
        &mut controls,
    )?;

    reject(
        "truncated_proof",
        &statement,
        &proof[..proof.len() - 1],
        &mut controls,
    )?;
    let mut trailing = proof.clone();
    trailing.push(0);
    reject("trailing_proof_byte", &statement, &trailing, &mut controls)?;
    let mut wrong_count = proof.clone();
    wrong_count[HEADER_RECORDS_OFFSET..HEADER_BYTES]
        .copy_from_slice(&((statement.len() + 1) as u64).to_le_bytes());
    reject(
        "changed_live_record_count",
        &statement,
        &wrong_count,
        &mut controls,
    )?;

    fs::create_dir_all(&out)?;
    fs::write(out.join("statement.bin"), statement.canonical_encoding()?)?;
    fs::write(out.join("aggregate.aerie"), &proof)?;
    let report = json!({
        "schema_version":1,
        "kind":"native Aerie public-verifier control, not leanVM",
        "aerie_revision":"49b6c212c209286c536196f53618823ffdf0e899",
        "honest_positive_verified":true,
        "records":statement.len(),
        "padded_records":statement.len().next_power_of_two().max(8),
        "wire_bytes":proof.len(),
        "public_statement_bytes":statement.canonical_encoding()?.len(),
        "messages_lengths":statement.messages().iter().map(Vec::len).collect::<Vec<_>>(),
        "controls":controls,
        "fixture":fixture,
        "scope":"Mutation checks against unchanged verify_aggregate over intended canonical public keys and messages. They do not establish Aerie soundness or a leanVM port. No signing secret keys serialized."
    });
    fs::write(
        out.join("controls.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
