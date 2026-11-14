use std::{error::Error, fs, path::PathBuf, time::Instant};
use aerie_verifier::{AggregationStatement, Falcon512, FalconVerifierSetup, verify_aggregate};
use aerie_falcon::substrate::BaseField;
use akita_types::AkitaVerifierSetup;
use akita_serialization::{AkitaDeserialize, Compress, Validate};
use serde_json::json;

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf();
    let mut cases = Vec::new();
    for records in [1, 10, 30, 70, 100] {
        let frame_bytes = fs::read(root.join(format!("artifacts/aerie-wrapper/development/n{records}/sample-0/input.frame")))?;
        let frame = aerie_wrapper_format::decode(&frame_bytes).expect("canonical development frame");
        assert_eq!(frame.records, records);
        let statement = AggregationStatement::<Falcon512>::parse_canonical(frame.statement)?;
        let setup_bytes = fs::read(root.join(format!("artifacts/aerie-wrapper/public-setup/n{records}/setup.bin")))?;
        let start = Instant::now();
        let setup = AkitaVerifierSetup::<BaseField>::deserialize_exact_with_mode(&setup_bytes, Compress::Yes, Validate::No, &())?;
        let setup = FalconVerifierSetup::<Falcon512>::from_derived_setup(records, setup)?;
        let setup_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        verify_aggregate(&setup, &statement, frame.proof)?;
        let verify_s = start.elapsed().as_secs_f64();
        let mut changed_statement = frame.statement.to_vec();
        *changed_statement.last_mut().unwrap() ^= 1;
        let changed_statement = AggregationStatement::<Falcon512>::parse_canonical(&changed_statement)?;
        let changed_message_rejected = verify_aggregate(&setup, &changed_statement, frame.proof).is_err();
        let mut changed_proof = frame.proof.to_vec();
        *changed_proof.last_mut().unwrap() ^= 1;
        let changed_proof_rejected = verify_aggregate(&setup, &statement, &changed_proof).is_err();
        assert!(changed_message_rejected && changed_proof_rejected);
        cases.push(json!({"records":records,"native_verified":true,"changed_message_rejected":changed_message_rejected,
            "changed_proof_rejected":changed_proof_rejected,"selected_setup_import_prepare_s":setup_s,"native_verify_s":verify_s}));
    }
    let report = json!({"scope":"Selected-schedule constructor interoperability with original native development proofs. Full verifier unchanged; not an outer proof.", "all_passed":true,"cases":cases});
    let output = root.join("results/aerie-wrapper/selected-schedule-native.json");
    fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", output.display());
    Ok(())
}
