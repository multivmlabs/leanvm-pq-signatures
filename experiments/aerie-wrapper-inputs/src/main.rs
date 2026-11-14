//! Native Aerie producer for a complete-verifier guest.
//! Inputs contain an Aerie proof, not Falcon signature witnesses or host verdicts.
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use aerie::falcon::{
    prove_aggregate, verify_aggregate, AggregationRecord, AggregationStatement, AggregationWitness,
    CanonicalPublicKeyBytes, Falcon512, FalconAggregateSetup,
};
use aerie_falcon::wire::HEADER_BYTES as AERIE_HEADER_BYTES;
use aerie_wrapper_format::{claim_digest, decode, encode, PROFILE};
use akita_serialization::{AkitaDeserialize, AkitaSerialize, Compress, Validate};
use akita_types::{prepared_verifier_ntt_cache_metadata, AkitaVerifierSetup};
use akita_verifier::build_riscv64_terminal_ntt_cache;
use serde_json::{json, Value};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn save_json(path: impl AsRef<Path>, value: &Value) -> Result<(), Box<dyn Error>> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn median(values: &[f64]) -> f64 {
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    if values.len() % 2 == 0 {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.0
    } else {
        values[values.len() / 2]
    }
}

/// Export public setup and derived terminal transforms for immutable ELF data.
/// These bytes are not witnesses and must not be accepted from a prover without
/// an independent code/installation binding. No signatures or proof generation.
fn export_setup(records: usize, out: &Path) -> Result<(), Box<dyn Error>> {
    use aerie_falcon::pcs::verifier_group_profiles_of;
    use aerie_falcon::{FalconDegree, FalconVerifierSetup};
    fs::create_dir_all(out)?;
    let start = Instant::now();
    let verifier = FalconVerifierSetup::<Falcon512>::new(records)?;
    let derive_s = start.elapsed().as_secs_f64();
    let setup = verifier.akita().setup();
    assert!(setup.prefix_slots().is_empty());
    let descriptor = setup.expanded().descriptor();
    let mut encoded = Vec::new();
    setup.serialize_compressed(&mut encoded)?;
    assert_eq!(encoded.len(), setup.serialized_size(Compress::Yes));
    let start = Instant::now();
    let decoded =
        AkitaVerifierSetup::<aerie_falcon::substrate::BaseField>::deserialize_compressed_exact(
            &encoded,
            &(),
        )?;
    let validation_s = start.elapsed().as_secs_f64();
    assert_eq!(&decoded, setup);
    let (_, _, selection) = verifier_group_profiles_of(FalconDegree::Falcon512, records)?;
    let row = verifier.akita().schedules().resolve_selection(selection)?;
    let start = Instant::now();
    let cache_result =
        build_riscv64_terminal_ntt_cache(setup, row.schedule(), selection.row_digest);
    let cache_build_s = start.elapsed().as_secs_f64();
    fs::write(out.join("setup.bin"), &encoded)?;
    let mut metadata = json!({"schema_version":1,"kind":"trusted public setup export, not a proof",
        "records":records,"padded_records":records.next_power_of_two().max(8),
        "aerie_revision":"49b6c212c209286c536196f53618823ffdf0e899",
        "akita_revision":"e023b6a46143f7b23199ccecb2684192baf7b640",
        "setup_bytes":encoded.len(),"setup_expected_bytes":106+8*descriptor.num_field_elements,
        "max_num_vars":descriptor.max_num_vars,"max_num_batched_polys":descriptor.max_num_batched_polys,
        "matrix_field_elements":descriptor.num_field_elements,"setup_seed_hex":hex(&descriptor.setup_seed.seed),
        "validated_exact_roundtrip":true,"empty_prefix_registry":true,
        "setup_derivation_s":derive_s,"setup_roundtrip_validation_s":validation_s,"terminal_cache_build_s":cache_build_s,
        "schedule_row_digest_hex":hex(selection.row_digest.as_bytes()),
        "trust_boundary":"Derived natively from fixed setup seed and catalog; validated against original setup before export. Only sound to skip guest re-expansion when bytes are immutable trusted ELF data or independently authenticated."});
    match cache_result {
        Ok(cache) => {
            let cache_meta = prepared_verifier_ntt_cache_metadata(&cache)?;
            assert_eq!(cache_meta.binding.schedule_row_digest, selection.row_digest);
            assert_eq!(
                cache_meta.binding.setup_field_elements,
                descriptor.num_field_elements
            );
            fs::write(out.join("terminal-cache.bin"), &cache)?;
            metadata["terminal_cache_supported"] = json!(true);
            metadata["terminal_cache_bytes"] = json!(cache.len());
            metadata["terminal_cache_ring_dimension"] = json!(cache_meta.ring_dimension);
            metadata["terminal_cache_base_prefix_len"] = json!(cache_meta.base_prefix_len);
            metadata["terminal_cache_tail_prefix_len"] = json!(cache_meta.tail_prefix_len);
            metadata["terminal_cache_width"] = json!(cache_meta.width);
            metadata["terminal_cache_rhs_abs_bound"] = json!(cache_meta.rhs_abs_bound);
            metadata["setup_seed_digest_hex"] = json!(hex(&cache_meta.binding.setup_seed_digest));
        }
        Err(error) => {
            metadata["terminal_cache_supported"] = json!(false);
            metadata["terminal_cache_error"] = json!(error.to_string());
            let cache_path = out.join("terminal-cache.bin");
            if cache_path.exists() {
                fs::remove_file(cache_path)?;
            }
        }
    }
    assert_eq!(metadata["setup_bytes"], metadata["setup_expected_bytes"]);
    save_json(out.join("metadata.json"), &metadata)?;
    println!("{}", serde_json::to_string_pretty(&metadata)?);
    Ok(())
}

/// Correctness check for importing the already validated public setup that
/// will be immutable ELF data. This is not a generic untrusted setup loader.
fn verify_imported_setup(
    records: usize,
    setup_file: &Path,
    statement_file: &Path,
    proof_file: &Path,
    report_file: &Path,
) -> Result<(), Box<dyn Error>> {
    use aerie_falcon::FalconVerifierSetup;
    let encoded = fs::read(setup_file)?;
    let statement_bytes = fs::read(statement_file)?;
    let proof = fs::read(proof_file)?;
    let statement = AggregationStatement::<Falcon512>::parse_canonical(&statement_bytes)?;
    if statement.len() != records {
        return Err("import-check statement count mismatch".into());
    }
    let start = Instant::now();
    let imported =
        AkitaVerifierSetup::<aerie_falcon::substrate::BaseField>::deserialize_exact_with_mode(
            &encoded,
            Compress::Yes,
            Validate::No,
            &(),
        )?;
    let descriptor = imported.expanded().descriptor();
    let fields = descriptor.num_field_elements;
    let max_vars = descriptor.max_num_vars;
    assert!(imported.prefix_slots().is_empty());
    let setup = FalconVerifierSetup::<Falcon512>::from_derived_setup(records, imported)?;
    let import_s = start.elapsed().as_secs_f64();
    let start = Instant::now();
    verify_aggregate(&setup, &statement, &proof)?;
    let verify_s = start.elapsed().as_secs_f64();
    let report = json!({"schema_version":1,"kind":"native interoperability check for immutable public setup import",
        "verified":true,"records":records,"setup_bytes":encoded.len(),"matrix_field_elements":fields,
        "max_num_vars":max_vars,"empty_prefix_registry":true,"deserialize_compression":"Yes",
        "deserialize_validation":"No: only for source-hash-bound previously native-validated public setup",
        "import_and_verifier_prepare_s":import_s,"native_verify_s":verify_s,
        "setup_file":setup_file,"statement_file":statement_file,"proof_file":proof_file,
        "claim_digest_hex":hex(&claim_digest(records,&statement_bytes)),
        "scope":"No proof generation. Full unchanged verify_aggregate runs after setup import; this does not establish an outer leanVM proof."});
    if let Some(parent) = report_file.parent() {
        fs::create_dir_all(parent)?;
    }
    save_json(report_file, &report)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn fixture(
    path: &Path,
) -> Result<
    (
        AggregationStatement<Falcon512>,
        AggregationWitness<Falcon512>,
    ),
    Box<dyn Error>,
> {
    let bytes = fs::read(path)?;
    if bytes.len() < 12 || &bytes[..4] != b"AHF1" {
        return Err("invalid pinned native fixture".into());
    }
    let len = usize::try_from(u64::from_le_bytes(bytes[4..12].try_into()?))?;
    let split = 12usize.checked_add(len).ok_or("fixture length overflow")?;
    if split > bytes.len() {
        return Err("truncated fixture".into());
    }
    let statement = AggregationStatement::<Falcon512>::parse_canonical(&bytes[12..split])?;
    let witness = AggregationWitness::<Falcon512>::parse_canonical(&bytes[split..])?;
    if statement.len() != witness.signatures().len() {
        return Err("fixture signature count differs".into());
    }
    Ok((statement, witness))
}

fn reject_case(
    out: &Path,
    label: &str,
    setup: &FalconAggregateSetup<Falcon512>,
    statement: &AggregationStatement<Falcon512>,
    proof: &[u8],
) -> Result<Value, Box<dyn Error>> {
    let error = verify_aggregate(setup.verifier(), statement, proof)
        .expect_err("negative control must fail unchanged native verification");
    let public = statement.canonical_encoding()?;
    let bytes =
        encode(statement.len(), &public, proof).map_err(|e| format!("encode {label}: {e:?}"))?;
    fs::write(out.join(format!("{label}.frame")), &bytes)?;
    Ok(
        json!({"name":label,"path":format!("controls/{label}.frame"),
        "expected_guest_accept":false,"native_rejected":true,"native_error":error.to_string(),
        "claim_digest_hex":hex(&claim_digest(statement.len(),&public))}),
    )
}

fn controls(
    out: &Path,
    setup: &FalconAggregateSetup<Falcon512>,
    statement: &AggregationStatement<Falcon512>,
    witness: &AggregationWitness<Falcon512>,
    proof: &[u8],
) -> Result<Value, Box<dyn Error>> {
    fs::create_dir_all(out)?;
    let mut cases = Vec::new();
    let mut records = statement.to_records();
    let mut message = statement.messages()[0].clone();
    message.push(1);
    records[0] = AggregationRecord::new(statement.public_keys()[0].clone(), message)?;
    cases.push(reject_case(
        out,
        "changed-message",
        setup,
        &AggregationStatement::new(records)?,
        proof,
    )?);
    let replacement = if statement.len() > 1 {
        statement.public_keys()[1].clone()
    } else {
        let mut key = vec![0; 897];
        key[0] = 9;
        CanonicalPublicKeyBytes::<Falcon512>::parse(&key)?
    };
    assert_ne!(&replacement, &statement.public_keys()[0]);
    let mut records = statement.to_records();
    records[0] = AggregationRecord::new(replacement, statement.messages()[0].clone())?;
    cases.push(reject_case(
        out,
        "changed-key",
        setup,
        &AggregationStatement::new(records)?,
        proof,
    )?);
    let mut salt = proof.to_vec();
    salt[AERIE_HEADER_BYTES] ^= 1;
    cases.push(reject_case(out, "changed-salt", setup, statement, &salt)?);
    let mut body = proof.to_vec();
    let last = body.len() - 1;
    body[last] ^= 1;
    cases.push(reject_case(out, "changed-proof", setup, statement, &body)?);
    cases.push(reject_case(
        out,
        "truncated-aerie-proof",
        setup,
        statement,
        &proof[..proof.len() - 1],
    )?);
    let mut trailer = proof.to_vec();
    trailer.push(0);
    cases.push(reject_case(
        out,
        "trailing-aerie-byte",
        setup,
        statement,
        &trailer,
    )?);

    let canonical = statement.canonical_encoding()?;
    let positive = encode(statement.len(), &canonical, proof)
        .map_err(|e| format!("positive encoding: {e:?}"))?;
    for (label, mut bytes) in [
        ("trailing-frame-byte", positive.clone()),
        ("truncated-frame", positive.clone()),
        ("oversized-statement-header", positive.clone()),
    ] {
        match label {
            "trailing-frame-byte" => bytes.push(0),
            "truncated-frame" => {
                bytes.pop();
            }
            _ => bytes[16..24].copy_from_slice(&u64::MAX.to_le_bytes()),
        }
        let error = decode(&bytes).expect_err("negative framing control must fail exact parser");
        fs::write(out.join(format!("{label}.frame")), bytes)?;
        cases.push(json!({"name":label,"path":format!("controls/{label}.frame"),
            "expected_guest_accept":false,"format_rejected":true,"format_error":format!("{error:?}"),
            "claim_digest_hex":hex(&claim_digest(statement.len(),&canonical))}));
    }
    let mut wrong_count = positive;
    wrong_count[8..16].copy_from_slice(&((statement.len() + 1) as u64).to_le_bytes());
    fs::write(out.join("wrong-frame-count.frame"), wrong_count)?;
    cases.push(
        json!({"name":"wrong-frame-count","path":"controls/wrong-frame-count.frame",
        "expected_guest_accept":false,"reason":"frame count differs from canonical statement count",
        "claim_digest_hex":hex(&claim_digest(statement.len(),&canonical))}),
    );

    // This is a VALID Aerie proof for a DIFFERENT intended record ordering.
    // Guest execution may accept; verifying its STARK under the original claim
    // digest must reject. This distinguishes proof validity from authorization.
    if statement.len() > 1 {
        let mut records = statement.to_records();
        records.swap(0, 1);
        let alternate = AggregationStatement::new(records)?;
        let mut signatures = witness.signatures().to_vec();
        signatures.swap(0, 1);
        let alternate_witness = AggregationWitness::new(signatures)?;
        let proof = prove_aggregate(setup, &alternate, &alternate_witness)?;
        verify_aggregate(setup.verifier(), &alternate, &proof)?;
        let public = alternate.canonical_encoding()?;
        let digest = claim_digest(alternate.len(), &public);
        assert_ne!(digest, claim_digest(statement.len(), &canonical));
        let frame =
            encode(alternate.len(), &public, &proof).map_err(|e| format!("alternate: {e:?}"))?;
        fs::write(out.join("valid-other-claims.frame"), frame)?;
        fs::write(out.join("valid-other-claims.statement.bin"), &public)?;
        cases.push(
            json!({"name":"valid-other-claims","path":"controls/valid-other-claims.frame",
            "expected_guest_accept":true,"expected_original_statement_stark_accept":false,
            "native_verified":true,"claim_digest_hex":hex(&digest),
            "original_claim_digest_hex":hex(&claim_digest(statement.len(),&canonical))}),
        );
    }
    Ok(
        json!({"kind":"native preconditions for later actual guest/proof-boundary controls",
        "controls":cases,"guest_controls_executed":false,
        "note":"Native rejection and framing checks do not substitute for actual guest execution and outer proof verification."}),
    )
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--export-setup") {
        if args.len() != 3 {
            return Err("usage: aerie-wrapper-inputs --export-setup N OUT".into());
        }
        return export_setup(args[1].parse()?, Path::new(&args[2]));
    }
    if args.first().map(String::as_str) == Some("--verify-imported-setup") {
        if args.len() != 6 {
            return Err("usage: aerie-wrapper-inputs --verify-imported-setup N SETUP STATEMENT PROOF REPORT".into());
        }
        return verify_imported_setup(
            args[1].parse()?,
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
            Path::new(&args[5]),
        );
    }
    if args.len() < 2 {
        return Err(
            "usage: aerie-wrapper-inputs FIXTURE OUT [--repeat N] [--warmup N] [--no-controls]"
                .into(),
        );
    }
    let fixture_path = PathBuf::from(&args[0]);
    let out = PathBuf::from(&args[1]);
    let mut repeat = 3usize;
    let mut warmup = 1usize;
    let mut run_controls = true;
    let mut at = 2;
    while at < args.len() {
        match args[at].as_str() {
            "--repeat" => {
                at += 1;
                repeat = args.get(at).ok_or("missing repeat")?.parse()?;
            }
            "--warmup" => {
                at += 1;
                warmup = args.get(at).ok_or("missing warmup")?.parse()?;
            }
            "--no-controls" => run_controls = false,
            _ => return Err(format!("unknown argument {}", args[at]).into()),
        }
        at += 1;
    }
    if repeat == 0 {
        return Err("repeat must be positive".into());
    }
    fs::create_dir_all(&out)?;
    let start = Instant::now();
    let (statement, witness) = fixture(&fixture_path)?;
    let fixture_parse_s = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let canonical = statement.canonical_encoding()?;
    let canonical_encode_s = start.elapsed().as_secs_f64();
    let digest = claim_digest(statement.len(), &canonical);
    fs::write(out.join("statement.bin"), &canonical)?;
    fs::write(out.join("claim-digest.bin"), digest)?;
    let start = Instant::now();
    let setup = FalconAggregateSetup::<Falcon512>::new(statement.len())?;
    let setup_s = start.elapsed().as_secs_f64();
    let mut warmups = Vec::new();
    let mut samples = Vec::new();
    let mut prove_times = Vec::new();
    let mut verify_times = Vec::new();
    let mut final_proof = Vec::new();
    for pass in 0..warmup + repeat {
        let start = Instant::now();
        let proof = prove_aggregate(&setup, &statement, &witness)?;
        let prove_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        verify_aggregate(setup.verifier(), &statement, &proof)?;
        let verify_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let frame =
            encode(statement.len(), &canonical, &proof).map_err(|e| format!("frame: {e:?}"))?;
        let frame_encode_s = start.elapsed().as_secs_f64();
        if pass < warmup {
            warmups.push(json!({"inner_prove_s":prove_s,"inner_verify_s":verify_s,"proof_bytes":proof.len()}));
            continue;
        }
        let sample = pass - warmup;
        let sample_dir = out.join(format!("sample-{sample}"));
        fs::create_dir_all(&sample_dir)?;
        fs::write(sample_dir.join("aggregate.aerie"), &proof)?;
        fs::write(sample_dir.join("input.frame"), &frame)?;
        samples.push(json!({"sample":sample,"inner_prove_s":prove_s,"inner_verify_s":verify_s,"frame_encode_s":frame_encode_s,
            "inner_proof_bytes":proof.len(),"guest_input_bytes":frame.len(),"inner_verified":true,
            "proof":format!("sample-{sample}/aggregate.aerie"),"frame":format!("sample-{sample}/input.frame")}));
        prove_times.push(prove_s);
        verify_times.push(verify_s);
        final_proof = proof;
    }
    if run_controls {
        let report = controls(
            &out.join("controls"),
            &setup,
            &statement,
            &witness,
            &final_proof,
        )?;
        save_json(out.join("controls.json"), &report)?;
    }
    let report = json!({"schema_version":1,"kind":"native Aerie production for complete leanVM verifier inputs",
        "aerie_revision":"49b6c212c209286c536196f53618823ffdf0e899","fixture":fixture_path,
        "records":statement.len(),"padded_records":statement.len().next_power_of_two().max(8),
        "profile":core::str::from_utf8(PROFILE)?,"claim_digest_hex":hex(&digest),"canonical_statement_bytes":canonical.len(),
        "message_lengths":statement.messages().iter().map(Vec::len).collect::<Vec<_>>(),
        "fixture_parse_s":fixture_parse_s,"canonical_encode_s":canonical_encode_s,"inner_setup_s":setup_s,
        "inner_prove_median_s":median(&prove_times),"inner_verify_median_s":median(&verify_times),
        "warmup_passes":warmup,"measured_passes":repeat,"warmups":warmups,"samples":samples,
        "timing_scope":"Native Aerie prove includes unchanged public proof production; setup/fixture parsing/signing separate. This producer does not execute or prove the leanVM guest.",
        "input_scope":"Guest receives canonical public statement and inner Aerie proof only; no original Falcon signatures, arithmetic advice or host verdict."});
    save_json(out.join("metadata.json"), &report)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
