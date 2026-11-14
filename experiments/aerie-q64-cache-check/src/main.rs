//! Native checks and export of immutable public Q64 terminal transforms.
//! No signatures or proofs are generated here. Cache payloads are trusted
//! derived verifier data, never prover advice.
use aerie::falcon::{verify_aggregate, AggregationRecord, AggregationStatement, Falcon512};
use aerie_falcon::{
    pcs::verifier_group_profiles_of, substrate::BaseField, FalconDegree, FalconVerifierSetup,
};
use akita_algebra::{
    ntt::tables::{Q64_NUM_PRIMES, Q64_PRIMES},
    CyclotomicRing,
};
use akita_params::ScheduleRowDigest;
use akita_serialization::{AkitaDeserialize, Compress, Validate};
use akita_types::{
    build_riscv64_scalar_q128_cache_artifact, build_riscv64_scalar_q64_cache_artifact,
    decode_riscv64_scalar_q128_cache, decode_riscv64_scalar_q64_cache,
    prepared_verifier_ntt_cache_metadata, AkitaVerifierSetup, PreparedVerifierNttCacheBinding,
};
use akita_verifier::build_riscv64_terminal_ntt_cache;
use jolt_field::Ring;
use serde_json::{json, Value};
use std::{error::Error, fs, path::Path, time::Instant};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn save(path: &Path, value: &Value) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn check_matvec(width: usize, dense_large: bool) -> Result<Value, Box<dyn Error>> {
    const D: usize = 64;
    let matrix: Vec<_> = (0..width)
        .map(|ring| {
            CyclotomicRing::<BaseField, D>::from_coefficients(std::array::from_fn(|coefficient| {
                BaseField::from_i64(if dense_large {
                    i64::MAX - (ring * D + coefficient) as i64
                } else {
                    ((ring * 13 + coefficient * 7) % 37) as i64 - 18
                })
            }))
        })
        .collect();
    let flat = akita_params::FlatMatrix::from_ring_slice(&matrix);
    let binding = PreparedVerifierNttCacheBinding {
        setup_seed_digest: [3; 32],
        schedule_row_digest: ScheduleRowDigest::from_bytes([7; 32]),
        setup_field_elements: width * D,
    };
    let bytes = build_riscv64_scalar_q64_cache_artifact(
        flat.ring_view::<D>(1, width)?,
        width,
        1 << 15,
        binding,
    )?;
    let (metadata, decoded) = decode_riscv64_scalar_q64_cache::<BaseField, D>(&bytes, binding)?;
    assert_eq!(&bytes[8..12], &2u32.to_le_bytes());
    assert!(
        decode_riscv64_scalar_q128_cache::<jolt_field::Prime128Offset275, D>(&bytes, binding)
            .is_err()
    );
    assert_eq!(
        bytes.len(),
        120 + width * D * Q64_NUM_PRIMES * 4 + metadata.tail_prefix_len * D * 2
    );
    assert!(!decoded.uses_ifma52());
    if dense_large {
        assert!(decoded.has_exactness_tail());
        assert_eq!(metadata.tail_prefix_len, width);
    }
    let rhs: Vec<_> = (0..width)
        .map(|column| {
            std::array::from_fn(|coefficient| {
                if dense_large {
                    i16::MIN
                } else {
                    ((column * 5 + coefficient * 3) % 31) as i16 - 15
                }
            })
        })
        .collect();
    let actual = decoded.mat_vec_i16::<BaseField>(16, 1, &rhs)?;
    let expected =
        matrix
            .iter()
            .zip(&rhs)
            .fold(CyclotomicRing::<BaseField, D>::zero(), |sum, (lhs, rhs)| {
                let rhs = CyclotomicRing::from_coefficients(
                    rhs.map(|v| BaseField::from_i64(i64::from(v))),
                );
                sum + *lhs * rhs
            });
    assert_eq!(actual, vec![expected]);
    // Range/identity checks do not authenticate derived transform contents.
    // An in-range payload change is admitted, then the actual arithmetic
    // differs. This is why these bytes must be immutable trusted ELF data.
    let mut corrupt = bytes.clone();
    let raw = i32::from_le_bytes(corrupt[120..124].try_into()?);
    corrupt[120..124].copy_from_slice(&(if raw == 0 { 1i32 } else { 0i32 }).to_le_bytes());
    let (_, corrupt_decoded) = decode_riscv64_scalar_q64_cache::<BaseField, D>(&corrupt, binding)?;
    assert!(corrupt_decoded
        .mat_vec_i16::<BaseField>(16, 1, &rhs)
        .map_or(true, |value| value != actual));
    let mut rejected = Vec::new();
    for label in [
        "target",
        "seed",
        "schedule",
        "residue",
        "truncated",
        "trailing",
        "tail-count",
        "width-zero",
    ] {
        let mut bad = bytes.clone();
        match label {
            "target" => bad[8..12].copy_from_slice(&1u32.to_le_bytes()),
            "seed" => bad[56] ^= 1,
            "schedule" => bad[88] ^= 1,
            "residue" => bad[120..124].copy_from_slice(&Q64_PRIMES[0].p.to_le_bytes()),
            "truncated" => {
                bad.pop();
            }
            "trailing" => bad.push(0),
            "tail-count" => bad[24..32].copy_from_slice(&(u64::MAX).to_le_bytes()),
            "width-zero" => bad[32..40].fill(0),
            _ => unreachable!(),
        }
        assert!(
            decode_riscv64_scalar_q64_cache::<BaseField, D>(&bad, binding).is_err(),
            "{label}"
        );
        rejected.push(label);
    }
    if metadata.tail_prefix_len > 0 {
        let mut bad = bytes.clone();
        let tail_start = 120 + width * D * Q64_NUM_PRIMES * 4;
        bad[tail_start..tail_start + 2]
            .copy_from_slice(&akita_algebra::ntt::tables::I16_TAIL_PRIME.p.to_le_bytes());
        assert!(decode_riscv64_scalar_q64_cache::<BaseField, D>(&bad, binding).is_err());
        rejected.push("tail-residue");
    }
    Ok(
        json!({"ring_dimension":D,"width":width,"dense_large_coefficients":dense_large,
        "artifact_bytes":bytes.len(),"tail_prefix_len":metadata.tail_prefix_len,
        "matvec_matches_direct_ring_arithmetic":true,"malformed_cases_rejected":rejected,
        "in_range_corruption_admitted_but_fails_matvec":true}),
    )
}

fn check_q128_compatibility() -> Result<Value, Box<dyn Error>> {
    use jolt_field::Prime128Offset275 as F;
    const D: usize = 64;
    const WIDTH: usize = 4;
    let matrix: Vec<_> = (0..WIDTH)
        .map(|ring| {
            CyclotomicRing::<F, D>::from_coefficients(std::array::from_fn(|coefficient| {
                F::from_i64(((ring * 13 + coefficient * 7) % 37) as i64 - 18)
            }))
        })
        .collect();
    let flat = akita_params::FlatMatrix::from_ring_slice(&matrix);
    let binding = PreparedVerifierNttCacheBinding {
        setup_seed_digest: [3; 32],
        schedule_row_digest: ScheduleRowDigest::from_bytes([7; 32]),
        setup_field_elements: WIDTH * D,
    };
    let bytes = build_riscv64_scalar_q128_cache_artifact(
        flat.ring_view::<D>(1, WIDTH)?,
        WIDTH,
        1 << 15,
        binding,
    )?;
    let (_, decoded) = decode_riscv64_scalar_q128_cache::<F, D>(&bytes, binding)?;
    assert_eq!(&bytes[8..12], &1u32.to_le_bytes());
    assert!(decode_riscv64_scalar_q64_cache::<BaseField, D>(&bytes, binding).is_err());
    let rhs: Vec<_> = (0..WIDTH)
        .map(|column| {
            std::array::from_fn(|coefficient| ((column * 5 + coefficient * 3) % 31) as i16 - 15)
        })
        .collect();
    let actual = decoded.mat_vec_i16::<F>(16, 1, &rhs)?;
    let expected =
        matrix
            .iter()
            .zip(&rhs)
            .fold(CyclotomicRing::<F, D>::zero(), |sum, (lhs, rhs)| {
                let rhs = CyclotomicRing::from_coefficients(rhs.map(|v| F::from_i64(i64::from(v))));
                sum + *lhs * rhs
            });
    assert_eq!(actual, vec![expected]);
    Ok(
        json!({"q128_roundtrip_and_matvec_preserved":true,"cross_target_rejected":true,
        "artifact_bytes":bytes.len()}),
    )
}

fn run(root: &Path) -> Result<(), Box<dyn Error>> {
    // Width 1024 forces the scalar-Q64 exactness tail for this coefficient bound.
    let arithmetic = vec![check_matvec(4, false)?, check_matvec(1024, true)?];
    let q128_compatibility = check_q128_compatibility()?;
    let mut cases = Vec::new();
    for n in [1usize, 10, 30, 70, 100] {
        let input = root.join(format!("artifacts/aerie-wrapper/development/n{n}"));
        let public_setup = root.join(format!(
            "artifacts/aerie-wrapper/public-setup/n{n}/setup.bin"
        ));
        let out = root.join(format!("artifacts/aerie-wrapper/q64-cache/n{n}"));
        fs::create_dir_all(&out)?;
        let original_setup = fs::read(&public_setup)?;
        // Revalidate seed-derived public setup natively before exporting transforms.
        let setup = AkitaVerifierSetup::<BaseField>::deserialize_exact_with_mode(
            &original_setup,
            Compress::Yes,
            Validate::Yes,
            &(),
        )?;
        let selected = FalconVerifierSetup::<Falcon512>::from_derived_setup(n, setup.clone())?;
        let (_, _, selection) = verifier_group_profiles_of(FalconDegree::Falcon512, n)?;
        let row = selected.akita().schedules().resolve_selection(selection)?;
        let start = Instant::now();
        let artifact =
            build_riscv64_terminal_ntt_cache(&setup, row.schedule(), selection.row_digest)?;
        let export_s = start.elapsed().as_secs_f64();
        let metadata = prepared_verifier_ntt_cache_metadata(&artifact)?;
        assert_eq!(metadata.binding.schedule_row_digest, selection.row_digest);
        assert_eq!(
            metadata.binding.setup_field_elements,
            setup.expanded().descriptor().num_field_elements
        );
        assert_eq!(&artifact[8..12], &2u32.to_le_bytes());
        let artifact_path = out.join("terminal-cache.bin");
        fs::write(&artifact_path, &artifact)?;
        let statement = AggregationStatement::<Falcon512>::parse_canonical(&fs::read(
            input.join("statement.bin"),
        )?)?;
        let proof = fs::read(input.join("sample-0/aggregate.aerie"))?;
        let start = Instant::now();
        let cached = FalconVerifierSetup::<Falcon512>::from_derived_setup_with_trusted_cache(
            n,
            setup.clone(),
            &artifact,
        )?;
        let import_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        verify_aggregate(&cached, &statement, &proof)?;
        let verify_s = start.elapsed().as_secs_f64();
        let mut rejected = Vec::new();
        for label in [
            "target",
            "seed",
            "schedule",
            "residue",
            "truncated",
            "trailing",
            "width",
        ] {
            let mut bad = artifact.clone();
            match label {
                "target" => bad[8..12].copy_from_slice(&1u32.to_le_bytes()),
                "seed" => bad[56] ^= 1,
                "schedule" => bad[88] ^= 1,
                "residue" => bad[120..124].copy_from_slice(&Q64_PRIMES[0].p.to_le_bytes()),
                "truncated" => {
                    bad.pop();
                }
                "trailing" => bad.push(0),
                "width" => bad[32..40].copy_from_slice(
                    &(if metadata.width == 1 { 2u64 } else { 1u64 }).to_le_bytes(),
                ),
                _ => unreachable!(),
            }
            assert!(
                FalconVerifierSetup::<Falcon512>::from_derived_setup_with_trusted_cache(
                    n,
                    setup.clone(),
                    &bad
                )
                .is_err(),
                "{label}"
            );
            rejected.push(label);
        }
        let mut message = statement.messages()[0].clone();
        message.push(1);
        let mut records = statement.to_records();
        records[0] = AggregationRecord::new(statement.public_keys()[0].clone(), message)?;
        assert!(verify_aggregate(&cached, &AggregationStatement::new(records)?, &proof).is_err());
        let mut bad_proof = proof.clone();
        let last = bad_proof.len() - 1;
        bad_proof[last] ^= 1;
        assert!(verify_aggregate(&cached, &statement, &bad_proof).is_err());
        let case = json!({"records":n,"full_unchanged_verify_aggregate":true,
            "setup_revalidated_native":true,"artifact_bytes":artifact.len(),"artifact_target":2,
            "ring_dimension":metadata.ring_dimension,"base_prefix_len":metadata.base_prefix_len,
            "tail_prefix_len":metadata.tail_prefix_len,"width":metadata.width,"rhs_abs_bound":metadata.rhs_abs_bound,
            "setup_field_elements":metadata.binding.setup_field_elements,
            "setup_seed_digest_hex":hex(&metadata.binding.setup_seed_digest),
            "schedule_row_digest_hex":hex(metadata.binding.schedule_row_digest.as_bytes()),
            "selected_runtime_cache_bytes":selected.akita().terminal_ntt_cache_bytes(),
            "imported_runtime_cache_bytes":cached.akita().terminal_ntt_cache_bytes(),
            "export_s":export_s,"import_s":import_s,"native_verify_s":verify_s,
            "malformed_artifacts_rejected":rejected,"changed_message_and_proof_rejected":true,
            "artifact_path":artifact_path,"setup_path":public_setup,"input_path":input});
        save(&out.join("metadata.json"), &case)?;
        println!("N={n}: full native verification with trusted Q64 cache passed");
        cases.push(case);
    }
    save(
        &root.join("results/aerie-wrapper/q64-cache-native.json"),
        &json!({"schema_version":1,
        "all_five_verified":true,"arithmetic_checks":arithmetic,"q128_compatibility":q128_compatibility,"cases":cases,
        "scope":"Native validation/export and full unchanged Aerie verification. No proof generation; trusted cache bytes must be immutable ELF public data, never advice."}),
    )?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = std::env::args_os()
        .nth(1)
        .ok_or("workspace root required")?;
    run(Path::new(&root))
}
