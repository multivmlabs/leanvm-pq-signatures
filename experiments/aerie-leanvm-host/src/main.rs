//! A trusted-program host for the complete Aerie verifier guest.

use aerie_wrapper_format::{MAX_RECORDS, MAX_STATEMENT_BYTES, PROFILE, claim_digest, decode};
use bench::{Counting, Jemalloc};
use leanvm::asm::Asm;
use leanvm::{
    CircuitId, Guest, Machine, Output, PerTable, Program, Proof, ProveError, Prover, Randomness,
    Rate, Region, Stats, TableId, Trap,
};
use leanvm_guest::PublicValues;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

#[global_allocator]
static ALLOCATOR: Counting<Jemalloc> = Counting(Jemalloc);

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const LEANVM_REVISION: &str = "06e5c9cd6981103786f9d0a17324241b559a50d3";
const HELP: &str = "aerie-leanvm-host inspect|execute|interpret|prove|verify --elf FILE --expect-elf-sha256 HEX --report FILE\n\
  execute/prove: --input FRAME [--rate 1] [--zk]\n\
  prove: --proof FILE\n\
  verify: --statement FILE --records N --proof FILE [--zk]\n\
  all modes: [--repeat 3] [--warmup 1] [--threads 12]\n\
  execute/interpret rejection tests: [--raw-negative-input] [--nonzero-advice-padding]\n\
  interpret: --input FRAME [--max-cycles 1000000000] [--profile-counts], no commitment capacity check or proof\n\
  inspect: synthetic exit with the ELF's code/memory heights, no Aerie execution or proof\n\
  execute counts rows without retaining a trace; its output digest is not inspected.\n\
  prove checks output, serializes, decodes and fully verifies every measured proof.\n\
  verify uses only the trusted ELF, intended canonical public statement, count and outer proof.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Inspect,
    Execute,
    Interpret,
    Prove,
    Verify,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Execute => "execute",
            Self::Interpret => "interpret",
            Self::Prove => "prove",
            Self::Verify => "verify",
        }
    }
}

struct Options {
    mode: Mode,
    elf: PathBuf,
    elf_sha256: String,
    input: Option<PathBuf>,
    statement: Option<PathBuf>,
    records: Option<usize>,
    proof: Option<PathBuf>,
    report: PathBuf,
    repeat: usize,
    warmup: usize,
    threads: NonZeroUsize,
    rate: Rate,
    zk: bool,
    raw_negative_input: bool,
    nonzero_advice_padding: bool,
    profile_counts: bool,
    max_cycles: u64,
}

fn options() -> Result<Options> {
    let mut args = env::args().skip(1);
    let mode = match args.next().as_deref() {
        Some("inspect") => Mode::Inspect,
        Some("execute" | "measure") => Mode::Execute,
        Some("interpret") => Mode::Interpret,
        Some("prove") => Mode::Prove,
        Some("verify") => Mode::Verify,
        _ => return Err(HELP.into()),
    };
    let mut flags = BTreeMap::new();
    let mut zk = false;
    let mut raw_negative_input = false;
    let mut nonzero_advice_padding = false;
    let mut profile_counts = false;
    while let Some(flag) = args.next() {
        if flag == "--zk" {
            if zk {
                return Err("duplicate --zk".into());
            }
            zk = true;
            continue;
        }
        if flag == "--raw-negative-input" {
            if raw_negative_input || !matches!(mode, Mode::Execute | Mode::Interpret) {
                return Err(
                    "--raw-negative-input is a single execute/interpret-only test option".into(),
                );
            }
            raw_negative_input = true;
            continue;
        }
        if flag == "--nonzero-advice-padding" {
            if nonzero_advice_padding || !matches!(mode, Mode::Execute | Mode::Interpret) {
                return Err(
                    "--nonzero-advice-padding is a single execute/interpret-only test option"
                        .into(),
                );
            }
            nonzero_advice_padding = true;
            continue;
        }
        if flag == "--profile-counts" {
            if profile_counts || mode != Mode::Interpret {
                return Err("--profile-counts is a single interpret-only option".into());
            }
            profile_counts = true;
            continue;
        }
        if !matches!(
            flag.as_str(),
            "--elf"
                | "--expect-elf-sha256"
                | "--input"
                | "--frame"
                | "--statement"
                | "--records"
                | "--proof"
                | "--report"
                | "--repeat"
                | "--warmup"
                | "--threads"
                | "--rate"
                | "--max-cycles"
        ) {
            return Err(format!("unknown argument {flag}\n{HELP}").into());
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        let name = if flag == "--frame" {
            "--input".to_string()
        } else {
            flag
        };
        if flags.insert(name.clone(), value).is_some() {
            return Err(format!("duplicate {name}").into());
        }
    }
    let required = |key: &str| -> Result<String> {
        flags
            .get(key)
            .cloned()
            .ok_or_else(|| format!("required {key}").into())
    };
    let number = |key: &str, default: usize| -> Result<usize> {
        flags.get(key).map_or(Ok(default), |v| Ok(v.parse()?))
    };
    let repeat = number("--repeat", 3)?;
    if repeat == 0 {
        return Err("--repeat must be positive".into());
    }
    let elf_sha256 = required("--expect-elf-sha256")?.to_ascii_lowercase();
    if elf_sha256.len() != 64 || !elf_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--expect-elf-sha256 must be exactly 64 hexadecimal digits".into());
    }
    let records = flags.get("--records").map(|s| s.parse()).transpose()?;
    let input = flags.get("--input").map(PathBuf::from);
    let statement = flags.get("--statement").map(PathBuf::from);
    let proof = flags.get("--proof").map(PathBuf::from);
    if mode == Mode::Verify {
        if statement.is_none() || records.is_none() || proof.is_none() {
            return Err("verify requires --statement, --records and --proof".into());
        }
        if input.is_some() {
            return Err("verify does not take an inner proof/frame".into());
        }
    } else if mode != Mode::Inspect && (input.is_none() || mode == Mode::Prove && proof.is_none()) {
        return Err("execute/prove requires --input; prove also requires --proof".into());
    }
    Ok(Options {
        mode,
        elf: required("--elf")?.into(),
        elf_sha256,
        input,
        statement,
        records,
        proof,
        report: required("--report")?.into(),
        repeat,
        warmup: number("--warmup", 1)?,
        threads: NonZeroUsize::new(number("--threads", 12)?).ok_or("--threads must be positive")?,
        rate: Rate::new(number("--rate", 1)?.try_into()?)?,
        zk,
        raw_negative_input,
        nonzero_advice_padding,
        profile_counts,
        max_cycles: number("--max-cycles", 1_000_000_000)?.try_into()?,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pinned_elf(bytes: &[u8], trusted_hash: &str) -> Result<String> {
    let actual = hex(&Sha256::digest(bytes));
    if actual != trusted_hash {
        return Err(
            format!("trusted ELF SHA-256 mismatch: expected {trusted_hash}, got {actual}").into(),
        );
    }
    Ok(actual)
}

fn output_for(records: usize, canonical: &[u8]) -> Result<([u8; 32], Output)> {
    if !(1..=MAX_RECORDS).contains(&records)
        || canonical.is_empty()
        || canonical.len() > MAX_STATEMENT_BYTES
    {
        return Err("public statement/count outside supported bounds".into());
    }
    let digest = claim_digest(records, canonical);
    let words = std::array::from_fn::<u64, 4, _>(|i| {
        u64::from_le_bytes(digest[i * 8..i * 8 + 8].try_into().expect("four words"))
    });
    let mut public = PublicValues::new();
    public.commit(&words);
    Ok((digest, Output::new(public.digest())))
}

fn advice_for(frame: &[u8]) -> Vec<u64> {
    let mut advice = Vec::with_capacity(1 + frame.len().div_ceil(8));
    advice.push(frame.len() as u64);
    advice.extend(frame.chunks(8).map(|chunk| {
        let mut word = [0; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        u64::from_le_bytes(word)
    }));
    advice
}

fn corrupt_advice_padding(advice: &mut [u64], frame_bytes: usize) -> Result<()> {
    let live_bytes = frame_bytes % 8;
    if live_bytes == 0 {
        return Err("--nonzero-advice-padding requires a frame length not divisible by 8".into());
    }
    let final_word = advice.last_mut().expect("a nonempty packed frame");
    *final_word |= 1 << (8 * live_bytes);
    Ok(())
}

fn stats_json(stats: &Stats) -> Value {
    let base: BTreeMap<_, _> = stats
        .base_counts
        .iter()
        .map(|(table, n)| (table.name(), *n))
        .collect();
    let proven: BTreeMap<_, _> = stats
        .counts
        .iter()
        .map(|(table, n)| (table.name(), *n))
        .collect();
    json!({
        "cycles":stats.cycles(), "proven_rows":stats.proven_rows,
        "committed_words":stats.committed, "base_rows":base,
        "proven_rows_by_table":proven, "details":stats.details()
    })
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn sample(report: &mut Value, name: &str, seconds: f64) {
    report[name]
        .as_array_mut()
        .expect("sample array")
        .push(json!(seconds));
}

fn check_output(observed: Output, expected: Output) -> Result<()> {
    if observed != expected {
        return Err(
            format!("guest public output mismatch: expected {expected}, got {observed}").into(),
        );
    }
    Ok(())
}

fn inspect_static_floor(elf: &[u8], program: &Program, report: &mut Value) -> Result<()> {
    let mut guest = Guest::from_elf(elf)?;
    let exit_pc = Region::TEXT.base() + (guest.text.len() as u64) * 4;
    guest.text.extend(Asm::new().exit().finish());
    let diagnostic = Program::new(
        &guest.text,
        exit_pc,
        guest.image,
        guest.log_ram,
        guest.log_advice,
    )?;
    let same_height = diagnostic.rv().entries().len() == program.rv().entries().len();
    report["static_floor_diagnostic"] = json!({
        "scope":"Synthetic exit appended to the original ELF text, retaining code and memory heights. Does not execute Aerie or produce a proof.",
        "same_decoded_bytecode_height":same_height,
        "synthetic_program_digest_hex":hex(diagnostic.digest()),
        "synthetic_decoded_bytecode_entries":diagnostic.rv().entries().len(),
    });
    if !same_height {
        return Err("appended diagnostic exit crossed a bytecode height boundary; cannot infer original static floor".into());
    }
    let start = Instant::now();
    let result = diagnostic.measure(&[]);
    report["static_floor_diagnostic"]["measurement_s"] = json!(start.elapsed().as_secs_f64());
    match result {
        Ok(stats) => {
            let mu = stats.committed.max(1).next_power_of_two().trailing_zeros() as usize;
            report["static_floor_diagnostic"]["fits_one_plain_commitment"] = json!(true);
            report["static_floor_diagnostic"]["stats"] = stats_json(&stats);
            report["static_floor_diagnostic"]["committed_log2_ceil"] =
                json!(mu.max(leanvm::MIN_MU));
            report["static_floor_diagnostic"]["below_commitment_word_limit"] =
                json!((1usize << leanvm::MAX_MU) - stats.committed);
        }
        Err(ProveError::TooLong) => {
            report["static_floor_diagnostic"]["fits_one_plain_commitment"] = json!(false);
            report["static_floor_diagnostic"]["error"] = json!(ProveError::TooLong.to_string());
            report["static_floor_diagnostic"]["committed_log2_lower_bound"] =
                json!(leanvm::MAX_MU + 1);
            report["static_floor_diagnostic"]["exact_committed_words_available"] = json!(false);
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn interpreter_counts_json(counts: &PerTable<usize>) -> Value {
    let base: BTreeMap<_, _> = counts
        .iter()
        .map(|(table, rows)| (table.name(), *rows))
        .collect();
    let heights: PerTable<usize> =
        PerTable::from_fn(|table: TableId| table.spec().provable_height(counts[table]));
    let padded: BTreeMap<_, _> = heights
        .iter()
        .map(|(table, rows)| (table.name(), *rows))
        .collect();
    let packed_words: usize = CircuitId::ALL
        .iter()
        .map(|circuit| heights[circuit.table()] << circuit.stride_log())
        .sum();
    json!({
        "base_rows":base,
        "independent_provable_heights":padded,
        "packed_witness_lower_bound_words":packed_words,
        "packed_witness_lower_bound_log2_ceil":packed_words.max(1).next_power_of_two().trailing_zeros(),
        "packed_witness_lower_bound_exceeds_one_commitment":packed_words > (1usize << leanvm::MAX_MU),
        "scope":"Exact per-class executed rows. Conservative witness lower bound counts class and clock packed witnesses at independently rounded provable heights, omitting shared state, other committed columns and any extra fill-plan rows. Not proof size or a proof."
    })
}

fn interpreter_profile_json(counts: &[u64]) -> Value {
    json!(
        counts
            .iter()
            .enumerate()
            .filter(|(_, count)| **count != 0)
            .map(|(index, count)| json!({
                "pc_hex":format!("{:016x}",Region::TEXT.base()+4*index as u64),"count":count
            }))
            .collect::<Vec<_>>()
    )
}

fn run(options: &Options, report: &mut Value) -> Result<()> {
    // ELF decoding hashes the initial program and can initialize the shared worker pool.
    // Fix its exact size before loading the program or invoking any parallel operation.
    let start = Instant::now();
    parallel::init_with_threads(options.threads)?;
    report["threads"] = json!(parallel::num_threads());
    report["pool_init_s"] = json!(start.elapsed().as_secs_f64());
    let start = Instant::now();
    let elf = fs::read(&options.elf)?;
    report["elf_sha256"] = json!(pinned_elf(&elf, &options.elf_sha256)?);
    report["elf_bytes"] = json!(elf.len());
    report["elf_read_hash_s"] = json!(start.elapsed().as_secs_f64());
    let start = Instant::now();
    let program = Program::from_elf(&elf)?;
    report["elf_load_decode_s"] = json!(start.elapsed().as_secs_f64());
    report["program_digest_hex"] = json!(hex(program.digest()));
    report["guest_ram_bytes"] = json!((1usize << program.rv().log_ram()) * 8);
    report["guest_advice_capacity_bytes"] = json!((1usize << program.rv().log_advice()) * 8);
    report["decoded_bytecode_entries"] = json!(program.rv().entries().len());
    report["initial_image_words"] = json!(program.rv().image().len());

    if options.mode == Mode::Inspect {
        return inspect_static_floor(&elf, &program, report);
    }

    if options.mode == Mode::Verify {
        let start = Instant::now();
        let statement = fs::read(options.statement.as_ref().expect("required statement"))?;
        let records = options.records.expect("required count");
        let (digest, expected) = output_for(records, &statement)?;
        report["records"] = json!(records);
        report["canonical_statement_bytes"] = json!(statement.len());
        report["public_claim_digest_hex"] = json!(hex(&digest));
        report["expected_output_words"] = json!(expected.words());
        report["public_statement_digest_s"] = json!(start.elapsed().as_secs_f64());
        let bytes = fs::read(options.proof.as_ref().expect("required proof"))?;
        report["proof_bytes"] = json!(bytes.len());
        report["proof_sha256"] = json!(hex(&Sha256::digest(&bytes)));
        for round in 0..options.warmup + options.repeat {
            // Receipt parsing is included in verification time, and each round uses a fresh object.
            let start = Instant::now();
            let proof = Proof::from_bytes(&bytes)?;
            if options.zk && !proof.is_zero_knowledge() {
                return Err("a zero-knowledge proof was required".into());
            }
            program.verify(expected, &proof)?;
            let elapsed = start.elapsed().as_secs_f64();
            report["zero_knowledge"] = json!(proof.is_zero_knowledge());
            if round >= options.warmup {
                sample(report, "verify_samples_s", elapsed);
            }
        }
        report["public_output_checked"] = json!(true);
        return Ok(());
    }

    let start = Instant::now();
    let input = fs::read(options.input.as_ref().expect("required frame"))?;
    let mut advice = advice_for(&input);
    if options.nonzero_advice_padding {
        corrupt_advice_padding(&mut advice, input.len())?;
    }
    let expected = if options.raw_negative_input {
        // Deliberately pass malformed framing to the unchanged guest parser in rejection tests.
        // This path cannot produce proofs and never skips a guest verification check.
        None
    } else {
        let frame = decode(&input).map_err(|error| format!("invalid input frame: {error:?}"))?;
        let (digest, output) = output_for(frame.records, frame.statement)?;
        report["records"] = json!(frame.records);
        report["canonical_statement_bytes"] = json!(frame.statement.len());
        report["inner_proof_bytes"] = json!(frame.proof.len());
        report["public_claim_digest_hex"] = json!(hex(&digest));
        report["expected_output_words"] = json!(output.words());
        Some(output)
    };
    report["input_frame_bytes"] = json!(input.len());
    report["advice_words"] = json!(advice.len());
    report["input_prepare_s"] = json!(start.elapsed().as_secs_f64());

    if options.mode == Mode::Interpret {
        let max = 1usize << program.rv().log_advice();
        if advice.len() > max {
            return Err(ProveError::AdviceTooLong {
                max,
                got: advice.len(),
            }
            .into());
        }
        let tables: Vec<_> = program
            .rv()
            .entries()
            .iter()
            .map(|entry| TableId::of(entry.class))
            .collect();
        for round in 0..options.warmup + options.repeat {
            let start = Instant::now();
            let mut machine = Machine::new(program.rv(), &advice);
            let mut cycles = 0;
            let mut counts = PerTable::<usize>::default();
            let mut profile = options.profile_counts.then(|| vec![0u64; tables.len()]);
            while !machine.halted() && cycles < options.max_cycles {
                let step = match machine.step() {
                    Ok(step) => step,
                    Err(error) => {
                        report["interpreter_instructions"] = json!(cycles);
                        report["interpreter_counts"] = interpreter_counts_json(&counts);
                        report["interpreter_failure_pc_hex"] =
                            json!(format!("{:016x}", machine.pc()));
                        return Err(error.into());
                    }
                };
                counts[tables[step.index].expect("every executed class has a table")] += 1;
                if let Some(profile) = profile.as_mut() {
                    profile[step.index] += 1;
                }
                cycles += 1;
            }
            report["interpreter_instructions"] = json!(cycles);
            if !machine.halted() {
                report["interpreter_counts"] = interpreter_counts_json(&counts);
                return Err(format!(
                    "interpreter stopped at --max-cycles {} without exit",
                    options.max_cycles
                )
                .into());
            }
            let output = Output::new(machine.output()?);
            if let Some(expected) = expected {
                check_output(output, expected)?;
            }
            let elapsed = start.elapsed().as_secs_f64();
            report["interpreter_counts"] = interpreter_counts_json(&counts);
            if let Some(profile) = profile.as_ref() {
                report["instruction_profile"] = interpreter_profile_json(profile);
            }
            report["observed_output_words"] = json!(output.words());
            report["public_output_checked"] = json!(expected.is_some());
            if round >= options.warmup {
                sample(report, "interpret_samples_s", elapsed);
            }
        }
        return Ok(());
    }

    if options.mode == Mode::Execute {
        for round in 0..options.warmup + options.repeat {
            let start = Instant::now();
            let measured = program.measure(&advice)?;
            let elapsed = start.elapsed().as_secs_f64();
            report["stats"] = stats_json(&measured);
            if round >= options.warmup {
                sample(report, "measure_samples_s", elapsed);
            }
        }
        // Program::measure checks successful exit but intentionally discards the four output words.
        report["public_output_checked"] = json!(false);
        return Ok(());
    }

    let mut prover = Prover::new(options.rate);
    if options.zk {
        prover = prover.zero_knowledge(Randomness::Os);
    }
    for round in 0..options.warmup + options.repeat {
        let start = Instant::now();
        let (proven, heap) = bench::measure_heap(|| prover.prove(&program, &advice));
        let prove_s = start.elapsed().as_secs_f64();
        let proven = proven?;
        let expected = expected.expect("proving always uses checked input framing");
        check_output(proven.output, expected)?;
        let start = Instant::now();
        let bytes = proven.proof.to_bytes();
        let serialize_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let fresh = Proof::from_bytes(&bytes)?;
        program.verify(expected, &fresh)?;
        let verify_s = start.elapsed().as_secs_f64();
        report["stats"] = stats_json(&proven.stats);
        report["proof_bytes"] = json!(bytes.len());
        report["proof_sha256"] = json!(hex(&Sha256::digest(&bytes)));
        report["public_output_checked"] = json!(true);
        if round >= options.warmup {
            sample(report, "prove_samples_s", prove_s);
            sample(report, "serialize_samples_s", serialize_s);
            sample(report, "self_verify_samples_s", verify_s);
            report["prove_peak_heap_bytes"]
                .as_array_mut()
                .expect("sample array")
                .push(json!(heap.peak));
            report["prove_allocations"]
                .as_array_mut()
                .expect("sample array")
                .push(json!(heap.allocations));
        }
        if round + 1 == options.warmup + options.repeat {
            let start = Instant::now();
            write(options.proof.as_ref().expect("required proof"), &bytes)?;
            report["proof_write_s"] = json!(start.elapsed().as_secs_f64());
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let options = match options() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let mut report = json!({
        "schema_version":1,"mode":options.mode.name(),"status":"running",
        "profile":String::from_utf8_lossy(PROFILE),"leanvm_revision":LEANVM_REVISION,
        "trusted_elf_sha256":options.elf_sha256,"rate_log_inv":options.rate.log_inv_rate(),
        "zero_knowledge":options.zk,"warmup":options.warmup,"repeat":options.repeat,
        "raw_negative_input":options.raw_negative_input,
        "nonzero_advice_padding":options.nonzero_advice_padding,
        "profile_counts":options.profile_counts,
        "instruction_profile_scope":"All nonzero instruction counts in address order. Counter collection is included in profiled interpretation, JSON formatting excluded. Not proof size or proving time.",
        "threads_requested":options.threads.get(),"proof_framing_bytes":0,
        "proof_encoding":"Proof::to_bytes includes leanVM envelope; file has no additional framing",
        "measure_samples_s":[],"interpret_samples_s":[],"prove_samples_s":[],"serialize_samples_s":[],
        "self_verify_samples_s":[],"verify_samples_s":[],"prove_peak_heap_bytes":[],"prove_allocations":[],
        "public_output_checked":false,"max_commitment_log_words":leanvm::MAX_MU,
        "verification_inputs":"trusted ELF and its independently configured SHA-256, intended canonical statement, record count, outer proof",
        "measure_scope":"count-only execution includes all guest verification; native capacity checks can reject before exit",
        "interpret_scope":"bounded reference RV64IM interpreter, full guest and output check; no trace, commitment capacity check or proof",
        "interpreter_max_cycles":options.max_cycles,
        "prove_scope":"execution, trace, witness and outer STARK; excludes serialization, verification and disk writes",
        "verify_scope":"fresh proof decoding plus full Program::verify; excludes ELF load and intended statement hashing"
    });
    let start = Instant::now();
    let result = run(&options, &mut report);
    report["total_wall_s"] = json!(start.elapsed().as_secs_f64());
    report["peak_rss_bytes"] = json!(bench::peak_rss_bytes());
    report["status"] = json!(if result.is_ok() { "ok" } else { "error" });
    if let Err(error) = &result {
        report["error"] = json!(error.to_string());
        report["error_debug"] = json!(format!("{error:?}"));
        report["error_kind"] = json!(match error.downcast_ref::<ProveError>() {
            Some(ProveError::TooLong) => "leanvm_capacity",
            Some(ProveError::Trap(_)) => "guest_trap",
            Some(ProveError::AdviceTooLong { .. }) => "advice_capacity",
            None if error.downcast_ref::<Trap>().is_some() => "guest_trap",
            None => "host_or_verification",
        });
        eprintln!("{error}");
    }
    if let Err(error) = write(
        &options.report,
        &serde_json::to_vec_pretty(&report).expect("JSON report"),
    ) {
        eprintln!("writing report: {error}");
        return ExitCode::FAILURE;
    }
    println!("{}", serde_json::to_string(&json!({"status":report["status"],"report":options.report,"proof_bytes":report["proof_bytes"],"records":report["records"]})).expect("summary"));
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanvm::Region;
    use leanvm::asm::{Addi, Asm, Reg};

    #[test]
    fn advice_has_exact_byte_length_and_zero_word_padding() {
        let bytes = b"abcdefghijk";
        let advice = advice_for(bytes);
        assert_eq!(advice[0], 11);
        let padded: Vec<_> = advice[1..].iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(&padded[..11], bytes);
        assert_eq!(&padded[11..], &[0; 5]);
        assert_eq!(advice.len(), 3);
        let mut corrupted = advice.clone();
        corrupt_advice_padding(&mut corrupted, bytes.len()).unwrap();
        let poisoned: Vec<_> = corrupted[1..]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert_eq!(corrupted[0], advice[0]);
        assert_eq!(&poisoned[..11], bytes);
        assert_eq!(poisoned[11], 1);
        assert_eq!(&poisoned[12..], &[0; 4]);
        assert!(corrupt_advice_padding(&mut advice_for(b"abcdefgh"), 8).is_err());
    }

    #[test]
    fn independent_public_claim_binds_message_key_order_and_count() {
        let (_, original) = output_for(2, b"pk1/message1;pk2/message2").unwrap();
        for bytes in [
            b"pk1/Message1;pk2/message2".as_slice(),
            b"pk3/message1;pk2/message2",
            b"pk2/message2;pk1/message1",
        ] {
            assert_ne!(output_for(2, bytes).unwrap().1, original);
        }
        assert_ne!(
            output_for(1, b"pk1/message1;pk2/message2").unwrap().1,
            original
        );
    }

    #[test]
    fn trusted_program_pin_rejects_changed_elf() {
        let hash = hex(&Sha256::digest(b"trusted ELF"));
        assert!(pinned_elf(b"trusted ELF", &hash).is_ok());
        assert!(pinned_elf(b"untrusted ELF", &hash).is_err());
    }

    #[test]
    fn real_outer_proof_binds_claim_program_and_exact_receipt() {
        // This small synthetic program tests the host/backend contract, not Aerie verification.
        let canonical = b"pk1/message1;pk2/message2";
        let (_, expected) = output_for(2, canonical).unwrap();
        let mut asm = Asm::new();
        for (register, word) in [Reg::A0, Reg::A1, Reg::A2, Reg::A3]
            .into_iter()
            .zip(expected.words())
        {
            asm.li(register, *word);
        }
        let text = asm.exit().finish();
        let program = Program::new(&text, Region::TEXT.base(), vec![], 0, 0).unwrap();
        let proven = Prover::new(Rate::MIN).prove(&program, &[]).unwrap();
        check_output(proven.output, expected).unwrap();
        let bytes = proven.proof.to_bytes();
        let proof = Proof::from_bytes(&bytes).unwrap();
        program.verify(expected, &proof).unwrap();
        for statement in [
            b"pk1/Message1;pk2/message2".as_slice(),
            b"pk3/message1;pk2/message2",
            b"pk2/message2;pk1/message1",
        ] {
            assert!(
                program
                    .verify(output_for(2, statement).unwrap().1, &proof)
                    .is_err()
            );
        }
        assert!(
            program
                .verify(output_for(1, canonical).unwrap().1, &proof)
                .is_err()
        );
        let mut altered = Asm::new();
        altered.i(Addi, Reg::ZERO, Reg::ZERO, 0);
        for word in text {
            altered.word(word);
        }
        let other_program =
            Program::new(&altered.finish(), Region::TEXT.base(), vec![], 0, 0).unwrap();
        assert!(other_program.verify(expected, &proof).is_err());
        assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(Proof::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
        let mut corrupted = bytes;
        let middle = corrupted.len() / 2;
        corrupted[middle] ^= 1;
        if let Ok(proof) = Proof::from_bytes(&corrupted) {
            assert!(program.verify(expected, &proof).is_err());
        }
    }
}
