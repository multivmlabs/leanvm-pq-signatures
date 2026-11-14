//! Reproducible measurements through the complete pinned leanVM API.
use bench::{Counting, Jemalloc};
use leanvm::{Output, Program, Proof, Prover, Rate, Stats};
use leanvm_guest::Run;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fs, path::Path, time::Instant};

#[global_allocator]
static ALLOCATOR: Counting<Jemalloc> = Counting(Jemalloc);
const REVISION: &str = "06e5c9cd6981103786f9d0a17324241b559a50d3";
type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    schema: u32,
    scheme: String,
    count: usize,
    elf_sha256: String,
    // These are the expected output of independently prepared intended public claims.
    // A verifier must obtain this statement and its digest from its own application.
    expected_output: [u64; 4],
    public_records: Vec<Value>,
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn save(path: &str, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn stats_json(s: &Stats) -> Value {
    json!({"cycles":s.cycles(),"committed_words":s.committed,"proven_rows":s.proven_rows,
      "rows":s.base_counts.iter().map(|(t,n)|(t.name(),*n)).collect::<BTreeMap<_,_>>(),
      "padded_rows":s.counts.iter().map(|(t,n)|(t.name(),*n)).collect::<BTreeMap<_,_>>()})
}
fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid hex".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn field_bytes(record: &Value, name: &str) -> Result<Vec<u8>> {
    unhex(
        record
            .get(name)
            .and_then(Value::as_str)
            .ok_or("missing public record field")?,
    )
}
fn expected(scheme: &str, records: &[Value]) -> Result<[u64; 4]> {
    if records.is_empty() {
        return Err("empty public claims".into());
    }
    match scheme {
        "falcon" => {
            let mut p = leanvm_guest::PublicValues::new();
            for r in records {
                let pk = field_bytes(r, "public_key")?;
                let msg = field_bytes(r, "message")?;
                if pk.len() != 897 || pk[0] != 9 || msg.len() != 32 {
                    return Err("invalid Falcon public record".into());
                }
                let key: [u64; 112] = std::array::from_fn(|i| {
                    u64::from_be_bytes(pk[1 + i * 8..1 + i * 8 + 8].try_into().unwrap())
                });
                let message: [u64; 4] = std::array::from_fn(|i| {
                    u64::from_le_bytes(msg[i * 8..i * 8 + 8].try_into().unwrap())
                });
                p.commit(&key).commit(&message);
            }
            Ok(p.digest())
        }
        "fors" => {
            let headers = records
                .iter()
                .map(|r| -> Result<_> {
                    let mut header = [[0; 4]; 3];
                    for (i, name) in ["seed", "root", "message"].iter().enumerate() {
                        let b = field_bytes(r, name)?;
                        if b.len() != 32 {
                            return Err("invalid FORS public record".into());
                        }
                        for j in 0..4 {
                            header[i][j] =
                                u64::from_le_bytes(b[j * 8..j * 8 + 8].try_into().unwrap());
                        }
                    }
                    Ok(header)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(fors_host::expected_output(&headers))
        }
        "mldsa" => {
            let records = records
                .iter()
                .map(|r| -> Result<_> {
                    Ok(mldsa_riscv_host::PublicRecord {
                        public_key: field_bytes(r, "public_key")?
                            .try_into()
                            .map_err(|_| "ML-DSA key length")?,
                        message: field_bytes(r, "message")?
                            .try_into()
                            .map_err(|_| "ML-DSA message length")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(mldsa_riscv_host::expected_output(&records))
        }
        _ => Err("unsupported scheme".into()),
    }
}
fn fixture(scheme: &str, n: usize) -> Result<(&'static [u8], Run, Vec<Value>)> {
    match scheme {
        "falcon" => {
            let run = falcon_host::batch(n);
            let records = run.advice[1..]
                .as_chunks::<201>()
                .0
                .iter()
                .map(|record| {
                    let mut key = vec![9u8];
                    key.extend(record[..112].iter().flat_map(|w| w.to_be_bytes()));
                    let msg: Vec<u8> = record[112..116]
                        .iter()
                        .flat_map(|w| w.to_le_bytes())
                        .collect();
                    json!({"public_key":hex(&key),"message":hex(&msg)})
                })
                .collect();
            Ok((falcon_host::ELF, run, records))
        }
        "fors" => {
            let (run, records) = fors_host::batch_with_records(0, n);
            let public=records.iter().map(|r|json!({"seed":hex(&fors_host::bytes(&r.header[0])),"root":hex(&fors_host::bytes(&r.header[1])),"message":hex(&fors_host::bytes(&r.header[2]))})).collect();
            Ok((fors_host::ELF, run, public))
        }
        "mldsa" => {
            let records: Vec<_> = (0..n).map(mldsa_riscv_host::record).collect();
            let public=records.iter().map(|r|json!({"public_key":hex(&r.public.public_key),"message":hex(&r.public.message)})).collect();
            Ok((
                mldsa_riscv_host::ELF,
                mldsa_riscv_host::run_from_records(&records),
                public,
            ))
        }
        _ => Err(format!("unsupported scheme {scheme}").into()),
    }
}
fn elf_for(scheme: &str) -> Result<&'static [u8]> {
    match scheme {
        "falcon" => Ok(falcon_host::ELF),
        "fors" => Ok(fors_host::ELF),
        "mldsa" => Ok(mldsa_riscv_host::ELF),
        _ => Err("unsupported scheme".into()),
    }
}
fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let action = args.next().ok_or("expected measure, prove, or verify")?;
    let mut opts = BTreeMap::new();
    while let Some(k) = args.next() {
        if ![
            "--scheme",
            "--n",
            "--out",
            "--repeat",
            "--warmup",
            "--rate",
            "--threads",
            "--proof",
            "--statement",
            "--expect-statement-sha256",
            "--expect-elf-sha256",
        ]
        .contains(&k.as_str())
        {
            return Err(format!("unknown flag {k}").into());
        }
        let v = args.next().ok_or("missing option value")?;
        if opts.insert(k, v).is_some() {
            return Err("duplicate option".into());
        }
    }
    let get = |k: &str| {
        opts.get(k)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {k}"))
    };
    let number =
        |k: &str, d: usize| -> Result<usize> { Ok(opts.get(k).map_or(Ok(d), |s| s.parse())?) };
    let scheme = get("--scheme")?;
    let out = get("--out")?;
    let threads = number("--threads", 8)?;
    if threads == 0 {
        return Err("threads must be positive".into());
    }
    parallel::init_with_threads(std::num::NonZeroUsize::new(threads).unwrap())
        .map_err(|e| format!("thread pool: {e:?}"))?;
    let repeat = number("--repeat", 3)?;
    let warmup = number("--warmup", 1)?;
    if repeat == 0 {
        return Err("repeat must be positive".into());
    }
    let rate = Rate::new(number("--rate", 1)?.try_into()?).map_err(|e| format!("rate: {e:?}"))?;
    let mut report = json!({"schema":1,"action":action,"scheme":scheme,"leanvm_revision":REVISION,
      "threads":threads,"log_inverse_rate":rate.log_inv_rate(),"zero_knowledge":false,
      "os":std::env::consts::OS,"arch":std::env::consts::ARCH});
    if action == "verify" {
        let statement_bytes = fs::read(get("--statement")?)?;
        if hash(&statement_bytes) != get("--expect-statement-sha256")? {
            return Err("intended statement hash mismatch".into());
        }
        let s: Statement = serde_json::from_slice(&statement_bytes)?;
        let elf = elf_for(scheme)?;
        if s.schema != 1
            || s.scheme != scheme
            || s.count == 0
            || s.count != s.public_records.len()
            || s.expected_output != expected(scheme, &s.public_records)?
            || hash(elf) != get("--expect-elf-sha256")?
            || s.elf_sha256 != hash(elf)
        {
            return Err("trusted program/statement mismatch".into());
        }
        let program = Program::from_elf(elf)?;
        let bytes = fs::read(get("--proof")?)?;
        let mut times = Vec::new();
        for i in 0..warmup + repeat {
            let t = Instant::now();
            let proof = Proof::from_bytes(&bytes)?;
            program.verify(Output::new(s.expected_output), &proof)?;
            if i >= warmup {
                times.push(t.elapsed().as_secs_f64());
            }
        }
        report["verify_s"] = json!(times);
        report["verified"] = json!(true);
        report["count"] = json!(s.count);
        report["proof_bytes"] = json!(bytes.len());
        report["verify_median_s"] = json!(median(&times));
    } else {
        let n = number("--n", 1)?;
        if n == 0 {
            return Err("count must be positive".into());
        }
        let now = Instant::now();
        let (elf, run, public_records) = fixture(scheme, n)?;
        if run.expected != expected(scheme, &public_records)? {
            return Err("host public claim mismatch".into());
        }
        report["fixture_s"] = json!(now.elapsed().as_secs_f64());
        report["count"] = json!(n);
        report["advice_words"] = json!(run.advice.len());
        report["elf_sha256"] = json!(hash(elf));
        let now = Instant::now();
        let program = Program::from_elf(elf)?;
        report["program_load_s"] = json!(now.elapsed().as_secs_f64());
        let now = Instant::now();
        match program.measure(&run.advice) {
            Ok(stats) => report["execution"] = stats_json(&stats),
            Err(e) => {
                report["status"] = json!("rejected");
                report["error"] = json!(format!("{e:?}"));
                report["measure_s"] = json!(now.elapsed().as_secs_f64());
                if action == "prove" {
                    let t = Instant::now();
                    match Prover::new(rate).prove(&program, &run.advice) {
                        Ok(_) => {
                            return Err("measure refused a run that the prover accepted".into());
                        }
                        Err(error) => {
                            report["prover_error"] = json!(format!("{error:?}"));
                            report["prover_rejection_s"] = json!(t.elapsed().as_secs_f64());
                        }
                    }
                }
                report["peak_rss_bytes"] = json!(bench::peak_rss_bytes());
                save(out, &report)?;
                println!("{}", report);
                return Ok(());
            }
        }
        report["measure_s"] = json!(now.elapsed().as_secs_f64());
        if action == "prove" {
            let prover = Prover::new(rate);
            let mut pts = Vec::new();
            let mut vts = Vec::new();
            let mut sizes = Vec::new();
            let mut last = None;
            for i in 0..warmup + repeat {
                let t = Instant::now();
                let made = prover.prove(&program, &run.advice)?;
                let pt = t.elapsed().as_secs_f64();
                if made.output != run.expected {
                    return Err("guest output disagrees with independently prepared claims".into());
                }
                let bytes = made.proof.to_bytes();
                let t = Instant::now();
                let decoded = Proof::from_bytes(&bytes)?;
                program.verify(Output::new(run.expected), &decoded)?;
                let vt = t.elapsed().as_secs_f64();
                if i >= warmup {
                    pts.push(pt);
                    vts.push(vt);
                    sizes.push(bytes.len());
                }
                last = Some(bytes);
            }
            let bytes = last.unwrap();
            let proof_path = get("--proof")?;
            if let Some(parent) = Path::new(proof_path).parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(proof_path, &bytes)?;
            let statement = Statement {
                schema: 1,
                scheme: scheme.to_owned(),
                count: n,
                elf_sha256: hash(elf),
                expected_output: run.expected,
                public_records,
            };
            let statement_path = format!("{proof_path}.statement.json");
            save(&statement_path, &statement)?;
            report["statement_sha256"] = json!(hash(&fs::read(&statement_path)?));
            report["prove_s"] = json!(pts);
            report["verify_s"] = json!(vts);
            report["prove_median_s"] = json!(median(&pts));
            report["verify_median_s"] = json!(median(&vts));
            report["proof_bytes_samples"] = json!(sizes);
            report["proof_bytes"] = json!(bytes.len());
            report["verified"] = json!(true);
            report["warmup"] = json!(warmup);
        } else if action != "measure" {
            return Err("unknown action".into());
        }
        report["status"] = json!("accepted");
    }
    report["peak_rss_bytes"] = json!(bench::peak_rss_bytes());
    save(out, &report)?;
    println!("{}", report);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1)
    }
}
