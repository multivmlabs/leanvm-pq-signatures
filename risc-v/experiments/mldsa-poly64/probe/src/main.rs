use leanvm::{Machine, Output, Program, Proof, Prover, Rate, TableId};
use serde_json::json;
use sha2::{Digest,Sha256};
use std::{collections::BTreeMap,fs};
#[global_allocator]
static ALLOCATOR:bench::Jemalloc=bench::Jemalloc;
const HERE:&str="risc-v/experiments/mldsa-poly64";
fn hash(bytes:&[u8])->String {Sha256::digest(bytes).iter().map(|x|format!("{x:02x}")).collect()}
fn hex(bytes:&[u8])->String {bytes.iter().map(|x|format!("{x:02x}")).collect()}
fn unhex(s:&str)->Vec<u8> {(0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).unwrap()).collect()}

fn main(){
 if matches!(std::env::args().nth(1).as_deref(),Some("--prove7"|"--reject8")) {
  parallel::init_with_threads(std::num::NonZeroUsize::new(8).unwrap()).unwrap();
 }
 let bytes=fs::read("risc-v/experiments/mldsa-poly64/twiddle64.elf").unwrap();
 if std::env::args().nth(1).as_deref()==Some("--dump-elf") {
  use std::io::Write;std::io::stdout().write_all(&bytes).unwrap();return;
 }
 let program=Program::from_elf(&bytes).unwrap();
 assert_eq!(hash(&bytes),"8d1a19b35874db7c3ffff15e851d0312a97c6c9b370ce58c300b674ac57922ee");
 if std::env::args().nth(1).as_deref()==Some("--reject8") {
  let input=mldsa_riscv_host::batch(8);
  let result=Prover::new(Rate::MIN).prove(&program,&input.advice);
  assert!(matches!(result,Err(leanvm::ProveError::TooLong)));
  let report=json!({"count":8,"actual_prover_attempt":true,"result":"TooLong","guest_sha256":hash(&bytes),"no_proof_produced":true,"threads":8,"log_inverse_rate":1});
  fs::write(format!("{HERE}/capacity-next.json"),serde_json::to_vec_pretty(&report).unwrap()).unwrap();println!("{report}");return;
 }
 if std::env::args().nth(1).as_deref()==Some("--prove7") {
  let records=mldsa_riscv_host::records(0,7);
  let run=mldsa_riscv_host::run_from_records(&records);
  let expected=Output::new(run.expected);
  fs::write(format!("{HERE}/capacity-advice.bin"),run.advice.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>()).unwrap();
  let public:Vec<_>=records.iter().map(|r|json!({"public_key":hex(&r.public.public_key),"message":hex(&r.public.message)})).collect();
  let manifest=json!({"profile":"ML-DSA-44,pure,emptycontext,compact1312/2420,32Bmessage","count":7,"expected_output":run.expected,"elf_sha256":hash(&bytes),"public_records":public});
  fs::write(format!("{HERE}/capacity-public.json"),serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
  let start=std::time::Instant::now();
  let made=Prover::new(Rate::MIN).prove(&program,&run.advice).expect("unchanged backend must really produce a proof");
  let proving=start.elapsed().as_secs_f64();
  assert_eq!(made.output,expected);
  let wire=made.proof.to_bytes();fs::write(format!("{HERE}/capacity-7.proof"),&wire).unwrap();
  let decoded=Proof::from_bytes(&wire).unwrap();
  program.verify(expected,&decoded).expect("full verify including deferred checks");
  let mut wrong=run.expected;wrong[0]^=1;
  let wrong_output_rejected=program.verify(Output::new(wrong),&decoded).is_err();assert!(wrong_output_rejected);
  let baseline_bytes=fs::read(format!("{HERE}/baseline.elf")).unwrap();
  let baseline=Program::from_elf(&baseline_bytes).unwrap();
  let baseline_program_rejected=baseline.verify(expected,&decoded).is_err();assert!(baseline_program_rejected);
  let report=json!({"scope":"One fresh capacity-confirmation proof, not a repeated timing benchmark","count":7,"backend_revision":"06e5c9cd6981103786f9d0a17324241b559a50d3","guest_sha256":hash(&bytes),"baseline_guest_sha256":hash(&baseline_bytes),"log_inverse_rate":1,"threads":8,"prove_s":proving,"proof_bytes":wire.len(),"proof_sha256":hash(&wire),"cycles":made.stats.cycles(),"committed_words":made.stats.committed,"serialized_decoded_full_verify":true,"wrong_output_rejected":wrong_output_rejected,"baseline_program_substitution_rejected":baseline_program_rejected,"peak_rss_bytes":bench::peak_rss_bytes()});
  fs::write(format!("{HERE}/capacity-proof.json"),serde_json::to_vec_pretty(&report).unwrap()).unwrap();println!("{report}");return;
 }
 if std::env::args().nth(1).as_deref()==Some("--verify7") {
  let manifest:serde_json::Value=serde_json::from_slice(&fs::read(format!("{HERE}/capacity-public.json")).unwrap()).unwrap();
  assert_eq!(manifest["elf_sha256"].as_str().unwrap(),hash(&bytes));
  let records:Vec<_>=manifest["public_records"].as_array().unwrap().iter().map(|r|mldsa_riscv_host::PublicRecord{public_key:unhex(r["public_key"].as_str().unwrap()).try_into().unwrap(),message:unhex(r["message"].as_str().unwrap()).try_into().unwrap()}).collect();
  assert_eq!(records.len(),7);assert_eq!(manifest["count"].as_u64(),Some(7));
  let output=mldsa_riscv_host::expected_output(&records);
  let recorded:Vec<u64>=manifest["expected_output"].as_array().unwrap().iter().map(|v|v.as_u64().unwrap()).collect();assert_eq!(output.as_slice(),recorded.as_slice());
  let proof=Proof::from_bytes(&fs::read(format!("{HERE}/capacity-7.proof")).unwrap()).unwrap();
  program.verify(Output::new(output),&proof).unwrap();
  let report=json!({"public_only_full_verify":true,"count":7,"elf_sha256":hash(&bytes),"public_output_recomputed":true});
  fs::write(format!("{HERE}/capacity-consumer.json"),serde_json::to_vec_pretty(&report).unwrap()).unwrap();println!("{report}");return;
 }
 if let Some(path)=std::env::args().nth(1){
  let raw=fs::read(path).unwrap();assert!(raw.len().is_multiple_of(8));
  let advice:Vec<_>=raw.chunks_exact(8).map(|c|u64::from_le_bytes(c.try_into().unwrap())).collect();
  match Machine::new(program.rv(),&advice).run(){
   Ok(out)=>println!("{}",out.map(|w|format!("{w:016x}")).join("")),
   Err(e)=>{eprintln!("guest rejected: {e:?}");std::process::exit(1)}
  }return;
 }
 let baseline=Program::from_elf(mldsa_riscv_host::ELF).unwrap();
 let hash:String=Sha256::digest(&bytes).iter().map(|x|format!("{x:02x}")).collect();
 let mut reports=Vec::new();
 for n in [1usize,6,7,8,9]{
  let run=mldsa_riscv_host::batch(n);
  let mut rows=BTreeMap::<&str,usize>::new();
  let mut machine=Machine::new(program.rv(),&run.advice);
  while !machine.halted(){let step=machine.step().unwrap();let class=program.rv().entries()[step.index].class;*rows.entry(TableId::of(class).unwrap().name()).or_default()+=1;}
  assert_eq!(machine.output().unwrap(),run.expected,"n{n}");
  let measure=program.measure(&run.advice);
  let original=baseline.measure(&run.advice);
  let row=json!({"count":n,"output_matches":true,"rows":rows,"cycles":rows.values().sum::<usize>(),"committed_words":measure.as_ref().ok().map(|s|s.committed),"measure_error":measure.err().map(|e|format!("{e:?}")),"baseline_committed_words":original.as_ref().ok().map(|s|s.committed),"baseline_error":original.err().map(|e|format!("{e:?}"))});
  println!("{row}");reports.push(row);
 }
 let report=json!({"guest_sha256":hash,"scope":"Full actual RISC-V guest execution and measure only, no STARK production","cases":reports});
 fs::write("risc-v/experiments/mldsa-poly64/measurements.json",serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}
