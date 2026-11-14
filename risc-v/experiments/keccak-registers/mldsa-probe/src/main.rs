//! Same ML-DSA FIPS204 verifier and compact inputs, only the isolated SDK permutation changes.
use leanvm::{Machine,Program};
use serde_json::json;
use sha2::{Digest,Sha256};
use std::{fs,path::PathBuf};
#[global_allocator]
static ALLOCATOR:bench::Counting<bench::Jemalloc>=bench::Counting(bench::Jemalloc);
fn sha(bytes:&[u8])->String{Sha256::digest(bytes).iter().map(|b|format!("{b:02x}")).collect()}
fn execute(p:&Program,a:&[u64])->Result<[u64;4],leanvm::Trap>{Machine::new(p.rv(),a).run()}
fn set_byte(a:&mut [u64], offset:usize,byte:u8){let word=169+offset/8;let shift=8*(offset%8);a[word]=(a[word]&!(255u64<<shift))|((byte as u64)<<shift);}
fn prove(base:&std::path::Path,n:usize){
 assert!(n>0&&n<=256);
 parallel::init_with_threads(std::num::NonZeroUsize::new(8).unwrap()).unwrap();
 let elf=fs::read(base.join("mldsa-registers.elf")).unwrap();let program=Program::from_elf(&elf).unwrap();
 let records=mldsa_riscv_host::records(0,n);let run=mldsa_riscv_host::run_from_records(&records);
 let stem=format!("mldsa-registers-{n}");
 let advice:Vec<u8>=run.advice.iter().flat_map(|w|w.to_le_bytes()).collect();fs::write(base.join(format!("{stem}.advice.bin")),&advice).unwrap();
 let public:Vec<_>=records.iter().map(|r|json!({"public_key":hex(&r.public.public_key),"message":hex(&r.public.message)})).collect();
 let statement=json!({"schema":1,"scheme":"mldsa","count":n,"elf_sha256":sha(&elf),"expected_output":run.expected,"public_records":public});
 fs::write(base.join(format!("{stem}.statement.json")),serde_json::to_vec_pretty(&statement).unwrap()).unwrap();
 let t=std::time::Instant::now();let made=leanvm::Prover::new(leanvm::Rate::MIN).prove(&program,&run.advice);let proving_s=t.elapsed().as_secs_f64();
 let report=match made{
  Ok(made)=>{
   assert_eq!(made.output,run.expected);let bytes=made.proof.to_bytes();fs::write(base.join(format!("{stem}.proof")),&bytes).unwrap();
   let decoded=leanvm::Proof::from_bytes(&bytes).unwrap();let t=std::time::Instant::now();program.verify(leanvm::Output::new(run.expected),&decoded).unwrap();let verify_s=t.elapsed().as_secs_f64();
   let mut wrong:Vec<_>=records.iter().map(|r|r.public.clone()).collect();wrong[0].message[0]^=1;let wrong_output=mldsa_riscv_host::expected_output(&wrong);assert_ne!(wrong_output,run.expected);
   let err=program.verify(leanvm::Output::new(wrong_output),&decoded).expect_err("different intended message must fail unchanged verifier");
   let mut bit_wrong=run.expected;bit_wrong[0]^=1;assert!(program.verify(leanvm::Output::new(bit_wrong),&decoded).is_err());
   json!({"status":"verified","count":n,"elf_sha256":sha(&elf),"advice_sha256":sha(&advice),"proof_sha256":sha(&bytes),"proof_bytes":bytes.len(),"proving_s":proving_s,"verify_s":verify_s,"committed_words":made.stats.committed,"cycles":made.stats.cycles(),"negative_changed_message_rejected":true,"negative_changed_message_error":format!("{err:?}"),"negative_changed_output_bit_rejected":true})
  },Err(e)=>json!({"status":"rejected","count":n,"elf_sha256":sha(&elf),"advice_sha256":sha(&advice),"prover_error":format!("{e:?}"),"elapsed_s":proving_s})
 };
 fs::write(base.join(format!("{stem}.proof-result.json")),serde_json::to_vec_pretty(&report).unwrap()).unwrap();println!("{report}");
}
fn hex(bytes:&[u8])->String{bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn main(){
 let base=PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_owned();
 if std::env::args().nth(1).as_deref()==Some("--prove"){let n=std::env::args().nth(2).unwrap().parse().unwrap();prove(&base,n);return;}
 let elf=fs::read(base.join("mldsa/guest/target/riscv64im-unknown-none-elf/release/mldsa-riscv-guest")).unwrap();
 let program=Program::from_elf(&elf).unwrap();
 let first=mldsa_riscv_host::batch(1);assert_eq!(execute(&program,&first.advice),Ok(first.expected));
 let mut negatives=Vec::new();
 for index in [1,165,169] {let mut bad=first.advice.clone();bad[index]^=1;assert!(execute(&program,&bad).is_err());negatives.push(format!("changed-word-{index}"));}
 let mut bad=first.advice.clone();set_byte(&mut bad,2419,81);assert!(execute(&program,&bad).is_err());negatives.push("hint-boundary".into());
 let mut bad=first.advice.clone();for j in 0..4{set_byte(&mut bad,2416+j,2);}set_byte(&mut bad,2336,0);set_byte(&mut bad,2337,0);assert!(execute(&program,&bad).is_err());negatives.push("duplicate-hints".into());
 let mut bad=first.advice.clone();for j in 0..4{set_byte(&mut bad,2416+j,0);}set_byte(&mut bad,2336,1);assert!(execute(&program,&bad).is_err());negatives.push("unused-hint".into());
 let mut bad=first.advice.clone();set_byte(&mut bad,32,0);set_byte(&mut bad,33,0);let b=((bad[169+34/8]>>(8*(34%8)))&255)as u8;set_byte(&mut bad,34,b&!3);assert!(execute(&program,&bad).is_err());negatives.push("z-bound".into());
 let mut bad=first.advice.clone();bad[169+302]|=1<<32;assert!(execute(&program,&bad).is_err());negatives.push("transport-padding".into());
 let mut bad=first.advice.clone();bad[0]=0;assert!(execute(&program,&bad).is_err());negatives.push("zero-count".into());
 let mut measurements=Vec::new();
 for n in [1,2,3,4,5,6,7,8,9,10,12,16]{
   let run=mldsa_riscv_host::batch(n);assert_eq!(execute(&program,&run.advice),Ok(run.expected));
   let m=match program.measure(&run.advice){
    Ok(s)=>json!({"count":n,"status":"fits","cycles":s.cycles(),"committed_words":s.committed,"rows":s.base_counts.iter().map(|(t,n)|(t.name(),*n)).collect::<std::collections::BTreeMap<_,_>>(),"padded_rows":s.counts.iter().map(|(t,n)|(t.name(),*n)).collect::<std::collections::BTreeMap<_,_>>()}),
    Err(e)=>json!({"count":n,"status":"rejected","error":format!("{e:?}")})
   };println!("{m}");measurements.push(m);
 }
 let report=json!({"backend_revision":"06e5c9cd6981103786f9d0a17324241b559a50d3","pr605_head":"c67701c037c11d229c563671419ccc48827b5c2d","pr605_merged":false,"elf_sha256":sha(&elf),"negative_vm_controls":negatives,"all_negative_vm_rejected":true,"measurements":measurements,"scope":"Actual full interpreter and production Program::measure only. No proof. Same compact FIPS204MLDSA44 pure emptycontext signature relation, backend cap and verifier."});
 fs::write(base.join("mldsa-probe-results.json"),serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}
