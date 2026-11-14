//! Unchanged backend, unmerged PR605 software kernel, exact same FORS relation.
use leanvm::{Machine, Program};
use leanvm_guest::PublicValues;
use serde_json::json;
use sha2::{Digest,Sha256};
use std::{fs,path::PathBuf};

fn sha(bytes:&[u8])->String{Sha256::digest(bytes).iter().map(|b|format!("{b:02x}")).collect()}
fn execute(program:&Program, advice:&[u64])->Result<[u64;4],leanvm::Trap>{Machine::new(program.rv(),advice).run()}

fn main(){
 let base=PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_owned();
 let elf=fs::read(base.join("guest/target/riscv64im-unknown-none-elf/release/fors-registers")).unwrap();
 let program=Program::from_elf(&elf).unwrap();
 let kernel=fs::read(base.join("kernel-guest/target/riscv64im-unknown-none-elf/release/keccak-state-check")).unwrap();
 let kernel_program=Program::from_elf(&kernel).unwrap();

 // All1600 bit basis states, zero, allones and128 pseudorandomfullstates.
 // Assembly is exercised by the actual RISC-V interpreter. The oracle is the
 // original SDK Rust permutation executed natively, never this assembly.
 let states=1600+2+128;
 let mut advice=vec![states as u64];let mut expected=PublicValues::new();expected.commit(&(states as u64));
 let mut random=0x6a09e667f3bcc909u64;
 for case in 0..states {
   let mut state=std::array::from_fn(|i|{
     random^=random<<13;random^=random>>7;random^=random<<17;
     match case{0=>0,1=>u64::MAX,2..1602=>if i==(case-2)/64{1u64<<((case-2)%64)}else{0},_=>random}
   });
   advice.extend(state);leanvm_guest::keccak::f1600(&mut state);expected.commit(&state);
 }
 assert_eq!(execute(&kernel_program,&advice),Ok(expected.digest()),"assembly must match all25 lanes for every state");

 let first=fors_host::batch(1);assert_eq!(execute(&program,&first.advice),Ok(first.expected));
 let mut negative_cases=Vec::new();
 for tree in 0..16 {for level in 0..9 {
   let mut bad=first.advice.clone();let word=1+12+tree*36+level*4+(tree+level)%4;
   bad[word]^=1u64<<((tree*7+level*11)%64);
   assert!(execute(&program,&bad).is_err(),"tree{tree},level{level}");
   negative_cases.push(format!("opening-{tree}-{level}"));
 }}
 for word in 0..12 {let mut bad=first.advice.clone();bad[1+word]^=1<<63;assert!(execute(&program,&bad).is_err());negative_cases.push(format!("public-{word}"));}
 for count in [0,446,u64::MAX] {let mut bad=first.advice.clone();bad[0]=count;assert!(execute(&program,&bad).is_err());negative_cases.push(format!("count-{count}"));}
 let mut bad=first.advice.clone();bad[0]=2;assert!(execute(&program,&bad).is_err());negative_cases.push("underfilled-count-two".into());
 let mut bad=first.advice.clone();for i in 0..36{bad.swap(13+i,13+36+i);}assert!(execute(&program,&bad).is_err());negative_cases.push("swapped-tree-openings".into());
 assert!(execute(&program,&first.advice[..first.advice.len()-4]).is_err());negative_cases.push("truncated-last-sibling".into());

 let mut measurements=Vec::new();
 for n in [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,20,24] {
   let run=fors_host::batch(n);
   assert_eq!(execute(&program,&run.advice),Ok(run.expected),"honest full executionn{n}");
   let measurement=match program.measure(&run.advice){
     Ok(s)=>json!({"count":n,"status":"fits","cycles":s.cycles(),"committed_words":s.committed,"rows":s.base_counts.iter().map(|(t,n)|(t.name(),*n)).collect::<std::collections::BTreeMap<_,_>>(),"padded_rows":s.counts.iter().map(|(t,n)|(t.name(),*n)).collect::<std::collections::BTreeMap<_,_>>()}),
     Err(e)=>json!({"count":n,"status":"rejected","error":format!("{e:?}")})
   };
   println!("{measurement}");measurements.push(measurement);
 }
 let report=json!({"backend_revision":"06e5c9cd6981103786f9d0a17324241b559a50d3","pr605_head":"c67701c037c11d229c563671419ccc48827b5c2d","pr605_merged":false,"elf_sha256":sha(&elf),"kernel_elf_sha256":sha(&kernel),"full_state_vm_differentials":states,"negative_vm_controls":negative_cases,"negative_vm_all_rejected":true,"measurements":measurements,"scope":"Interpreter+productionProgram::measure only. Not proof production. SameKeccak256/FORSprofile, unchanged cap and verifier."});
 fs::write(base.join("probe-results.json"),serde_json::to_vec_pretty(&report).unwrap()).unwrap();
 println!("state checks:{states},negative checks:{}",negative_cases.len());
}
