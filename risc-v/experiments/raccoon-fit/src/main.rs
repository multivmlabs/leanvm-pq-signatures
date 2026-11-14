//! Review-only exact public-size diagnostic, with a separate optional proof mode.
//!
//! Runs the unchanged guest on the unchanged raw interpreter to completion,
//! without Program::run's allocation guard, then reproduces its public fill and
//! column-size rules. Production Program::measure is called separately, unchanged.
//! The optional `prove` argument uses the unchanged production Prover and verifier;
//! diagnostic counts never bypass a production check or become a proof.
use leanvm::{CircuitId, Class, Machine, Part, PerTable, Program, TableId, Word};
use leanvm_guest::{PublicValues, Run};
use serde_json::{json, Value};
use sha2::{Digest,Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs, path::Path};

#[global_allocator]
static ALLOCATOR: bench::Counting<bench::Jemalloc> = bench::Counting(bench::Jemalloc);

const CAP: usize = 1 << 28;

fn height(t: TableId, n: usize) -> usize { t.spec().provable_height(n) }
fn register_bits(t: TableId) -> usize {
    let s=t.spec();5 + usize::from(s.reads_rs2)*5 + if s.writes_rd {6} else if s.reads_rd {5} else {0}
}
fn normalize(t:TableId,w:Word)->Option<String>{
    match (t.class(),w) {
        (_,Word::HintQ|Word::HintR)=>None,
        (Class::Ld, Word::Out|Word::CellNew(0))=>Some("Cell(0)".into()),
        (Class::Load, Word::CellNew(0))=>Some("Cell(0)".into()),
        (Class::Sd,Word::CellNew(0))=>Some("V2".into()),
        (Class::Hash,Word::CellNew(k)) if !(4..8).contains(&k)=>Some(format!("Cell({k})")),
        _=>Some(format!("{w:?}"))
    }
}
fn coefficients()->PerTable<usize>{
    PerTable::from_fn(|t:TableId|{
        let table=t.class_table();
        let mut ports=BTreeSet::new();
        for part in [Part::Class,Part::Clock] {
            if part==Part::Class && CircuitId::class(t).is_none(){continue;}
            for &w in table.ports(part){if let Some(key)=normalize(t,w){ports.insert(key);}}
        }
        let s=t.spec();
        let registers=1+usize::from(s.reads_rs2)+usize::from(s.writes_rd||s.reads_rd);
        table.n_committed_columns().checked_sub(ports.len()+registers).expect("disjoint ports and register columns")
    })
}
fn size(p:&Program, heights:&PerTable<usize>)->(usize,Value){
    // Shared::ALL: two register, two RAM, three advice, one bytecode multiplicity.
    // RegisterFile::LOG_CELLS is six; word heights are public program metadata.
    let shared=2*64+2*(1usize<<p.rv().log_ram())+3*(1usize<<p.rv().log_advice())+p.rv().entries().len();
    let direct_coeff=coefficients();
    let mut table_parts=BTreeMap::new();
    let packed:usize=CircuitId::ALL.iter().map(|f| heights[f.table()]<<f.stride_log()).sum();
    let direct:usize=TableId::ALL.iter().map(|&t| heights[t]*direct_coeff[t]).sum();
    for t in TableId::ALL {
        let packed_t:usize=CircuitId::class(t).into_iter().chain([CircuitId::clock(t)]).map(|f|heights[t]<<f.stride_log()).sum();
        table_parts.insert(t.name(),json!({"height":heights[t],"direct_columns":direct_coeff[t],"direct_words":heights[t]*direct_coeff[t],"packed_words":packed_t,"register_bits":register_bits(t)}));
    }
    // RegisterWord::of: first-fit, protocol order, grouping only equal heights.
    let mut groups:Vec<(usize,usize,Vec<&str>)>=Vec::new();
    for t in TableId::ALL {
        let bits=register_bits(t);
        if let Some((_,used,tables))=groups.iter_mut().find(|(h,used,_)|*h==heights[t]&&*used+bits<=64){*used+=bits;tables.push(t.name());}
        else{groups.push((heights[t],bits,vec![t.name()]));}
    }
    let registers:usize=groups.iter().map(|g|g.0).sum();
    let total=shared+packed+direct+registers;
    (total,json!({"shared_words":shared,"packed_words":packed,"direct_words":direct,"register_words":registers,"register_groups":groups,"tables":table_parts,"committed_words":total,"mu":total.max(1).next_power_of_two().trailing_zeros().max(leanvm::MIN_MU as u32),"fits":total<=CAP}))
}
fn fill(counts:PerTable<usize>)->(PerTable<usize>,usize){
    // Exact Plan::solve: greedily deliver gaps with blocks 128,64,...,1;
    // one ALU jump per traversal. ALU's own padding is then solved separately.
    let mut out=counts;
    let mut jumps=0;
    for t in TableId::ALL.into_iter().filter(|&t|t!=TableId::ALU){
        let target=height(t,counts[t]);let mut left=target-counts[t];
        for block in [128,64,32,16,8,4,2,1]{let n=left/block;left-=n*block;jumps+=n;}
        assert_eq!(left,0);out[t]=target;
    }
    // landing_on_jump fills exactly to the ALU height, including its own jumps.
    out[TableId::ALU]=height(TableId::ALU,counts[TableId::ALU]+jumps);
    (out,jumps)
}
fn rows(counts:&PerTable<usize>)->BTreeMap<&'static str,usize>{counts.iter().map(|(t,&n)|(t.name(),n)).collect()}
fn fixture(scheme:&str,n:usize,start:usize)->(&'static[u8],Run){
    match scheme{
        "falcon"=>{
            let all=falcon_host::batch(start+n);
            let record=&all.advice[1+start*201..];
            assert_eq!(record.len(),n*201);
            let mut advice=vec![n as u64];advice.extend(record);
            let mut public=PublicValues::new();
            for r in record.chunks_exact(201){let key:[u64;112]=r[..112].try_into().unwrap();let message:[u64;4]=r[112..116].try_into().unwrap();public.commit(&key).commit(&message);}
            (falcon_host::ELF,Run{advice,expected:public.digest()})
        },
        "mldsa"=>(mldsa_riscv_host::ELF,mldsa_riscv_host::batch_range(start,n)),
        "raccoon"=>(raccoon_riscv_host::ELF,raccoon_riscv_host::batch_range(start,n)),
        "raccoon-g"=>(raccoong_riscv_host::ELF,raccoong_riscv_host::batch_range(start,n)),
        "fors"=>(fors_host::ELF,fors_host::batch_range(start,n)),
        _=>panic!("unknown scheme")
    }
}
fn main(){
    let args:Vec<String>=std::env::args().collect();
    if args.get(5).is_some_and(|x|x=="prove") {
        assert_eq!(args[1],"falcon","saved-public-statement export is implemented for Falcon only");
        parallel::init_with_threads(std::num::NonZeroUsize::new(8).unwrap()).unwrap();
    }
    if args[1]=="export-falcon" {
        let count:usize=args[2].parse().unwrap();let run=falcon_host::batch(count);
        let bytes:Vec<u8>=run.advice.iter().flat_map(|w|w.to_le_bytes()).collect();fs::write(&args[3],bytes).unwrap();
        println!("Exported {count} unchanged upstream corpus records");return;
    }
    if args[1]=="check-reports" {
        let root=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");let mut checked=0;
        for entry in fs::read_dir(root.join("risc-v/results/direct")).unwrap(){
            let path=entry.unwrap().path();if path.extension().is_none_or(|x|x!="json"){continue;}
            let report:Value=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();if report["verified"]!=true{continue;}
            let elf=match report["scheme"].as_str().unwrap(){"falcon"=>falcon_host::ELF,"mldsa"=>mldsa_riscv_host::ELF,"fors"=>fors_host::ELF,_=>panic!()};
            let p=Program::from_elf(elf).unwrap();let heights=PerTable::from_fn(|t:TableId|report["execution"]["padded_rows"][t.name()].as_u64().unwrap() as usize);
            let (words,_)=size(&p,&heights);assert_eq!(words,report["execution"]["committed_words"].as_u64().unwrap() as usize,"{}",path.display());checked+=1;
        }
        println!("Exact public-layout replica matches {checked} production reports");return;
    }
    if args[1]=="scan-falcon" {
        let count:usize=args[2].parse().unwrap();let all=falcon_host::batch(count);let p=Program::from_elf(falcon_host::ELF).unwrap();let tables:Vec<_>=p.rv().entries().iter().map(|e|TableId::of(e.class)).collect();
        let mut out=Vec::new();
        for (index,record) in all.advice[1..].chunks_exact(201).enumerate(){
            let mut advice=vec![1];advice.extend(record);let mut m=Machine::new(p.rv(),&advice);let mut counts=PerTable::<usize>::default();
            while !m.halted(){let step=m.step().unwrap();counts[tables[step.index].unwrap()]+=1;}
            out.push(json!({"index":index,"rows":rows(&counts),"cycles":counts.values().sum::<usize>()}));
        }
        fs::write(&args[3],serde_json::to_vec_pretty(&out).unwrap()).unwrap();println!("Scanned {count} valid upstream records individually");return;
    }
    let scheme=&args[1];let n:usize=args[2].parse().unwrap();let start:usize=args[3].parse().unwrap();let output=&args[4];
    let (original_elf,run)=fixture(scheme,n,start);
    let override_elf=args.get(5).filter(|s|s.as_str()!="prove").map(|path|fs::read(path).unwrap());
    let elf=override_elf.as_deref().unwrap_or(original_elf);let p=Program::from_elf(elf).unwrap();
    let mut m=Machine::new(p.rv(),&run.advice);let tables:Vec<_>=p.rv().entries().iter().map(|e|TableId::of(e.class)).collect();
    let mut counts=PerTable::<usize>::default();let mut checks=Vec::new();let mut max_words=0;let mut steps=0usize;
    // Addresses from the pinned ELF symbol table, recorded in falcon-symbols.json.
    let mut keccak_calls=0usize;let mut keccak_rows=PerTable::<usize>::default();
    while !m.halted(){
        // Program::run checks before the cycle numbered 65536, 131072, ...
        if (steps+1).is_multiple_of(1<<16){
            let heights=PerTable::from_fn(|t|height(t,counts[t]));let (words,detail)=size(&p,&heights);max_words=max_words.max(words);
            checks.push(json!({"next_cycle":steps+1,"words":words,"fits":words<=CAP,"detail":detail}));
        }
        let keccak_start=args.get(6).map(|v|u64::from_str_radix(v.trim_start_matches("0x"),16).unwrap()).unwrap_or_else(||match scheme.as_str(){"raccoon"=>0x100005bc,"raccoon-g"=>0x100021c4,_=>268442604});
        let pc=m.pc();if pc==keccak_start{keccak_calls+=1;}
        let step=m.step().unwrap();let t=tables[step.index].unwrap();counts[t]+=1;steps+=1;
        if (keccak_start..keccak_start+2448).contains(&pc){keccak_rows[t]+=1;}
        assert!(steps<50_000_000,"diagnostic guard");
    }
    assert_eq!(m.output().unwrap(),run.expected,"honest guest completed and binds expected claims");
    let natural=PerTable::from_fn(|t|height(t,counts[t]));let (filled,jumps)=fill(counts);
    let (words,details)=size(&p,&filled);let (_,natural_details)=size(&p,&natural);
    let production=match p.measure(&run.advice){Ok(s)=>{assert_eq!(s.base_counts,counts);assert_eq!(s.counts,filled);assert_eq!(s.committed,words);json!({"accepted":true,"committed_words":s.committed})},Err(e)=>json!({"accepted":false,"error":format!("{e:?}")})};
    let elf_sha256=Sha256::digest(elf).iter().map(|b|format!("{b:02x}")).collect::<String>();
    let mut report=json!({"elf_sha256":elf_sha256,"scheme":scheme,"n":n,"start":start,"scope":"Unchanged raw interpreter + owned exact public-layout replica. Diagnostic counts only; production proving is separate and never bypasses its checks.","base_rows":rows(&counts),"filled_rows":rows(&filled),"fill_external_jumps":jumps,"final":details,"natural_final":natural_details,"max_periodic_words":max_words,"periodic_checks":checks,"production_measure":production,"cycles":steps,"guest_output":run.expected});
    if ["falcon","raccoon","raccoon-g"].contains(&scheme.as_str()){report["keccak_permutation_calls"]=json!(keccak_calls);report["keccak_function_rows"]=json!(rows(&keccak_rows));let (kf,kj)=fill(keccak_rows);let (_,kd)=size(&p,&kf);report["keccak_only_lower_bound"]=kd;report["keccak_only_external_jumps"]=json!(kj);}
    if let Some(parent)=Path::new(output).parent(){fs::create_dir_all(parent).unwrap();}
    if args.get(5).is_some_and(|x|x=="prove") {
        parallel::init_with_threads(std::num::NonZeroUsize::new(8).unwrap()).unwrap();
        let now=std::time::Instant::now();let made=leanvm::Prover::new(leanvm::Rate::MIN).prove(&p,&run.advice).expect("unchanged production prover");let proving_s=now.elapsed().as_secs_f64();
        assert_eq!(made.output,run.expected);
        let encoded=made.proof.to_bytes();let decoded=leanvm::Proof::from_bytes(&encoded).unwrap();let now=std::time::Instant::now();p.verify(leanvm::Output::new(run.expected),&decoded).unwrap();let verifying_s=now.elapsed().as_secs_f64();
        let mut wrong=run.expected;wrong[0]^=1;assert!(p.verify(leanvm::Output::new(wrong),&decoded).is_err());
        let artifact=Path::new(output).with_extension("proof");fs::write(&artifact,&encoded).unwrap();
        let advice:Vec<u8>=run.advice.iter().flat_map(|w|w.to_le_bytes()).collect();fs::write(Path::new(output).with_extension("advice.bin"),&advice).unwrap();
        let hex=|bytes:&[u8]|->String{bytes.iter().map(|b|format!("{b:02x}")).collect()};
        let public_records:Vec<Value>=run.advice[1..].chunks_exact(201).map(|r|{let mut pk=vec![9u8];pk.extend(r[..112].iter().flat_map(|w|w.to_be_bytes()));let msg:Vec<u8>=r[112..116].iter().flat_map(|w|w.to_le_bytes()).collect();json!({"public_key":hex(&pk),"message":hex(&msg)})}).collect();
        let statement=json!({"schema":1,"scheme":"falcon","count":n,"elf_sha256":hex(&Sha256::digest(elf)),"expected_output":run.expected,"public_records":public_records});
        fs::write(Path::new(output).with_extension("statement.json"),serde_json::to_vec_pretty(&statement).unwrap()).unwrap();
        report["actual_proof"]=json!({"verified":true,"wrong_output_rejected":true,"proof_bytes":encoded.len(),"proving_s":proving_s,"verifying_s":verifying_s,"proof_sha256":hex(&Sha256::digest(&encoded)),"advice_sha256":hex(&Sha256::digest(&advice)),"elf_sha256":hex(&Sha256::digest(elf)),"executable_sha256":hex(&Sha256::digest(fs::read(std::env::current_exe().unwrap()).unwrap())),"peak_rss_bytes":bench::peak_rss_bytes(),"repeat":1,"warmup":0,"threads":8,"rate":1,"scope":"One real unmodified production Prover::prove followed by serialization, decode, full Program::verify and wrong-public-output rejection. Not a three-sample timing benchmark."});
    }
    fs::write(output,serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{scheme} n={n} start={start} cycles={steps} words={words} periodic_max={max_words} production={}",report["production_measure"]);
}
