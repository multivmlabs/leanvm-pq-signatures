//! Independent review harness. No prover, witness planner, statistics or timers.
use std::{fs,path::Path};
use leanvm::{Machine,Program};
use raccoong_riscv_guest::{PK_BYTES,SIG_BYTES,verify,constants::{Q,ONE,NI,QINV,R2},arithmetic::{Poly,to_montgomery,from_montgomery,forward,inverse,multiply,matrix_poly,challenge},xof::Xof};
use raccoong_riscv_host::{ELF,PublicRecord,Record,expected_output,run_from_records};
use serde_json::json;

fn hex(bytes:&[u8])->String {bytes.iter().map(|x|format!("{x:02x}")).collect()}
fn dump() {
    let mut shakes=Vec::new();
    for rate in [136,168] {
        for len in [0,1,7,8,135,136,137,167,168,169,271,272,273,1024] {
            let input:Vec<u8>=(0..len).map(|i|(i*37+11)as u8).collect();
            let mut x=Xof::new(rate);
            for b in input.chunks(7) {x.update(b)}
            let mut output=vec![0;401];
            for b in output.chunks_mut(11) {x.read(b)}
            shakes.push(json!({"rate":rate,"input":hex(&input),"output":hex(&output)}));
        }
    }
    let seed:[u8;16]=core::array::from_fn(|i|i as u8);
    let hash:[u8;32]=core::array::from_fn(|i|i as u8);
    let mut matrix=Vec::new();
    for row in 0..9 {for col in 0..9 {
        let mut p=[0;256];matrix_poly(&seed,row,col,&mut p);
        matrix.push(p.map(from_montgomery).to_vec());
    }}
    let mut polynomials=Vec::new();
    for name in ["zero","unit","boundary","largest","dense"] {
        let a:Poly=core::array::from_fn(|j|match name {
            "zero"=>0,"unit"=>if j==0{1}else{0},
            "boundary"=>if j==255{1}else{0},"largest"=>Q-1,
            _=>((j as u128+39).pow(7)%(Q as u128))as u64,
        });
        let b:Poly=core::array::from_fn(|j|match name {
            "boundary"=>if j==1{1}else{0},"largest"=>Q-1,
            _=>((j as u128+93).pow(6)%(Q as u128))as u64,
        });
        let mut ah=a.map(to_montgomery);let mut bh=b.map(to_montgomery);
        forward(&mut ah);forward(&mut bh);
        let forward_values=ah.map(from_montgomery);
        let mut roundtrip=ah;inverse(&mut roundtrip);
        let mut product=core::array::from_fn(|i|multiply(ah[i],bh[i]));inverse(&mut product);
        polynomials.push(json!({"name":name,"a":a.to_vec(),"b":b.to_vec(),"forward":forward_values.to_vec(),"roundtrip":roundtrip.map(from_montgomery).to_vec(),"product":product.map(from_montgomery).to_vec()}));
    }
    println!("{}",json!({"shakes":shakes,"seed":hex(&seed),"challenge_hash":hex(&hash),"challenge":challenge(&hash).map(from_montgomery).to_vec(),"matrix":matrix,"polynomials":polynomials,"montgomery":{"Q":Q,"ONE":ONE,"NI":NI,"QINV":QINV,"R2":R2}}));
}
fn run(directory:&str) {
    let mut paths:Vec<_>=fs::read_dir(Path::new(directory)).unwrap().map(|p|p.unwrap().path()).filter(|p|p.extension().is_some_and(|e|e=="bin")).collect();paths.sort();
    for path in paths {
        let bytes=fs::read(&path).unwrap();assert_eq!(bytes.len()%(PK_BYTES+32+SIG_BYTES),0);
        let records:Vec<_>=bytes.chunks_exact(PK_BYTES+32+SIG_BYTES).map(|b|Record{public:PublicRecord{public_key:b[..PK_BYTES].try_into().unwrap(),message:b[PK_BYTES..PK_BYTES+32].try_into().unwrap()},signature:b[PK_BYTES+32..].try_into().unwrap()}).collect();
        let native=records.iter().all(|r|verify(&r.public.public_key,&r.public.message,&r.signature));
        let run=run_from_records(&records);let program=Program::from_elf(ELF).unwrap();let result=Machine::new(program.rv(),&run.advice).run();
        let public:Vec<_>=records.iter().map(|r|r.public.clone()).collect();
        let expected=hex(&expected_output(&public).iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>());
        let output=match result{Ok(x)=>hex(&x.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>()),Err(e)=>format!("TRAP:{e:?}")};
        println!("{}\tnative={}\toutput={}\texpected={}",path.file_name().unwrap().to_string_lossy(),native,output,expected);
    }
}
fn main(){let args:Vec<_>=std::env::args().collect();match args.get(1).map(String::as_str){Some("dump")=>dump(),Some("run")=>run(args.get(2).expect("vector directory")),_=>panic!("dump | run DIR")}}
