//! Read-only independent execution controls. This never invokes a prover or timer.
use std::{fs, path::Path};
use leanvm::{Machine, Program};
use raccoon_riscv_host::{ELF, PublicRecord, Record, expected_output, run_from_records};
use raccoon_riscv_guest::{PK_BYTES, SIG_BYTES, verify};

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|x|format!("{x:02x}")).collect() }

fn main() {
    let directory = std::env::args().nth(1).expect("control vector directory");
    let mut paths: Vec<_> = fs::read_dir(Path::new(&directory)).unwrap()
        .map(|p|p.unwrap().path()).filter(|p|p.extension().is_some_and(|e|e=="bin")).collect();
    paths.sort();
    for path in paths {
        let bytes=fs::read(&path).unwrap();
        assert_eq!(bytes.len() % (PK_BYTES+32+SIG_BYTES), 0);
        let records:Vec<_>=bytes.chunks_exact(PK_BYTES+32+SIG_BYTES).map(|b|Record {
            public: PublicRecord {
                public_key:b[..PK_BYTES].try_into().unwrap(),
                message:b[PK_BYTES..PK_BYTES+32].try_into().unwrap(),
            },
            signature:b[PK_BYTES+32..].try_into().unwrap(),
        }).collect();
        let native=records.iter().all(|r|verify(&r.public.public_key,&r.public.message,&r.signature));
        let run=run_from_records(&records);
        let program=Program::from_elf(ELF).unwrap();
        let result=Machine::new(program.rv(),&run.advice).run();
        let public:Vec<_>=records.iter().map(|r|r.public.clone()).collect();
        let digest=expected_output(&public).iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>();
        let actual=match result {Ok(x)=>hex(&x.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>()),Err(e)=>format!("TRAP:{e:?}")};
        println!("{}\tnative={}\toutput={}\texpected={}",path.file_name().unwrap().to_string_lossy(),native,actual,hex(&digest));
    }
}
