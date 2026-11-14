use std::{env, fs, path::PathBuf, process::Command};

fn run(mut cmd: Command) {
    let status = cmd.status().expect("run C compiler/linker");
    assert!(status.success(), "C build failed: {cmd:?}");
}

fn main() {
    println!("cargo:rerun-if-env-changed=MLDSA_CLANG");
    println!("cargo:rerun-if-env-changed=MLDSA_CLANG_FINGERPRINT");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let base = manifest.parent().unwrap();
    let root = base.join("../..").canonicalize().unwrap();
    let reference = root.join("vendor/ETHDILITHIUM/c-ref");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let rv = env::var("TARGET").unwrap() == "riscv64im-unknown-none-elf";
    let sdk_keccak = rv && env::var_os("CARGO_FEATURE_SDK_KECCAK").is_some();
    let files = [
        "sign",
        "packing",
        "polyvec",
        "poly",
        "ntt",
        "reduce",
        "rounding",
        "fips202",
        "symmetric-shake",
    ];
    let mut objects = Vec::new();
    for name in files.into_iter().chain(["adapter", "memory"]) {
        let src = if name == "adapter" || name == "memory" {
            base.join(format!("c/{name}.c"))
        } else {
            reference.join(format!("{name}.c"))
        };
        println!("cargo:rerun-if-changed={}", src.display());
        let compiled_src = if sdk_keccak && name == "fips202" {
            let original = fs::read_to_string(&src).unwrap();
            let marker = "static void KeccakF1600_StatePermute(uint64_t state[25])\n{";
            let start = original.find(marker).expect("pinned permutation function");
            let end = start
                + original[start..]
                    .find("\n}\n")
                    .expect("permutation closing brace")
                + 3;
            let adapted = format!("{}extern void pqbench_keccak_f1600(uint64_t state[25]);\n#define KeccakF1600_StatePermute pqbench_keccak_f1600\n{}", &original[..start], &original[end..]);
            let generated = out.join("fips202-sdk-keccak.c");
            fs::write(&generated, adapted).unwrap();
            generated
        } else {
            src.clone()
        };
        let object = out.join(format!("{name}.{}", if rv { "bc" } else { "o" }));
        let mut cmd = Command::new(env::var_os("MLDSA_CLANG").unwrap_or("clang".into()));
        cmd.args([
            "-O3",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-strict-aliasing",
            "-ffunction-sections",
            "-fdata-sections",
            "-DETHDILITHIUM=0",
            "-DDILITHIUM_MODE=2",
        ])
        .arg("-I")
        .arg(base.join("c/include"))
        .arg("-I")
        .arg(&reference);
        if rv {
            // Apple's clang has the RISC-V frontend but no RISC-V machine-code
            // backend. Rust's rust-lld lowers this portable LLVM bitcode.
            cmd.args([
                "--target=riscv64-unknown-none-elf",
                "-march=rv64im",
                "-mabi=lp64",
                "-mcmodel=medany",
                "-mno-relax",
                "-emit-llvm",
            ]);
        }
        cmd.arg("-c").arg(&compiled_src).arg("-o").arg(&object);
        run(cmd);
        objects.push(object);
    }
    for path in fs::read_dir(&reference)
        .unwrap()
        .filter_map(Result::ok)
        .map(|x| x.path())
        .filter(|p| p.extension().is_some_and(|x| x == "h"))
    {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        base.join("c/include/stdio.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        base.join("c/include/string.h").display()
    );
    if rv {
        for object in objects {
            println!("cargo:rustc-link-arg={}", object.display());
        }
    } else {
        let archive = out.join("libmldsa_ref.a");
        let mut cmd = Command::new("ar");
        cmd.arg("crs").arg(&archive).args(objects);
        run(cmd);
        println!("cargo:rustc-link-search=native={}", out.display());
        println!("cargo:rustc-link-lib=static=mldsa_ref");
    }
}
