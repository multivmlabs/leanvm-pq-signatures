use std::{env, fs, path::PathBuf, process::Command};

fn run(mut command: Command) {
    let status = command.status().expect("run C toolchain");
    assert!(status.success(), "C build failed: {command:?}");
}

fn main() {
    println!("cargo:rerun-if-env-changed=RACCOON_CLANG");
    println!("cargo:rerun-if-env-changed=RACCOON_CLANG_FINGERPRINT");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let base = manifest.parent().unwrap();
    let root = base.join("../../..").canonicalize().unwrap();
    let reference = root.join("vendor/raccoon/ref-c");
    println!("cargo:rerun-if-changed={}", base.join("c/include").display());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let rv = env::var("TARGET").unwrap() == "riscv64im-unknown-none-elf";
    let crt32 = env::var_os("CARGO_FEATURE_CRT32").is_some();
    let sdk_keccak = rv && env::var_os("CARGO_FEATURE_SDK_KECCAK").is_some();
    let mut files = vec![
        "racc_core",
        "racc_serial",
        "polyr",
        if crt32 { "ntt32" } else { "ntt64" },
        "xof_sample",
        "util/ct_util",
        "util/sha3_t",
        "util/keccakf1600",
    ];
    if !rv {
        files.extend(["racc_api", "util/nist_random", "util/test_aes1kt"]);
    }
    let mut objects = Vec::new();
    for name in files.into_iter().chain(["adapter", "memory"]) {
        let source = if ["adapter", "memory"].contains(&name) {
            base.join(format!("c/{name}.c"))
        } else {
            reference.join(format!("{name}.c"))
        };
        println!("cargo:rerun-if-changed={}", source.display());
        let compiled = if sdk_keccak && name == "util/keccakf1600" {
            let original = fs::read_to_string(&source).unwrap();
            let marker = "void keccak_f1600(uint64_t vs[25])\n{";
            let start = original.find(marker).expect("pinned Keccak function");
            // This permutation is the final function in the pinned file. All
            // byte absorption/extraction helpers remain exactly unchanged.
            let generated = out.join("keccak-sdk.c");
            fs::write(&generated, format!("{}\nextern void pqbench_raccoon_keccak(uint64_t vs[25]);\nvoid keccak_f1600(uint64_t vs[25]) {{ pqbench_raccoon_keccak(vs); }}\n", &original[..start])).unwrap();
            generated
        } else {
            source
        };
        let object = out.join(format!(
            "{}.{}",
            name.replace('/', "_"),
            if rv { "bc" } else { "o" }
        ));
        let mut command = Command::new(env::var_os("RACCOON_CLANG").unwrap_or("clang".into()));
        command
            .args([
                "-O3",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-strict-aliasing",
                // The reference Montgomery code keeps low limbs of signed wide
                // products. Define that wraparound instead of leaving C overflow UB.
                "-fwrapv",
                "-ffunction-sections",
                "-fdata-sections",
            ])
            .arg("-include")
            .arg(base.join("c/namespace.h"))
            .arg("-include")
            .arg(base.join("c/include/plat_local.h"))
            .arg("-I")
            .arg(base.join("c/include"))
            .arg("-I")
            .arg(&reference)
            .arg("-I")
            .arg(reference.join("inc"));
        if crt32 { command.arg("-DPOLYR_Q32=1"); }
        if rv {
            command.args([
                "--target=riscv64-unknown-none-elf",
                "-march=rv64im",
                "-mabi=lp64",
                "-mcmodel=medany",
                "-mno-relax",
                "-emit-llvm",
            ]);
        }
        command.arg("-c").arg(compiled).arg("-o").arg(&object);
        run(command);
        objects.push(object);
    }
    println!(
        "cargo:rerun-if-changed={}",
        base.join("c/namespace.h").display()
    );
    for directory in [&reference, &reference.join("inc"), &base.join("c/include")] {
        for path in fs::read_dir(directory)
            .unwrap()
            .filter_map(Result::ok)
            .map(|x| x.path())
            .filter(|p| p.extension().is_some_and(|x| x == "h"))
        {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    if rv {
        for object in objects {
            println!("cargo:rustc-link-arg={}", object.display());
        }
    } else {
        let archive = out.join("libraccoon_ref.a");
        let mut command = Command::new("ar");
        command.arg("crs").arg(&archive).args(objects);
        run(command);
        println!("cargo:rustc-link-search=native={}", out.display());
        println!("cargo:rustc-link-lib=static=raccoon_ref");
    }
}
