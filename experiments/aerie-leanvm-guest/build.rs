//! Enforce immutable public verifier-key provenance even for direct Cargo builds.
use std::{env, path::PathBuf, process::Command};
fn main() {
    let here = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=check_setup.py");
    println!("cargo:rerun-if-changed=trusted-setup-sha256.json");
    println!("cargo:rerun-if-changed=trusted-cache-sha256.json");
    if env::var_os("CARGO_FEATURE_TRUSTED_PUBLIC_SETUP").is_none() { return; }
    for n in [1, 30, 70] {
        println!("cargo:rerun-if-changed=../../artifacts/aerie-wrapper/public-setup/n{n}/setup.bin");
    }
    let mut check = Command::new("python3");
    check.arg(here.join("check_setup.py"));
    if env::var_os("CARGO_FEATURE_TRUSTED_TERMINAL_CACHE").is_some() {
        check.arg("--terminal-cache");
        for n in [1, 30, 70] {
            println!("cargo:rerun-if-changed=../../artifacts/aerie-wrapper/q64-cache/n{n}/terminal-cache.bin");
        }
    }
    let status = check.status().expect("run pinned setup hash check");
    assert!(status.success(), "immutable public setup hash mismatch");
}
