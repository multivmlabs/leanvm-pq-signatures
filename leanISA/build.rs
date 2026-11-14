use std::process::Command;

fn git(args: &[&str]) -> String {
    let result = Command::new("git")
        .args(["-C", "vendor/leanVM"])
        .args(args)
        .output()
        .expect("git is required");
    assert!(result.status.success(), "run scripts/bootstrap.py first");
    String::from_utf8(result.stdout)
        .expect("git UTF-8")
        .trim()
        .to_string()
}

fn main() {
    println!("cargo:rerun-if-changed=vendor/leanVM/crates");
    println!("cargo:rerun-if-changed=vendor/leanVM/.git/HEAD");
    println!("cargo:rerun-if-changed=vendor/leanVM/.git/index");
    println!(
        "cargo:rustc-env=LEANVM_BUILD_REVISION={}",
        git(&["rev-parse", "HEAD"])
    );
    println!(
        "cargo:rustc-env=LEANVM_BUILD_DIRTY={}",
        !git(&["status", "--porcelain"]).is_empty()
    );
}
