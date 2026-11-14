//! Static native-binary identity. This never executes a guest.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub fn describe(scheme: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let (elf, manifest) = match scheme {
        "raccoon" => (
            raccoon_riscv_host::ELF,
            include_str!("../raccoon/build-manifest.json"),
        ),
        "raccoon-g" => (
            raccoong_riscv_host::ELF,
            include_str!("../raccoon-g/build-manifest.json"),
        ),
        _ => return Err("identity supports raccoon and raccoon-g".into()),
    };
    let provenance: Value = serde_json::from_str(manifest)?;
    let hash = |bytes: &[u8]| -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    let elf_hash = hash(elf);
    if provenance["elf_sha256"].as_str() != Some(&elf_hash) {
        return Err("embedded ELF differs from embedded build manifest".into());
    }
    Ok(json!({"schema":1,"action":"identity","scheme":scheme,
        "embedded_elf_sha256":elf_hash,"embedded_elf_bytes":elf.len(),
        "embedded_build_manifest_sha256":hash(manifest.as_bytes()),
        "backend_revision":provenance["backend_pins"]["vendor/leanVM-riscv"],
        "executes_guest":false,"produces_proof":false}))
}

#[cfg(test)]
mod tests {
    #[test]
    fn each_embedded_guest_matches_its_embedded_build_manifest() {
        for scheme in ["raccoon", "raccoon-g"] {
            let identity = super::describe(scheme).unwrap();
            assert_eq!(identity["executes_guest"], false);
            assert_eq!(identity["produces_proof"], false);
        }
    }
}
