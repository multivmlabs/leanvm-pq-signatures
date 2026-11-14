//! Export one deterministic record for an independent byte-level verifier.
use mldsa_riscv_host::record;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}
fn main() {
    let index = std::env::args()
        .nth(1)
        .map_or(0, |x| x.parse().expect("index"));
    let r = record(index);
    println!(
        "{{\"compact_public_key_hex\":\"{}\",\"message_hex\":\"{}\",\"compact_signature_hex\":\"{}\"}}",
        hex(&r.public.public_key),
        hex(&r.public.message),
        hex(&r.signature)
    );
}
