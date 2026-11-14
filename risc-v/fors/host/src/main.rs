//! Export deterministic records for independent Python verification.
fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "2".into())
        .parse()
        .unwrap();
    let records = (0..n)
        .map(|i| fors_host::record_json(&fors_host::record(i)))
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string(&records).unwrap());
}
