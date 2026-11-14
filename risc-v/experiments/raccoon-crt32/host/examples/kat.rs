//! First official NIST KAT record, not a performance experiment.
use raccoon_riscv_guest::{PK_BYTES, SIG_BYTES};

fn unhex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let seed = unhex::<48>(
        "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
    );
    let message = unhex::<33>("d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8");
    let mut pk = [0; PK_BYTES];
    let mut sk = [0; 14800];
    let mut sm = [0; SIG_BYTES + 33];
    unsafe extern "C" {
        fn pqbench_raccoon_kat(
            seed: *const u8,
            message: *const u8,
            mlen: usize,
            pk: *mut u8,
            sk: *mut u8,
            sm: *mut u8,
        ) -> i32;
    }
    // SAFETY: all arrays have the exact sizes required by this reference API.
    assert_eq!(
        unsafe {
            pqbench_raccoon_kat(
                seed.as_ptr(),
                message.as_ptr(),
                message.len(),
                pk.as_mut_ptr(),
                sk.as_mut_ptr(),
                sm.as_mut_ptr(),
            )
        },
        0
    );
    println!(
        "{{\"count\":0,\"seed\":\"{}\",\"message\":\"{}\",\"public_key\":\"{}\",\"secret_key\":\"{}\",\"signed_message\":\"{}\"}}",
        hex(&seed),
        hex(&message),
        hex(&pk),
        hex(&sk),
        hex(&sm)
    );
}
