//! Original NIST Raccoon-128-1, compact keys and fixed serialized signatures.
#![no_std]

pub const PK_BYTES: usize = 2256;
pub const SIG_BYTES: usize = 11524;
pub const PK_WORDS: usize = PK_BYTES / 8;
pub const SIG_WORDS: usize = SIG_BYTES.div_ceil(8);
pub const RECORD_WORDS: usize = PK_WORDS + 4 + SIG_WORDS;
/// Advice transport bound, not a measured proof capacity.
pub const MAX_BATCH: usize = 64;
pub const DOMAIN: [u64; 4] = [
    u64::from_le_bytes(*b"pqbench/"),
    u64::from_le_bytes(*b"racc1281"),
    u64::from_le_bytes(*b"/compact"),
    u64::from_le_bytes(*b"/v1\0\0\0\0\0"),
];

#[cfg(all(feature = "sdk-keccak", target_arch = "riscv64", target_os = "none"))]
#[unsafe(no_mangle)]
unsafe extern "C" fn pqbench_raccoon_keccak(state: *mut u64) {
    // SAFETY: the reference always passes its aligned, initialized 25-lane state.
    leanvm_guest::keccak::f1600(unsafe { &mut *state.cast::<[u64; 25]>() });
}

unsafe extern "C" {
    fn pqbench_raccoon_verify(pk: *const u8, message: *const u8, signature: *const u8) -> i32;
}

pub fn verify(pk: &[u8; PK_BYTES], message: &[u8; 32], signature: &[u8; SIG_BYTES]) -> bool {
    // SAFETY: exact-sized arrays provide every byte read by the bounded C decoder.
    unsafe { pqbench_raccoon_verify(pk.as_ptr(), message.as_ptr(), signature.as_ptr()) == 1 }
}

pub fn verify_words(
    pk: &[u64; PK_WORDS],
    message: &[u64; 4],
    signature: &[u64; SIG_WORDS],
) -> bool {
    // Four high bytes are transport padding, distinct from signature zero padding.
    if signature[SIG_WORDS - 1] >> 32 != 0 {
        return false;
    }
    #[cfg(target_endian = "little")]
    unsafe {
        // SAFETY: little endian words contain the exact complete input arrays.
        verify(
            &*pk.as_ptr().cast::<[u8; PK_BYTES]>(),
            &*message.as_ptr().cast::<[u8; 32]>(),
            &*signature.as_ptr().cast::<[u8; SIG_BYTES]>(),
        )
    }
    #[cfg(not(target_endian = "little"))]
    compile_error!("Raccoon word transport requires little endian");
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
pub fn fixture(
    index: u64,
    pk: &mut [u8; PK_BYTES],
    signature: &mut [u8; SIG_BYTES],
    message: &mut [u8; 32],
) {
    extern crate std;
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    unsafe extern "C" {
        fn pqbench_raccoon_fixture(
            index: u64,
            pk: *mut u8,
            signature: *mut u8,
            message: *mut u8,
        ) -> i32;
    }
    let _lock = LOCK.lock().expect("fixture lock");
    // SAFETY: exact output buffers and a lock around the reference global DRBG.
    assert_eq!(
        unsafe {
            pqbench_raccoon_fixture(
                index,
                pk.as_mut_ptr(),
                signature.as_mut_ptr(),
                message.as_mut_ptr(),
            )
        },
        0
    );
}
