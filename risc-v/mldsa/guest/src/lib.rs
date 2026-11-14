//! Full FIPS 204 ML-DSA-44 compact-input verification, pure mode, empty context.
#![no_std]

pub const PK_BYTES: usize = 1312;
pub const SIG_BYTES: usize = 2420;
pub const PK_WORDS: usize = PK_BYTES / 8;
pub const SIG_WORDS: usize = SIG_BYTES.div_ceil(8);
pub const RECORD_WORDS: usize = PK_WORDS + 4 + SIG_WORDS;
pub const MAX_BATCH: usize = 256;
/// Domain/profile includes the exact key and signature model.
pub const DOMAIN: [u64; 4] = [
    u64::from_le_bytes(*b"pqbench/"),
    u64::from_le_bytes(*b"mldsa44/"),
    u64::from_le_bytes(*b"compact/"),
    u64::from_le_bytes(*b"v1\0\0\0\0\0\0"),
];

/// The SDK permutation is ordinary constrained RV64IM code, not a Keccak
/// precompile or host hint. C retains all SHAKE domain padding and byte I/O.
#[cfg(all(feature = "sdk-keccak", target_arch = "riscv64", target_os = "none"))]
#[unsafe(no_mangle)]
unsafe extern "C" fn pqbench_keccak_f1600(state: *mut u64) {
    // SAFETY: C calls this only with its aligned, initialized 25-lane state.
    leanvm_guest::keccak::f1600(unsafe { &mut *state.cast::<[u64; 25]>() });
}

unsafe extern "C" {
    fn pqcrystals_dilithium2_ref_verify(
        sig: *const u8,
        siglen: usize,
        message: *const u8,
        mlen: usize,
        context: *const u8,
        ctxlen: usize,
        pk: *const u8,
    ) -> i32;
}

/// Canonical fixed-size byte arrays. All public-key bit patterns encode a valid
/// rho and four 10-bit t1 vectors; signature parsing and bounds are checked by C.
pub fn verify(pk: &[u8; PK_BYTES], message: &[u8; 32], sig: &[u8; SIG_BYTES]) -> bool {
    // SAFETY: each pointer names an exact-size byte array. The reference accepts
    // the null context only with length zero, and never writes through inputs.
    unsafe {
        pqcrystals_dilithium2_ref_verify(
            sig.as_ptr(),
            SIG_BYTES,
            message.as_ptr(),
            32,
            core::ptr::null(),
            0,
            pk.as_ptr(),
        ) == 0
    }
}

/// Word representation is little-endian and the last four signature bytes are
/// transport padding, constrained to zero before calling the byte verifier.
pub fn verify_words(pk: &[u64; PK_WORDS], message: &[u64; 4], sig: &[u64; SIG_WORDS]) -> bool {
    if sig[SIG_WORDS - 1] >> 32 != 0 {
        return false;
    }
    // SAFETY: RV64 and the benchmark host are little-endian; arrays are fully
    // initialized and every byte of these lengths lies within the word arrays.
    #[cfg(target_endian = "little")]
    unsafe {
        verify(
            &*pk.as_ptr().cast::<[u8; PK_BYTES]>(),
            &*message.as_ptr().cast::<[u8; 32]>(),
            &*sig.as_ptr().cast::<[u8; SIG_BYTES]>(),
        )
    }
    #[cfg(not(target_endian = "little"))]
    compile_error!("ML-DSA word transport currently requires little endian");
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
pub fn fixture(
    index: u64,
    pk: &mut [u8; PK_BYTES],
    sig: &mut [u8; SIG_BYTES],
    message: &mut [u8; 32],
) {
    extern crate std;
    use std::sync::Mutex;
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    unsafe extern "C" {
        fn pqbench_mldsa_fixture(index: u64, pk: *mut u8, sig: *mut u8, message: *mut u8) -> i32;
    }
    let _lock = FIXTURE_LOCK.lock().expect("fixture lock");
    // SAFETY: writes fit the arrays and the lock protects deterministic C state.
    assert_eq!(
        unsafe {
            pqbench_mldsa_fixture(
                index,
                pk.as_mut_ptr(),
                sig.as_mut_ptr(),
                message.as_mut_ptr(),
            )
        },
        0
    );
}
