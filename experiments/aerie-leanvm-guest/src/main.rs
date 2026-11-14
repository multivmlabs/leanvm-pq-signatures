//! Complete scalar Aerie verification inside the RV64IM guest.
#![no_std]
#![no_main]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::{cell::UnsafeCell, ptr::NonNull};
use aerie_verifier::{verify_aggregate, AggregationStatement, Falcon512, FalconVerifierSetup};

// The advice is bounded independently from the frame's checked live lengths.
leanvm_guest::advice_words!(128 * 1024);

struct Allocator { initialized: UnsafeCell<bool>, heap: UnsafeCell<linked_list_allocator::Heap> }
unsafe impl Sync for Allocator {}
unsafe extern "C" { static __heap_start: u8; static __heap_end: u8; }
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = unsafe { &mut *self.heap.get() };
        if !unsafe { *self.initialized.get() } {
            let start = &raw const __heap_start as *mut u8;
            let size = &raw const __heap_end as usize - start as usize;
            unsafe { heap.init(start, size); *self.initialized.get() = true; }
        }
        heap.allocate_first_fit(layout).map(NonNull::as_ptr).unwrap_or(core::ptr::null_mut())
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if let Some(pointer) = NonNull::new(pointer) { unsafe { (&mut *self.heap.get()).deallocate(pointer, layout); } }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator { initialized: UnsafeCell::new(false), heap: UnsafeCell::new(linked_list_allocator::Heap::empty()) };

fn unavailable_entropy(_: &mut [u8]) -> Result<(), getrandom::Error> { Err(getrandom::Error::UNSUPPORTED) }
getrandom::register_custom_getrandom!(unavailable_entropy);

#[cfg(feature = "trusted-public-setup")]
fn verifier_setup(records: usize) -> FalconVerifierSetup<Falcon512> {
    use aerie_falcon::substrate::BaseField;
    use akita_serialization::{AkitaDeserialize, Compress, Validate};
    use akita_types::{AkitaVerifierSetup, sample_akita_setup_seed};
    // These are public verification-key data, immutable and authenticated by
    // the guest program identity. No setup data is read from prover advice.
    let (bytes, variables, elements): (&[u8], usize, usize) = match records {
        1 | 10 => (include_bytes!("../../../artifacts/aerie-wrapper/public-setup/n1/setup.bin"), 13, 131072),
        30 => (include_bytes!("../../../artifacts/aerie-wrapper/public-setup/n30/setup.bin"), 14, 229376),
        70 | 100 => (include_bytes!("../../../artifacts/aerie-wrapper/public-setup/n70/setup.bin"), 16, 229376),
        _ => panic!("record count outside compiled setup bank"),
    };
    let setup = AkitaVerifierSetup::<BaseField>::deserialize_exact_with_mode(bytes, Compress::Yes, Validate::No, &())
        .expect("immutable public setup encoding");
    let descriptor = setup.expanded().descriptor();
    assert_eq!(descriptor.max_num_vars, variables);
    assert_eq!(descriptor.max_num_batched_polys, 9);
    assert_eq!(descriptor.num_field_elements, elements);
    assert_eq!(descriptor.setup_seed, sample_akita_setup_seed());
    assert_eq!(setup.expanded().shared_matrix().num_field_elements(), elements);
    assert!(setup.prefix_slots().is_empty());
    #[cfg(feature = "trusted-terminal-cache")]
    {
        let cache: &[u8] = match records {
            1 | 10 => include_bytes!("../../../artifacts/aerie-wrapper/q64-cache/n1/terminal-cache.bin"),
            30 => include_bytes!("../../../artifacts/aerie-wrapper/q64-cache/n30/terminal-cache.bin"),
            70 | 100 => include_bytes!("../../../artifacts/aerie-wrapper/q64-cache/n70/terminal-cache.bin"),
            _ => unreachable!(),
        };
        FalconVerifierSetup::<Falcon512>::from_derived_setup_with_trusted_cache(records, setup, cache)
            .expect("trusted immutable public terminal cache")
    }
    #[cfg(not(feature = "trusted-terminal-cache"))]
    {
        FalconVerifierSetup::<Falcon512>::from_derived_setup(records, setup).expect("trusted public verifier setup")
    }
}

#[cfg(not(feature = "trusted-public-setup"))]
fn verifier_setup(records: usize) -> FalconVerifierSetup<Falcon512> {
    FalconVerifierSetup::<Falcon512>::new(records).expect("derived Aerie verifier setup")
}

#[unsafe(no_mangle)]
extern "C" fn main() {
    let length = usize::try_from(*leanvm_guest::read::<u64>()).expect("input length");
    assert!(length <= 1024 * 1024 - 8);
    let words = leanvm_guest::read_slice::<u64>(length.div_ceil(8));
    let padded = unsafe { core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 8) };
    assert!(padded[length..].iter().all(|byte| *byte == 0));
    let frame = aerie_wrapper_format::decode(&padded[..length]).expect("wrapper frame");
    let statement = AggregationStatement::<Falcon512>::parse_canonical(frame.statement).expect("canonical Aerie statement");
    assert_eq!(statement.len(), frame.records);
    let setup = verifier_setup(frame.records);
    verify_aggregate(&setup, &statement, frame.proof).expect("complete Aerie verification");
    let digest = aerie_wrapper_format::claim_digest(frame.records, frame.statement);
    let output = core::array::from_fn::<u64, 4, _>(|index| u64::from_le_bytes(digest[index * 8..index * 8 + 8].try_into().unwrap()));
    leanvm_guest::commit(&output);
}
