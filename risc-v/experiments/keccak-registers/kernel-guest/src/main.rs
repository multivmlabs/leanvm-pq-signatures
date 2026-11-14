#![no_std]
#![no_main]
use leanvm_guest::{read,commit};
leanvm_guest::advice_words!(1<<17);
#[unsafe(no_mangle)]
extern "C" fn main(){
 let n=*read::<u64>(); assert!(n>0&&n<=4096);commit(&n);
 for _ in 0..n {let mut state=*read::<[u64;25]>();leanvm_guest::keccak::f1600(&mut state);commit(&state);}
}
