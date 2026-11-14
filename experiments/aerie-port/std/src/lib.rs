//! The single-thread standard-library subset used by the Aerie verifier guest.
//! No OS, threads, entropy or wall clock are available inside this VM.
#![no_std]
#![feature(coerce_unsized, unsize, alloc_io, core_intrinsics)]

extern crate alloc as real_alloc;

pub use real_alloc::{borrow, boxed, rc, string};
pub mod vec { pub use real_alloc::vec::*; }
#[doc(hidden)]
pub use real_alloc::{format as __alloc_format, vec as __alloc_vec};
pub use core::{
    any, array, ascii, cell, char, clone, cmp, convert, default, f32, f64, fmt, future,
    hash, hint, iter, marker, mem, num, ops, option, pin, primitive, ptr, result, slice,
    str, task,
};

pub mod prelude {
    pub mod v1 {
        pub use real_alloc::borrow::ToOwned;
        pub use real_alloc::boxed::Box;
        pub use real_alloc::string::{String, ToString};
        pub use real_alloc::vec::Vec;
        pub use core::prelude::rust_2021::*;
        pub use crate::{eprint, eprintln, format, print, println, thread_local, vec};
        pub use crate::math::FloatMath;
    }
    pub use v1 as rust_2015;
    pub use v1 as rust_2018;
    pub use v1 as rust_2021;
    pub use v1 as rust_2024;
}

pub mod alloc {
    pub use ::real_alloc::alloc::*;
}

pub mod math {
    pub trait FloatMath: Sized {
        fn powf(self, exponent: Self) -> Self;
        fn powi(self, exponent: i32) -> Self;
        fn sqrt(self) -> Self;
        fn ln(self) -> Self;
        fn log2(self) -> Self;
        fn floor(self) -> Self;
        fn ceil(self) -> Self;
        fn round(self) -> Self;
        fn exp(self) -> Self;
    }
    macro_rules! float_math {
        ($ty:ty,$pow:ident,$powi:ident,$sqrt:ident,$ln:ident,$log2:ident,$floor:ident,$ceil:ident,$round:ident,$exp:ident) => {
            impl FloatMath for $ty {
                fn powf(self, exponent: Self)->Self { libm::$pow(self,exponent) }
                fn powi(self, exponent: i32)->Self { core::intrinsics::$powi(self,exponent) }
                fn sqrt(self)->Self { libm::$sqrt(self) }
                fn ln(self)->Self { libm::$ln(self) }
                fn log2(self)->Self { libm::$log2(self) }
                fn floor(self)->Self { libm::$floor(self) }
                fn ceil(self)->Self { libm::$ceil(self) }
                fn round(self)->Self { libm::$round(self) }
                fn exp(self)->Self { libm::$exp(self) }
            }
        }
    }
    float_math!(f64,pow,powif64,sqrt,log,log2,floor,ceil,round,exp);
    float_math!(f32,powf,powif32,sqrtf,logf,log2f,floorf,ceilf,roundf,expf);
}

pub mod error {
    pub use core::error::*;
}

pub mod backtrace {
    #[derive(Debug)]
    pub struct Backtrace;
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum BacktraceStatus { Unsupported, Disabled, Captured }
    impl Backtrace {
        pub const fn disabled() -> Self { Self }
        pub fn capture() -> Self { Self }
        pub fn force_capture() -> Self { Self }
        pub const fn status(&self) -> BacktraceStatus { BacktraceStatus::Unsupported }
    }
    impl core::fmt::Display for Backtrace {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.write_str("backtrace unavailable in guest") }
    }
}

pub mod ffi;
pub mod path;
pub use core::net;

pub mod collections {
    pub use ::real_alloc::collections::*;
    pub use hashbrown::{HashMap, HashSet, hash_map, hash_set};
}

pub mod time {
    pub use core::time::Duration;

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Instant;
    impl Instant {
        pub fn now() -> Self { Self }
        pub fn elapsed(&self) -> Duration { Duration::ZERO }
        pub fn duration_since(&self, _: Self) -> Duration { Duration::ZERO }
        pub fn checked_duration_since(&self, _: Self) -> Option<Duration> { Some(Duration::ZERO) }
        pub fn saturating_duration_since(&self, _: Self) -> Duration { Duration::ZERO }
        pub fn checked_add(&self, _: Duration) -> Option<Self> { Some(Self) }
        pub fn checked_sub(&self, _: Duration) -> Option<Self> { Some(Self) }
    }
    impl core::ops::Sub for Instant {
        type Output = Duration;
        fn sub(self, _: Self) -> Duration { Duration::ZERO }
    }
    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct SystemTime(Duration);
    pub const UNIX_EPOCH: SystemTime = SystemTime(Duration::ZERO);
    #[derive(Clone, Copy, Debug)]
    pub struct SystemTimeError(Duration);
    impl SystemTimeError { pub fn duration(&self)->Duration{self.0} }
    impl core::fmt::Display for SystemTimeError{fn fmt(&self,f:&mut core::fmt::Formatter<'_>)->core::fmt::Result{f.write_str("system time before epoch")}}
    impl core::error::Error for SystemTimeError{}
    impl SystemTime {
        pub fn now()->Self{UNIX_EPOCH}
        pub fn duration_since(&self,earlier:Self)->Result<Duration,SystemTimeError>{self.0.checked_sub(earlier.0).ok_or(SystemTimeError(earlier.0.saturating_sub(self.0)))}
        pub fn checked_add(&self,d:Duration)->Option<Self>{self.0.checked_add(d).map(Self)}
        pub fn checked_sub(&self,d:Duration)->Option<Self>{self.0.checked_sub(d).map(Self)}
    }
    impl core::ops::Add<Duration> for SystemTime{type Output=Self;fn add(self,d:Duration)->Self{self.checked_add(d).unwrap()}}
    impl core::ops::Sub<Duration> for SystemTime{type Output=Self;fn sub(self,d:Duration)->Self{self.checked_sub(d).unwrap()}}
}

pub mod env {
    use real_alloc::string::String;
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum VarError { NotPresent, NotUnicode(String) }
    impl core::fmt::Display for VarError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("environment variables are unavailable in the guest")
        }
    }
    impl core::error::Error for VarError {}
    pub fn var<K: AsRef<str>>(_: K) -> Result<String, VarError> { Err(VarError::NotPresent) }
    pub fn var_os<K: AsRef<str>>(_: K) -> Option<String> { None }
}

pub mod panic {
    pub use core::panic::*;
    pub fn catch_unwind<F: FnOnce() -> R + UnwindSafe, R>(f: F) -> Result<R, real_alloc::boxed::Box<dyn core::any::Any + Send>> { Ok(f()) }
    pub fn resume_unwind(_: real_alloc::boxed::Box<dyn core::any::Any + Send>) -> ! { panic!("guest unwind") }
}

pub mod thread {
    use crate::sync::OnceLock;
    use core::fmt;

    pub struct LocalKey<T: 'static> { value: OnceLock<T>, init: fn() -> T }
    impl<T> LocalKey<T> {
        pub const fn new(init: fn() -> T) -> Self { Self { value: OnceLock::new(), init } }
        pub fn with<F: FnOnce(&T) -> R, R>(&'static self, f: F) -> R { f(self.value.get_or_init(self.init)) }
        pub fn try_with<F: FnOnce(&T) -> R, R>(&'static self, f: F) -> Result<R, AccessError> { Ok(self.with(f)) }
    }
    unsafe impl<T> Sync for LocalKey<T> {}
    #[derive(Clone, Copy, Debug)]
    pub struct AccessError;
    impl fmt::Display for AccessError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("guest local access") } }
    impl core::error::Error for AccessError {}
    pub fn panicking() -> bool { false }
    pub fn yield_now() {}
    pub fn sleep(_: core::time::Duration) { panic!("sleep is unavailable in the guest") }
    #[derive(Clone, Debug)]
    pub struct Thread;
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    pub struct ThreadId;
    impl Thread { pub fn unpark(&self){} pub fn id(&self)->ThreadId{ThreadId} pub fn name(&self)->Option<&str>{None} }
    pub fn current()->Thread{Thread}
    pub fn park(){panic!("reentrant blocking initialization in the guest")}
}

#[macro_export]
macro_rules! thread_local {
    ($(#[$attr:meta])* $vis:vis static $name:ident: $ty:ty = $init:expr $(;)?) => {
        $(#[$attr])* $vis static $name: $crate::thread::LocalKey<$ty> = $crate::thread::LocalKey::new(|| $init);
    };
    ($( $(#[$attr:meta])* $vis:vis static $name:ident: $ty:ty = const { $($init:tt)* }; )*) => {
        $( $(#[$attr])* $vis static $name: $crate::thread::LocalKey<$ty> = $crate::thread::LocalKey::new(|| { $($init)* }); )*
    };
    ($( $(#[$attr:meta])* $vis:vis static $name:ident: $ty:ty = $init:expr; )*) => {
        $( $(#[$attr])* $vis static $name: $crate::thread::LocalKey<$ty> = $crate::thread::LocalKey::new(|| $init); )*
    };
}

#[macro_export]
macro_rules! vec { ($($arg:tt)*) => { $crate::__alloc_vec!($($arg)*) }; }
#[macro_export]
macro_rules! format { ($($arg:tt)*) => { $crate::__alloc_format!($($arg)*) }; }

#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments<'_>) {
    struct Sink;
    impl core::fmt::Write for Sink { fn write_str(&mut self, _: &str) -> core::fmt::Result { Ok(()) } }
    let _ = core::fmt::write(&mut Sink, args);
}

#[macro_export]
macro_rules! print { ($($arg:tt)*) => { $crate::_print(core::format_args!($($arg)*)) }; }
#[macro_export]
macro_rules! println { () => { $crate::_print(core::format_args!("\n")) }; ($($arg:tt)*) => { $crate::_print(core::format_args!("{}\n", core::format_args!($($arg)*))) }; }
#[macro_export]
macro_rules! eprint { ($($arg:tt)*) => { $crate::print!($($arg)*) }; }
#[macro_export]
macro_rules! eprintln { ($($arg:tt)*) => { $crate::println!($($arg)*) }; }

pub mod sync;
pub mod io;
