//! Byte-preserving Unix-style strings for generic serialization support.

pub use crate::real_alloc::ffi::*;
pub use core::ffi::*;

use crate::real_alloc::borrow::{Borrow, Cow, ToOwned};
use crate::real_alloc::boxed::Box;
use crate::real_alloc::string::String;
use crate::real_alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;

#[repr(transparent)]
#[derive(Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct OsStr([u8]);

#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct OsString(Vec<u8>);

impl OsStr {
    pub fn new<S: AsRef<Self> + ?Sized>(value: &S) -> &Self {
        value.as_ref()
    }
    pub fn from_bytes(bytes: &[u8]) -> &Self {
        // SAFETY: OsStr is transparent over an arbitrary byte slice.
        unsafe { &*(bytes as *const [u8] as *const Self) }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn as_encoded_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }
    pub fn to_os_string(&self) -> OsString {
        OsString(self.0.to_vec())
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl OsString {
    pub const fn new() -> Self {
        Self(Vec::new())
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
    pub fn as_os_str(&self) -> &OsStr {
        OsStr::from_bytes(&self.0)
    }
    pub fn into_string(self) -> Result<String, Self> {
        String::from_utf8(self.0).map_err(|error| Self(error.into_bytes()))
    }
    pub fn into_boxed_os_str(self) -> Box<OsStr> {
        let bytes = Box::into_raw(self.0.into_boxed_slice());
        // SAFETY: OsStr is transparent over [u8], with the same allocation and drop layout.
        unsafe { Box::from_raw(bytes as *mut OsStr) }
    }
    pub fn push<S: AsRef<OsStr>>(&mut self, value: S) {
        self.0.extend_from_slice(value.as_ref().as_bytes());
    }
    pub fn clear(&mut self) {
        self.0.clear();
    }
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }
    pub fn reserve(&mut self, additional: usize) {
        self.0.reserve(additional);
    }
}

impl Deref for OsString {
    type Target = OsStr;
    fn deref(&self) -> &OsStr {
        self.as_os_str()
    }
}
impl AsRef<OsStr> for OsStr {
    fn as_ref(&self) -> &OsStr {
        self
    }
}
impl AsRef<OsStr> for OsString {
    fn as_ref(&self) -> &OsStr {
        self.as_os_str()
    }
}
impl AsRef<OsStr> for str {
    fn as_ref(&self) -> &OsStr {
        OsStr::from_bytes(self.as_bytes())
    }
}
impl AsRef<OsStr> for String {
    fn as_ref(&self) -> &OsStr {
        OsStr::from_bytes(self.as_bytes())
    }
}
impl Borrow<OsStr> for OsString {
    fn borrow(&self) -> &OsStr {
        self.as_os_str()
    }
}
impl ToOwned for OsStr {
    type Owned = OsString;
    fn to_owned(&self) -> OsString {
        self.to_os_string()
    }
}
impl From<&str> for OsString {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}
impl From<String> for OsString {
    fn from(value: String) -> Self {
        Self(value.into_bytes())
    }
}
impl From<&OsStr> for OsString {
    fn from(value: &OsStr) -> Self {
        value.to_os_string()
    }
}
impl From<&OsString> for OsString {
    fn from(value: &OsString) -> Self {
        value.clone()
    }
}
impl fmt::Debug for OsStr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, formatter)
    }
}
impl fmt::Debug for OsString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_os_str(), formatter)
    }
}

/// Reexport these traits at `std::os::unix::ffi` in the guest shim.
pub mod unix {
    use super::{OsStr, OsString, Vec};
    pub trait OsStrExt {
        fn from_bytes(bytes: &[u8]) -> &Self;
        fn as_bytes(&self) -> &[u8];
    }
    impl OsStrExt for OsStr {
        fn from_bytes(bytes: &[u8]) -> &Self {
            Self::from_bytes(bytes)
        }
        fn as_bytes(&self) -> &[u8] {
            self.as_bytes()
        }
    }
    pub trait OsStringExt {
        fn from_vec(bytes: Vec<u8>) -> Self;
        fn into_vec(self) -> Vec<u8>;
    }
    impl OsStringExt for OsString {
        fn from_vec(bytes: Vec<u8>) -> Self {
            Self::from_vec(bytes)
        }
        fn into_vec(self) -> Vec<u8> {
            self.into_vec()
        }
    }
}
