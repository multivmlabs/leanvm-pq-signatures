//! Byte-preserving path containers for generic serialization, without filesystem access.

use crate::ffi::{OsStr, OsString};
use crate::real_alloc::borrow::{Borrow, Cow, ToOwned};
use crate::real_alloc::boxed::Box;
use crate::real_alloc::string::String;
use core::fmt;
use core::ops::Deref;

#[repr(transparent)]
#[derive(Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Path(OsStr);

#[derive(Clone, Default, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct PathBuf(OsString);

impl Path {
    pub fn new<S: AsRef<OsStr> + ?Sized>(value: &S) -> &Self {
        let value = value.as_ref();
        // SAFETY: Path is transparent over OsStr, with no additional invariant.
        unsafe { &*(value as *const OsStr as *const Self) }
    }
    pub fn as_os_str(&self) -> &OsStr {
        &self.0
    }
    pub fn to_str(&self) -> Option<&str> {
        self.0.to_str()
    }
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        self.0.to_string_lossy()
    }
    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf(self.0.to_os_string())
    }
    pub fn display(&self) -> Display<'_> {
        Display(self)
    }
    pub fn is_absolute(&self) -> bool {
        self.0.as_bytes().first() == Some(&b'/')
    }
    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }
    pub fn join<P: AsRef<Path>>(&self, path: P) -> PathBuf {
        let mut result = self.to_path_buf();
        result.push(path);
        result
    }
}

impl PathBuf {
    pub const fn new() -> Self {
        Self(OsString::new())
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self(OsString::with_capacity(capacity))
    }
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
    pub fn into_os_string(self) -> OsString {
        self.0
    }
    pub fn into_boxed_path(self) -> Box<Path> {
        let raw = Box::into_raw(self.0.into_boxed_os_str());
        // SAFETY: Path is transparent over OsStr, with the same allocation and drop layout.
        unsafe { Box::from_raw(raw as *mut Path) }
    }
    pub fn push<P: AsRef<Path>>(&mut self, path: P) {
        let path = path.as_ref();
        if path.is_absolute() {
            self.0 = path.as_os_str().to_os_string();
        } else {
            if !self.0.is_empty() && !self.0.as_bytes().ends_with(b"/") {
                self.0.push("/");
            }
            self.0.push(path.as_os_str());
        }
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

impl Deref for PathBuf {
    type Target = Path;
    fn deref(&self) -> &Path {
        self.as_path()
    }
}
impl AsRef<Path> for Path {
    fn as_ref(&self) -> &Path {
        self
    }
}
impl AsRef<Path> for PathBuf {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}
impl AsRef<Path> for OsStr {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}
impl AsRef<Path> for OsString {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}
impl AsRef<Path> for str {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}
impl AsRef<Path> for String {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}
impl AsRef<OsStr> for Path {
    fn as_ref(&self) -> &OsStr {
        self.as_os_str()
    }
}
impl AsRef<OsStr> for PathBuf {
    fn as_ref(&self) -> &OsStr {
        self.0.as_os_str()
    }
}
impl Borrow<Path> for PathBuf {
    fn borrow(&self) -> &Path {
        self.as_path()
    }
}
impl ToOwned for Path {
    type Owned = PathBuf;
    fn to_owned(&self) -> PathBuf {
        self.to_path_buf()
    }
}
impl From<&str> for PathBuf {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}
impl From<String> for PathBuf {
    fn from(value: String) -> Self {
        Self(value.into())
    }
}
impl From<&OsStr> for PathBuf {
    fn from(value: &OsStr) -> Self {
        Self(value.into())
    }
}
impl From<OsString> for PathBuf {
    fn from(value: OsString) -> Self {
        Self(value)
    }
}
impl From<&Path> for PathBuf {
    fn from(value: &Path) -> Self {
        value.to_path_buf()
    }
}
impl From<&PathBuf> for PathBuf {
    fn from(value: &PathBuf) -> Self {
        value.clone()
    }
}
impl fmt::Debug for Path {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_os_str(), formatter)
    }
}
pub struct Display<'a>(&'a Path);
impl fmt::Display for Display<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.to_string_lossy(), formatter)
    }
}
