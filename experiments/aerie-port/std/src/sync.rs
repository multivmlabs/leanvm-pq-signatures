//! Synchronization compatibility for a VM with exactly one execution thread.
use core::{cell::UnsafeCell, fmt, ops::{Deref, DerefMut}};
use real_alloc::rc::Rc;

pub mod atomic;

pub struct Arc<T: ?Sized>(Rc<T>);
impl<T: ?Sized + core::marker::Unsize<U>, U: ?Sized> core::ops::CoerceUnsized<Arc<U>> for Arc<T> {}
impl<T> Arc<T> {
    pub fn new(value: T) -> Self { Self(Rc::new(value)) }
    pub fn try_unwrap(this: Self) -> Result<T, Self> { Rc::try_unwrap(this.0).map_err(Self) }
}
impl<T: ?Sized> Arc<T> {
    pub fn ptr_eq(this: &Self, other: &Self) -> bool { Rc::ptr_eq(&this.0, &other.0) }
    pub fn strong_count(this: &Self) -> usize { Rc::strong_count(&this.0) }
    pub fn get_mut(this: &mut Self) -> Option<&mut T> { Rc::get_mut(&mut this.0) }
    pub fn as_ptr(this: &Self) -> *const T { Rc::as_ptr(&this.0) }
    pub fn into_raw(this: Self) -> *const T { Rc::into_raw(this.0) }
    pub unsafe fn from_raw(pointer: *const T) -> Self { Self(unsafe { Rc::from_raw(pointer) }) }
    pub fn weak_count(this: &Self) -> usize { Rc::weak_count(&this.0) }
    pub fn downgrade(this:&Self)->Weak<T>{Weak(Rc::downgrade(&this.0))}
}
impl<T: Clone> Arc<T> { pub fn make_mut(this: &mut Self) -> &mut T { Rc::make_mut(&mut this.0) } }
impl<T: ?Sized> Clone for Arc<T> { fn clone(&self) -> Self { Self(self.0.clone()) } }
impl<T: ?Sized> Deref for Arc<T> { type Target = T; fn deref(&self) -> &T { &self.0 } }
impl<T: ?Sized + fmt::Debug> fmt::Debug for Arc<T> { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) } }
impl<T: ?Sized + PartialEq> PartialEq for Arc<T> { fn eq(&self, other: &Self) -> bool { **self == **other } }
impl<T: ?Sized + Eq> Eq for Arc<T> {}
impl<T: Default> Default for Arc<T> { fn default() -> Self { Self::new(T::default()) } }
impl<T> From<T> for Arc<T> { fn from(value: T) -> Self { Self::new(value) } }
impl<T:?Sized> From<real_alloc::boxed::Box<T>> for Arc<T>{fn from(value:real_alloc::boxed::Box<T>)->Self{Self(Rc::from(value))}}
impl<T> From<real_alloc::vec::Vec<T>> for Arc<[T]> { fn from(value: real_alloc::vec::Vec<T>) -> Self { Self(Rc::from(value)) } }
impl<T: Clone> From<&[T]> for Arc<[T]> { fn from(value: &[T]) -> Self { Self(Rc::from(value)) } }
impl<T, const N: usize> From<[T; N]> for Arc<[T]> { fn from(value: [T; N]) -> Self { Self(Rc::from(value)) } }
impl<T: ?Sized> AsRef<T> for Arc<T> { fn as_ref(&self) -> &T { self } }
unsafe impl<T: ?Sized + Send + Sync> Send for Arc<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for Arc<T> {}
pub struct Weak<T:?Sized>(real_alloc::rc::Weak<T>);
impl<T> Weak<T>{pub const fn new()->Self{Self(real_alloc::rc::Weak::new())}}
impl<T:?Sized> Weak<T>{pub fn upgrade(&self)->Option<Arc<T>>{self.0.upgrade().map(Arc)}pub fn ptr_eq(this:&Self,other:&Self)->bool{real_alloc::rc::Weak::ptr_eq(&this.0,&other.0)}}
impl<T:?Sized> Clone for Weak<T>{fn clone(&self)->Self{Self(self.0.clone())}}
impl<T> Default for Weak<T>{fn default()->Self{Self::new()}}
impl<T:?Sized> fmt::Debug for Weak<T>{fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str("Weak")}}
unsafe impl<T:?Sized+Send+Sync> Send for Weak<T>{}
unsafe impl<T:?Sized+Send+Sync> Sync for Weak<T>{}

pub struct OnceLock<T> { state: UnsafeCell<u8>, value: UnsafeCell<Option<T>> }
impl<T> OnceLock<T> {
    pub const fn new() -> Self { Self { state: UnsafeCell::new(0), value: UnsafeCell::new(None) } }
    pub fn get(&self) -> Option<&T> { unsafe { (&*self.value.get()).as_ref() } }
    pub fn get_mut(&mut self) -> Option<&mut T> { self.value.get_mut().as_mut() }
    pub fn set(&self, value: T) -> Result<(), T> {
        unsafe {
            if *self.state.get() != 0 { return Err(value); }
            *self.value.get() = Some(value);
            *self.state.get() = 2;
            Ok(())
        }
    }
    pub fn get_or_init<F: FnOnce() -> T>(&self, init: F) -> &T {
        unsafe {
            match *self.state.get() {
                0 => { *self.state.get() = 1; let value = init(); *self.value.get() = Some(value); *self.state.get() = 2; }
                1 => panic!("reentrant guest OnceLock initialization"),
                _ => {}
            }
            (&*self.value.get()).as_ref().unwrap()
        }
    }
    pub fn get_or_try_init<F: FnOnce() -> Result<T, E>, E>(&self, init: F) -> Result<&T, E> {
        unsafe {
            match *self.state.get() {
                0 => { *self.state.get() = 1; match init() { Ok(value) => { *self.value.get() = Some(value); *self.state.get() = 2; }, Err(error) => { *self.state.get() = 0; return Err(error); } } }
                1 => panic!("reentrant guest OnceLock initialization"),
                _ => {}
            }
            Ok((&*self.value.get()).as_ref().unwrap())
        }
    }
    pub fn take(&mut self) -> Option<T> { *self.state.get_mut() = 0; self.value.get_mut().take() }
    pub fn into_inner(self) -> Option<T> { self.value.into_inner() }
}
impl<T> Default for OnceLock<T> { fn default() -> Self { Self::new() } }
unsafe impl<T> Sync for OnceLock<T> {}
unsafe impl<T> Send for OnceLock<T> {}

pub struct LazyLock<T, F = fn() -> T> { cell: OnceLock<T>, init: UnsafeCell<Option<F>> }
impl<T, F: FnOnce() -> T> LazyLock<T, F> {
    pub const fn new(init: F) -> Self { Self { cell: OnceLock::new(), init: UnsafeCell::new(Some(init)) } }
    pub fn force(this: &Self) -> &T { this.cell.get_or_init(|| unsafe { this.init.get().as_mut().unwrap().take().unwrap()() }) }
}
impl<T, F: FnOnce() -> T> Deref for LazyLock<T, F> { type Target=T; fn deref(&self) -> &T { Self::force(self) } }
unsafe impl<T, F> Sync for LazyLock<T, F> {}
unsafe impl<T, F> Send for LazyLock<T, F> {}

pub struct Once { state: UnsafeCell<u8> }
impl Once {
    pub const fn new() -> Self { Self { state: UnsafeCell::new(0) } }
    pub fn is_completed(&self) -> bool { unsafe { *self.state.get() == 2 } }
    pub fn call_once<F: FnOnce()>(&self, f: F) {
        unsafe { match *self.state.get() { 0 => { *self.state.get()=1; f(); *self.state.get()=2; }, 1 => panic!("reentrant guest Once"), _ => {} } }
    }
    pub fn call_once_force<F: FnOnce(&OnceState)>(&self, f: F) { self.call_once(|| f(&OnceState)); }
}
unsafe impl Sync for Once {}
pub struct OnceState;
impl OnceState { pub fn is_poisoned(&self) -> bool { false } }

pub struct PoisonError<T>(T);
impl<T> PoisonError<T> { pub fn new(value:T)->Self{Self(value)} pub fn into_inner(self)->T{self.0} pub fn get_ref(&self)->&T{&self.0} pub fn get_mut(&mut self)->&mut T{&mut self.0} }
impl<T> fmt::Debug for PoisonError<T> { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str("PoisonError")} }
impl<T> fmt::Display for PoisonError<T> { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str("poisoned guest lock")} }
impl<T:fmt::Debug> core::error::Error for PoisonError<T> {}
pub type LockResult<T> = Result<T,PoisonError<T>>;
pub enum TryLockError<T> { Poisoned(PoisonError<T>), WouldBlock }
impl<T> fmt::Debug for TryLockError<T> {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str("TryLockError")}}
pub type TryLockResult<T> = Result<T,TryLockError<T>>;

pub struct Mutex<T:?Sized> { locked: UnsafeCell<bool>, value: UnsafeCell<T> }
impl<T> Mutex<T> { pub const fn new(value:T)->Self{Self{locked:UnsafeCell::new(false),value:UnsafeCell::new(value)}} pub fn into_inner(self)->LockResult<T>{Ok(self.value.into_inner())} }
impl<T:?Sized> Mutex<T> {
    pub fn lock(&self)->LockResult<MutexGuard<'_,T>>{match self.try_lock(){Ok(g)=>Ok(g),Err(_)=>panic!("reentrant guest Mutex")}}
    pub fn try_lock(&self)->TryLockResult<MutexGuard<'_,T>>{unsafe{if *self.locked.get(){Err(TryLockError::WouldBlock)}else{*self.locked.get()=true;Ok(MutexGuard{mutex:self})}}}
    pub fn get_mut(&mut self)->LockResult<&mut T>{Ok(self.value.get_mut())}
    pub fn is_poisoned(&self)->bool{false}
}
unsafe impl<T:?Sized> Sync for Mutex<T>{}
unsafe impl<T:?Sized> Send for Mutex<T>{}
impl<T:Default> Default for Mutex<T>{fn default()->Self{Self::new(T::default())}}
pub struct MutexGuard<'a,T:?Sized>{mutex:&'a Mutex<T>}
impl<T:?Sized> Deref for MutexGuard<'_,T>{type Target=T;fn deref(&self)->&T{unsafe{&*self.mutex.value.get()}}}
impl<T:?Sized> DerefMut for MutexGuard<'_,T>{fn deref_mut(&mut self)->&mut T{unsafe{&mut*self.mutex.value.get()}}}
impl<T:?Sized> Drop for MutexGuard<'_,T>{fn drop(&mut self){unsafe{*self.mutex.locked.get()=false}}}
impl<T:?Sized+fmt::Debug> fmt::Debug for MutexGuard<'_,T>{fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{(**self).fmt(f)}}
pub struct RwLock<T:?Sized>(Mutex<T>);
impl<T> RwLock<T>{pub const fn new(value:T)->Self{Self(Mutex::new(value))}pub fn into_inner(self)->LockResult<T>{self.0.into_inner()}}
impl<T:?Sized> RwLock<T>{pub fn read(&self)->LockResult<MutexGuard<'_,T>>{self.0.lock()}pub fn write(&self)->LockResult<MutexGuard<'_,T>>{self.0.lock()}pub fn try_read(&self)->TryLockResult<MutexGuard<'_,T>>{self.0.try_lock()}pub fn try_write(&self)->TryLockResult<MutexGuard<'_,T>>{self.0.try_lock()}pub fn get_mut(&mut self)->LockResult<&mut T>{self.0.get_mut()}pub fn is_poisoned(&self)->bool{false}}
impl<T:Default> Default for RwLock<T>{fn default()->Self{Self::new(T::default())}}
pub type RwLockReadGuard<'a,T> = MutexGuard<'a,T>;
pub type RwLockWriteGuard<'a,T> = MutexGuard<'a,T>;
