//! Single-hart atomics. The guest cannot spawn threads or receive interrupts.
pub use core::sync::atomic::Ordering;
use core::cell::UnsafeCell;

pub fn fence(_: Ordering) {}
pub fn compiler_fence(_: Ordering) {}

macro_rules! integer {
    ($name:ident,$ty:ty) => {
        pub struct $name { value: UnsafeCell<$ty> }
        unsafe impl Send for $name {}
        unsafe impl Sync for $name {}
        impl $name {
            pub const fn new(value:$ty)->Self{Self{value:UnsafeCell::new(value)}}
            pub fn load(&self,_:Ordering)->$ty{unsafe{*self.value.get()}}
            pub fn store(&self,value:$ty,_:Ordering){unsafe{*self.value.get()=value}}
            pub fn swap(&self,value:$ty,_:Ordering)->$ty{unsafe{core::mem::replace(&mut*self.value.get(),value)}}
            pub fn compare_exchange(&self,current:$ty,new:$ty,_:Ordering,_:Ordering)->Result<$ty,$ty>{let old=self.load(Ordering::Relaxed);if old==current{self.store(new,Ordering::Relaxed);Ok(old)}else{Err(old)}}
            pub fn compare_exchange_weak(&self,current:$ty,new:$ty,success:Ordering,failure:Ordering)->Result<$ty,$ty>{self.compare_exchange(current,new,success,failure)}
            pub fn fetch_add(&self,value:$ty,order:Ordering)->$ty{let old=self.load(order);self.store(old.wrapping_add(value),order);old}
            pub fn fetch_sub(&self,value:$ty,order:Ordering)->$ty{let old=self.load(order);self.store(old.wrapping_sub(value),order);old}
            pub fn fetch_and(&self,value:$ty,order:Ordering)->$ty{let old=self.load(order);self.store(old&value,order);old}
            pub fn fetch_or(&self,value:$ty,order:Ordering)->$ty{let old=self.load(order);self.store(old|value,order);old}
            pub fn fetch_xor(&self,value:$ty,order:Ordering)->$ty{let old=self.load(order);self.store(old^value,order);old}
            pub fn fetch_nand(&self,value:$ty,order:Ordering)->$ty{let old=self.load(order);self.store(!(old&value),order);old}
            pub fn fetch_max(&self,value:$ty,order:Ordering)->$ty{let old=self.load(order);self.store(core::cmp::max(old,value),order);old}
            pub fn fetch_min(&self,value:$ty,order:Ordering)->$ty{let old=self.load(order);self.store(core::cmp::min(old,value),order);old}
            pub fn fetch_update<F:FnMut($ty)->Option<$ty>>(&self,set:Ordering,fetch:Ordering,mut f:F)->Result<$ty,$ty>{let old=self.load(fetch);match f(old){Some(new)=>{self.store(new,set);Ok(old)},None=>Err(old)}}
            pub fn get_mut(&mut self)->&mut $ty{self.value.get_mut()}
            pub fn into_inner(self)->$ty{self.value.into_inner()}
            pub fn as_ptr(&self)->*mut $ty{self.value.get()}
        }
        impl Default for $name{fn default()->Self{Self::new(0)}}
        impl From<$ty> for $name{fn from(value:$ty)->Self{Self::new(value)}}
        impl core::fmt::Debug for $name{fn fmt(&self,f:&mut core::fmt::Formatter<'_>)->core::fmt::Result{self.load(Ordering::Relaxed).fmt(f)}}
    }
}
integer!(AtomicU8,u8); integer!(AtomicU16,u16); integer!(AtomicU32,u32); integer!(AtomicU64,u64); integer!(AtomicUsize,usize);
integer!(AtomicI8,i8); integer!(AtomicI16,i16); integer!(AtomicI32,i32); integer!(AtomicI64,i64); integer!(AtomicIsize,isize);

pub struct AtomicBool { value: UnsafeCell<bool> }
unsafe impl Send for AtomicBool {}
unsafe impl Sync for AtomicBool {}
impl AtomicBool {
    pub const fn new(value:bool)->Self{Self{value:UnsafeCell::new(value)}}
    pub fn load(&self,_:Ordering)->bool{unsafe{*self.value.get()}}
    pub fn store(&self,value:bool,_:Ordering){unsafe{*self.value.get()=value}}
    pub fn swap(&self,value:bool,_:Ordering)->bool{unsafe{core::mem::replace(&mut*self.value.get(),value)}}
    pub fn compare_exchange(&self,current:bool,new:bool,_:Ordering,_:Ordering)->Result<bool,bool>{let old=self.load(Ordering::Relaxed);if old==current{self.store(new,Ordering::Relaxed);Ok(old)}else{Err(old)}}
    pub fn compare_exchange_weak(&self,current:bool,new:bool,s:Ordering,f:Ordering)->Result<bool,bool>{self.compare_exchange(current,new,s,f)}
    pub fn fetch_or(&self,value:bool,o:Ordering)->bool{let old=self.load(o);self.store(old|value,o);old}
    pub fn fetch_and(&self,value:bool,o:Ordering)->bool{let old=self.load(o);self.store(old&value,o);old}
    pub fn fetch_xor(&self,value:bool,o:Ordering)->bool{let old=self.load(o);self.store(old^value,o);old}
    pub fn fetch_nand(&self,value:bool,o:Ordering)->bool{let old=self.load(o);self.store(!(old&value),o);old}
    pub fn get_mut(&mut self)->&mut bool{self.value.get_mut()}
    pub fn into_inner(self)->bool{self.value.into_inner()}
}
impl Default for AtomicBool{fn default()->Self{Self::new(false)}}
impl From<bool> for AtomicBool{fn from(value:bool)->Self{Self::new(value)}}

pub struct AtomicPtr<T> { value: UnsafeCell<*mut T> }
unsafe impl<T> Send for AtomicPtr<T> {}
unsafe impl<T> Sync for AtomicPtr<T> {}
impl<T> AtomicPtr<T> {
    pub const fn new(value:*mut T)->Self{Self{value:UnsafeCell::new(value)}}
    pub fn load(&self,_:Ordering)->*mut T{unsafe{*self.value.get()}}
    pub fn store(&self,value:*mut T,_:Ordering){unsafe{*self.value.get()=value}}
    pub fn swap(&self,value:*mut T,_:Ordering)->*mut T{unsafe{core::mem::replace(&mut*self.value.get(),value)}}
    pub fn compare_exchange(&self,current:*mut T,new:*mut T,_:Ordering,_:Ordering)->Result<*mut T,*mut T>{let old=self.load(Ordering::Relaxed);if old==current{self.store(new,Ordering::Relaxed);Ok(old)}else{Err(old)}}
    pub fn compare_exchange_weak(&self,current:*mut T,new:*mut T,s:Ordering,f:Ordering)->Result<*mut T,*mut T>{self.compare_exchange(current,new,s,f)}
    pub fn get_mut(&mut self)->&mut *mut T{self.value.get_mut()}
    pub fn into_inner(self)->*mut T{self.value.into_inner()}
}
impl<T> Default for AtomicPtr<T>{fn default()->Self{Self::new(core::ptr::null_mut())}}
impl<T> core::fmt::Debug for AtomicPtr<T>{fn fmt(&self,f:&mut core::fmt::Formatter<'_>)->core::fmt::Result{self.load(Ordering::Relaxed).fmt(f)}}
