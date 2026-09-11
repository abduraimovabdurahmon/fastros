//! Sleeping mutex: may be held across blocking operations.

use super::WaitQueue;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub struct Mutex<T: ?Sized> {
    locked: AtomicBool,
    wq: WaitQueue,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(v: T) -> Self {
        Self { locked: AtomicBool::new(false), wq: WaitQueue::new(), data: UnsafeCell::new(v) }
    }
}

impl<T: ?Sized> Mutex<T> {
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.wq.wait_until(|| (!self.locked.swap(true, Ordering::Acquire)).then_some(()));
        MutexGuard { m: self }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        (!self.locked.swap(true, Ordering::Acquire)).then_some(MutexGuard { m: self })
    }
}

pub struct MutexGuard<'a, T: ?Sized> {
    m: &'a Mutex<T>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.m.data.get() }
    }
}
impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.m.data.get() }
    }
}
impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.m.locked.store(false, Ordering::Release);
        self.m.wq.wake_one();
    }
}
