//! Synchronisation primitives.
//!
//! The kernel runs on one CPU and kernel code is never preempted by another
//! task, so mutual exclusion only has to guard against interrupt handlers and
//! against a task blocking while it holds something:
//!
//! * [`SpinLock`] disables interrupts for the critical section. Taking a lock
//!   that is already held can only mean re-entry (a deadlock on one CPU), so it
//!   panics with the lock's location instead of hanging. The scheduler refuses
//!   to switch tasks while any spinlock is held.
//! * [`Mutex`] may be held across blocking operations (disk I/O); waiters sleep
//!   on a [`WaitQueue`].
//! * [`Once`] / [`Lazy`] for write-once globals.

mod mutex;
mod waitq;

pub use mutex::{Mutex, MutexGuard};
pub use waitq::{WaitQueue, WaitResult};

use crate::arch::cpu;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::panic::Location;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering};

/// Number of spinlocks currently held (the scheduler asserts it is zero).
static HELD: AtomicUsize = AtomicUsize::new(0);

pub fn spinlocks_held() -> usize {
    HELD.load(Ordering::Relaxed)
}

pub struct SpinLock<T: ?Sized> {
    locked: AtomicBool,
    owner: AtomicPtr<Location<'static>>,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}
unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(v: T) -> Self {
        Self { locked: AtomicBool::new(false), owner: AtomicPtr::new(core::ptr::null_mut()), data: UnsafeCell::new(v) }
    }
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> SpinLock<T> {
    #[track_caller]
    #[inline]
    pub fn lock(&self) -> SpinGuard<'_, T> {
        let irq = cpu::irq_save();
        if self.locked.swap(true, Ordering::Acquire) {
            let owner = self.owner.load(Ordering::Relaxed);
            crate::panic::lock_recursion(Location::caller(), owner);
        }
        self.owner.store(Location::caller() as *const _ as *mut _, Ordering::Relaxed);
        HELD.fetch_add(1, Ordering::Relaxed);
        SpinGuard { lock: self, irq }
    }

    #[inline]
    pub fn try_lock(&self) -> Option<SpinGuard<'_, T>> {
        let irq = cpu::irq_save();
        if self.locked.swap(true, Ordering::Acquire) {
            cpu::irq_restore(irq);
            return None;
        }
        HELD.fetch_add(1, Ordering::Relaxed);
        Some(SpinGuard { lock: self, irq })
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// Break the lock unconditionally. Only for the panic path, which must be
    /// able to print even if it interrupted the lock holder.
    ///
    /// # Safety
    /// The previous holder must never run again.
    pub unsafe fn force_unlock(&self) {
        if self.locked.swap(false, Ordering::Release) {
            HELD.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

pub struct SpinGuard<'a, T: ?Sized> {
    lock: &'a SpinLock<T>,
    irq: bool,
}

impl<T: ?Sized> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}
impl<T: ?Sized> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}
impl<T: ?Sized + core::fmt::Display> core::fmt::Display for SpinGuard<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        (**self).fmt(f)
    }
}

impl<T: ?Sized> Drop for SpinGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.owner.store(core::ptr::null_mut(), Ordering::Relaxed);
        self.lock.locked.store(false, Ordering::Release);
        HELD.fetch_sub(1, Ordering::Relaxed);
        cpu::irq_restore(self.irq);
    }
}

// ── Once / Lazy ─────────────────────────────────────────────────────────────

const UNINIT: u8 = 0;
const RUNNING: u8 = 1;
const READY: u8 = 2;

pub struct Once<T> {
    state: AtomicU8,
    value: UnsafeCell<core::mem::MaybeUninit<T>>,
}

unsafe impl<T: Send + Sync> Sync for Once<T> {}
unsafe impl<T: Send> Send for Once<T> {}

impl<T> Once<T> {
    pub const fn new() -> Self {
        Self { state: AtomicU8::new(UNINIT), value: UnsafeCell::new(core::mem::MaybeUninit::uninit()) }
    }

    pub fn call_once(&self, f: impl FnOnce() -> T) -> &T {
        match self.state.compare_exchange(UNINIT, RUNNING, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => {
                unsafe { (*self.value.get()).write(f()) };
                self.state.store(READY, Ordering::Release);
            }
            Err(RUNNING) => panic!("Once initialised recursively"),
            Err(_) => {}
        }
        unsafe { (*self.value.get()).assume_init_ref() }
    }

    pub fn get(&self) -> Option<&T> {
        (self.state.load(Ordering::Acquire) == READY).then(|| unsafe { (*self.value.get()).assume_init_ref() })
    }

    /// The value; panics if it was never set (an init-order bug).
    #[track_caller]
    pub fn expect_init(&self) -> &T {
        self.get().expect("subsystem used before initialisation")
    }
}

pub struct Lazy<T, F = fn() -> T> {
    once: Once<T>,
    init: F,
}

unsafe impl<T: Send + Sync, F: Sync> Sync for Lazy<T, F> {}

impl<T, F: Fn() -> T> Lazy<T, F> {
    pub const fn new(init: F) -> Self {
        Self { once: Once::new(), init }
    }
}

impl<T, F: Fn() -> T> Deref for Lazy<T, F> {
    type Target = T;
    fn deref(&self) -> &T {
        self.once.call_once(&self.init)
    }
}
