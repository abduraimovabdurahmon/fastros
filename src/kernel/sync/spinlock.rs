//! Spin lock — busy-waits until the lock is acquired.
//!
//! Use ONLY for very short critical sections (a few instructions).
//! Do NOT hold a spinlock while calling any function that may sleep.
//! On a single-core system, spinlocks must disable interrupts to avoid deadlock.

use core::sync::atomic::{AtomicBool, Ordering};

pub struct SpinLock {
    locked: AtomicBool,
}

impl SpinLock {
    pub const fn new() -> Self {
        Self { locked: AtomicBool::new(false) }
    }

    /// Acquire the lock (spin until available).
    pub fn lock(&self) {
        while self.locked.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            // Hint to the CPU that we're spinning (reduces power/pipeline pressure).
            core::hint::spin_loop();
        }
    }

    /// Release the lock.
    pub fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }

    /// Try to acquire without spinning. Returns true if acquired.
    pub fn try_lock(&self) -> bool {
        self.locked.compare_exchange(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_ok()
    }
}
