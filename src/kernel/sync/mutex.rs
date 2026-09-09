//! Sleeping Mutex — blocks the thread (does not spin) while waiting.
//!
//! Unlike SpinLock, the waiting thread is put to sleep and woken by the scheduler.
//! Safe to hold across longer operations. Requires a working scheduler.

// TODO: Implement with a wait queue (list of blocked threads).
// TODO: lock() → add current thread to wait queue → reschedule
// TODO: unlock() → wake one thread from wait queue

pub struct Mutex {
    // TODO
}

impl Mutex {
    pub const fn new() -> Self {
        Self {}
    }

    pub fn lock(&self) {
        // TODO
    }

    pub fn unlock(&self) {
        // TODO
    }
}
