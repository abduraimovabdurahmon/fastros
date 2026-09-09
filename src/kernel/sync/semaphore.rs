//! Counting Semaphore
//!
//! Allows up to N threads to access a resource simultaneously.
//! Use cases: resource pools, producer/consumer, rate limiting.
//!
//! Binary semaphore (N=1) is equivalent to a Mutex.

// TODO: Implement with an atomic counter + wait queue.

pub struct Semaphore {
    // TODO: count: AtomicI64
    // TODO: waiters: WaitQueue
}

impl Semaphore {
    pub fn new(_count: i64) -> Self {
        Self {}
    }

    /// Decrement (wait/P operation). Blocks if count == 0.
    pub fn wait(&self) {
        // TODO
    }

    /// Increment (signal/V operation). Wakes one waiter if any.
    pub fn signal(&self) {
        // TODO
    }
}
