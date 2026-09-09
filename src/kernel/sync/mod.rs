//! Kernel synchronization primitives
//!
//! Rule: use the WEAKEST primitive that solves your problem.
//!   spinlock   → very short critical sections, interrupts may be disabled
//!   mutex      → longer critical sections, thread may sleep
//!   semaphore  → resource counting, producer/consumer

pub mod mutex;
pub mod semaphore;
pub mod spinlock;

pub fn init() {
    // Nothing to do — primitives are zero-initialized.
}
