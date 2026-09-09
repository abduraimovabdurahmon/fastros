//! Round-Robin scheduler
//!
//! Each thread gets an equal time slice.
//! When the timer fires, the current thread is moved to the back of the queue,
//! and the next thread at the front gets the CPU.

// TODO: Implement a run queue (circular list of Threads).
// TODO: Implement context_switch(current: &mut Thread, next: &Thread).
// TODO: context_switch saves callee-saved registers, switches stack, restores next.

pub fn next_thread() {
    // TODO
}
