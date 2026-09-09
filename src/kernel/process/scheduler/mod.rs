//! CPU Scheduler
//!
//! Decides which thread runs next.
//! Default: Round-Robin (simple, fair for equal-priority tasks).
//! Future: CFS (Completely Fair Scheduler) or priority-based.

pub mod round_robin;

pub fn init() {
    // TODO: Initialize run queue.
}

/// Called by the timer interrupt — pick next thread to run.
pub fn tick() {
    // TODO: round_robin::next()
}
