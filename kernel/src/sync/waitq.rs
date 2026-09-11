//! Wait queues: block the current task until a condition holds.
//!
//! The condition is re-checked with interrupts disabled right before the task
//! blocks, and wakers run either in task context or in IRQ handlers (which
//! cannot interleave with an IRQ-disabled section on one CPU), so a wake-up
//! can never slip between "condition false" and "task asleep".

use crate::arch::cpu::IrqGuard;
use crate::sched::{self, Task};
use crate::sync::SpinLock;
use alloc::collections::VecDeque;
use alloc::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    TimedOut,
    Interrupted,
}

pub struct WaitQueue {
    waiters: SpinLock<VecDeque<Arc<Task>>>,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self { waiters: SpinLock::new(VecDeque::new()) }
    }

    /// Block (uninterruptibly) until `cond` returns `Some`.
    pub fn wait_until<R>(&self, mut cond: impl FnMut() -> Option<R>) -> R {
        match self.wait(&mut cond, false, None) {
            Ok(v) => v,
            Err(_) => unreachable!("uninterruptible wait without deadline cannot fail"),
        }
    }

    /// Block until `cond` returns `Some`, a signal arrives, or `deadline_ns`
    /// (monotonic, see `time::now_ns`) passes.
    pub fn wait_until_interruptible<R>(
        &self,
        mut cond: impl FnMut() -> Option<R>,
        deadline_ns: Option<u64>,
    ) -> Result<R, WaitResult> {
        self.wait(&mut cond, true, deadline_ns)
    }

    fn wait<R>(
        &self,
        cond: &mut dyn FnMut() -> Option<R>,
        interruptible: bool,
        deadline: Option<u64>,
    ) -> Result<R, WaitResult> {
        loop {
            if let Some(v) = cond() {
                return Ok(v);
            }
            let _irq = IrqGuard::new();
            if let Some(v) = cond() {
                return Ok(v);
            }
            let me = sched::current();
            if interruptible && me.signal_pending() {
                return Err(WaitResult::Interrupted);
            }
            if deadline.is_some_and(|d| crate::time::now_ns() >= d) {
                return Err(WaitResult::TimedOut);
            }
            self.waiters.lock().push_back(me.clone());
            sched::block_current(deadline);
            self.waiters.lock().retain(|t| !Arc::ptr_eq(t, &me));
        }
    }

    pub fn wake_all(&self) {
        let list = core::mem::take(&mut *self.waiters.lock());
        for t in list {
            sched::wake(&t);
        }
    }

    pub fn wake_one(&self) {
        let t = self.waiters.lock().pop_front();
        if let Some(t) = t {
            sched::wake(&t);
        }
    }

    pub fn has_waiters(&self) -> bool {
        !self.waiters.lock().is_empty()
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}
