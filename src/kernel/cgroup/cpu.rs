//! CPU cgroup controller
//!
//! Implements CFS (Completely Fair Scheduler) bandwidth control.
//! A cgroup can use at most `quota` microseconds per `period` microseconds.
//!
//! Example: quota=50000, period=100000 → max 50% CPU

pub struct CpuCgroup {
    /// CPU time allowed per period (microseconds). 0 = unlimited.
    pub quota_us: u64,
    /// Period length (microseconds).
    pub period_us: u64,
    /// CPU time used in the current period (tracked by scheduler).
    pub used_us: u64,
}

impl CpuCgroup {
    pub const fn unlimited() -> Self {
        Self { quota_us: 0, period_us: 100_000, used_us: 0 }
    }

    pub const fn with_limit(quota_us: u64, period_us: u64) -> Self {
        Self { quota_us, period_us, used_us: 0 }
    }

    /// Returns true if this cgroup has exceeded its CPU quota.
    pub fn throttled(&self) -> bool {
        if self.quota_us == 0 { return false; }
        self.used_us >= self.quota_us
    }

    /// Account for CPU time used. Called by the scheduler on each tick.
    pub fn charge(&mut self, us: u64) {
        self.used_us = self.used_us.saturating_add(us);
    }

    /// Reset usage counter at the start of a new period.
    pub fn reset_period(&mut self) {
        self.used_us = 0;
    }
}
