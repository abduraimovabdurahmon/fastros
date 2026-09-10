//! Memory cgroup controller
//!
//! Tracks and limits memory usage per container.
//! When a container exceeds its limit, the OOM (Out-Of-Memory) killer
//! terminates the heaviest process inside that cgroup.

pub struct MemoryCgroup {
    /// Maximum bytes this cgroup may allocate. 0 = unlimited.
    pub limit_bytes: u64,
    /// Current bytes in use (tracked by PMM/heap).
    pub used_bytes: u64,
}

impl MemoryCgroup {
    pub const fn unlimited() -> Self {
        Self { limit_bytes: 0, used_bytes: 0 }
    }

    pub const fn with_limit(limit_bytes: u64) -> Self {
        Self { limit_bytes, used_bytes: 0 }
    }

    /// Try to charge `bytes` to this cgroup. Returns false if over limit.
    pub fn charge(&mut self, bytes: u64) -> bool {
        if self.limit_bytes != 0 && self.used_bytes + bytes > self.limit_bytes {
            return false; // OOM — caller should trigger OOM kill
        }
        self.used_bytes += bytes;
        true
    }

    /// Release `bytes` back (on free).
    pub fn uncharge(&mut self, bytes: u64) {
        self.used_bytes = self.used_bytes.saturating_sub(bytes);
    }

    /// Returns true if the cgroup is over its memory limit.
    pub fn oom(&self) -> bool {
        if self.limit_bytes == 0 { return false; }
        self.used_bytes >= self.limit_bytes
    }
}
