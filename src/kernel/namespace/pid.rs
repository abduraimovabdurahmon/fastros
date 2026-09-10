//! PID Namespace
//!
//! Each PID namespace has its own PID counter starting at 1.
//! A process inside a container sees itself as PID 1 (init).
//! The host kernel sees the real PID.

use super::{Namespace, NsId};

pub struct PidNamespace {
    id: NsId,
    next_pid: u32,
}

impl PidNamespace {
    pub const fn root() -> Self {
        Self { id: 0, next_pid: 1 }
    }

    pub fn new(id: NsId) -> Self {
        Self { id, next_pid: 1 }
    }

    /// Allocate the next PID inside this namespace.
    pub fn alloc_pid(&mut self) -> u32 {
        // TODO: wrap around, handle exhaustion
        let pid = self.next_pid;
        self.next_pid += 1;
        pid
    }
}

impl Namespace for PidNamespace {
    fn id(&self) -> NsId { self.id }
}
