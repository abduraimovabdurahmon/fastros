//! Thread (execution context within a process)
//!
//! Each process has at least one thread.
//! Threads within one process share the same address space (cr3).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tid(pub u64);

/// Saved CPU registers for context switching.
#[repr(C)]
pub struct Context {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rip: u64, // saved instruction pointer (return address from context_switch)
}

pub struct Thread {
    pub tid:     Tid,
    pub context: Context,
    /// Stack top (kernel stack for this thread).
    pub stack:   u64,
}
