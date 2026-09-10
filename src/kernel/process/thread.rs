//! Thread — execution context within a process
//!
//! Each process has at least one thread.
//! Threads within one process share the same address space (cr3).
//!
//! Context layout must match the `context_switch` assembly in boot.s:
//!   offset  0: r15
//!   offset  8: r14
//!   offset 16: r13
//!   offset 24: r12
//!   offset 32: rbp
//!   offset 40: rbx
//!   offset 48: rip  (saved return address — where execution resumes)

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tid(pub u32);

/// Callee-saved registers + instruction pointer.
/// Layout matches the `context_switch` assembly stub in boot.s.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Context {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    /// Saved RIP — the address `context_switch` will jump to when this
    /// thread is next scheduled.  Points to the instruction after the
    /// `call context_switch` in the previous run.
    pub rip: u64,
}

impl Context {
    pub const fn zeroed() -> Self {
        Self { r15: 0, r14: 0, r13: 0, r12: 0, rbp: 0, rbx: 0, rip: 0 }
    }
}

#[derive(Clone, Copy)]
pub struct Thread {
    pub tid:     Tid,
    /// Index into PROCESS_TABLE — which process owns this thread.
    pub proc_idx: usize,
    /// Saved CPU context (callee-saved registers + RIP).
    pub context: Context,
    /// Top of this thread's kernel stack.
    pub kstack_top: u64,
}

impl Thread {
    pub fn new(tid: u32, proc_idx: usize, entry: u64, kstack_top: u64) -> Self {
        let mut ctx = Context::zeroed();
        ctx.rip = entry;     // first schedule → jump to `entry`
        ctx.rbp = kstack_top;
        Self { tid: Tid(tid), proc_idx, context: ctx, kstack_top }
    }
}
