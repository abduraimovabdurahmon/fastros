//! Process (task) — the unit of isolation in FastROS
//!
//! Each process has:
//!   - Its own address space (PML4 / CR3)
//!   - A kernel stack (used during interrupts/syscalls)
//!   - A file descriptor table
//!   - A signal state
//!   - Namespace + cgroup indices (into global tables)
//!   - An exit code (when Zombie)

use super::fd::FdTable;
use crate::kernel::ipc::signal::SignalState;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pid(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessState {
    Created,  // allocated but not yet runnable
    Ready,    // in the run queue, waiting for CPU
    Running,  // currently on CPU
    Blocked,  // waiting for I/O, sleep, or child
    Zombie,   // exited, waiting for parent to wait()
}

#[derive(Clone, Copy)]
pub struct Process {
    pub pid:    Pid,
    pub ppid:   Pid,    // parent PID
    pub state:  ProcessState,

    /// Physical address of PML4 (loaded into CR3 on context switch).
    pub cr3:    u64,
    /// Top of this process's kernel stack (RSP saved here when in kernel).
    pub kstack_top: u64,

    /// Exit code (valid only when state == Zombie).
    pub exit_code: i32,

    /// Open file descriptors.
    pub fds: FdTable,

    /// Signal state (pending signals, masks, handlers).
    pub signals: SignalState,

    /// Index into the global namespace table (0 = root namespace).
    pub ns_idx: u32,
    /// Index into the global cgroup table (0 = unlimited).
    pub cgroup_idx: u32,
}

impl Process {
    pub fn new(pid: u32, ppid: u32, cr3: u64, kstack_top: u64) -> Self {
        Self {
            pid:    Pid(pid),
            ppid:   Pid(ppid),
            state:  ProcessState::Created,
            cr3,
            kstack_top,
            exit_code:  0,
            fds:        FdTable::new_init(),
            signals:    SignalState::new(),
            ns_idx:     0,
            cgroup_idx: 0,
        }
    }
}
