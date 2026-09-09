//! Process (task) representation

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pid(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Created,
    Ready,
    Running,
    Blocked,
    Zombie,
}

pub struct Process {
    pub pid:   Pid,
    pub state: ProcessState,
    /// Physical address of this process's PML4 (address space root).
    pub cr3:   u64,
    /// Kernel stack pointer (saved during context switch).
    pub kstack: u64,
}

impl Process {
    pub fn new(pid: u64, cr3: u64, kstack: u64) -> Self {
        Self {
            pid: Pid(pid),
            state: ProcessState::Created,
            cr3,
            kstack,
        }
    }
}
