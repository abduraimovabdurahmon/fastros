//! Syscall number constants
//!
//! Keep in sync with docs/SYSCALL_TABLE.md

pub const SYS_READ:    u64 = 0;
pub const SYS_WRITE:   u64 = 1;
pub const SYS_OPEN:    u64 = 2;
pub const SYS_CLOSE:   u64 = 3;
pub const SYS_STAT:    u64 = 4;
pub const SYS_MMAP:    u64 = 9;
pub const SYS_MUNMAP:  u64 = 11;
pub const SYS_BRK:     u64 = 12;
pub const SYS_GETPID:  u64 = 39;
pub const SYS_FORK:    u64 = 57;
pub const SYS_EXEC:    u64 = 59;
pub const SYS_EXIT:    u64 = 60;
pub const SYS_WAITPID: u64 = 61;
pub const SYS_YIELD:   u64 = 128;
