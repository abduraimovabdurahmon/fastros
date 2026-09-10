//! Syscall number constants (Linux x86_64 ABI compatible)

pub const SYS_READ:      u64 = 0;
pub const SYS_WRITE:     u64 = 1;
pub const SYS_OPEN:      u64 = 2;
pub const SYS_CLOSE:     u64 = 3;
pub const SYS_STAT:      u64 = 4;
pub const SYS_FSTAT:     u64 = 5;
pub const SYS_MMAP:      u64 = 9;
pub const SYS_MUNMAP:    u64 = 11;
pub const SYS_BRK:       u64 = 12;
pub const SYS_SIGACTION: u64 = 13;
pub const SYS_KILL:      u64 = 62;
pub const SYS_GETPID:    u64 = 39;
pub const SYS_GETPPID:   u64 = 110;
pub const SYS_FORK:      u64 = 57;
pub const SYS_EXEC:      u64 = 59;
pub const SYS_EXIT:      u64 = 60;
pub const SYS_WAITPID:   u64 = 61;
pub const SYS_YIELD:     u64 = 24;
pub const SYS_PIPE:      u64 = 22;
pub const SYS_DUP:       u64 = 32;
pub const SYS_DUP2:      u64 = 33;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETUID:    u64 = 102;
pub const SYS_GETGID:    u64 = 104;
pub const SYS_SETUID:    u64 = 105;
pub const SYS_SETGID:    u64 = 106;
pub const SYS_SIGRETURN: u64 = 15;

// FastROS-specific (>= 512)
pub const SYS_CONTAINER_CREATE: u64 = 512;
pub const SYS_CONTAINER_START:  u64 = 513;
pub const SYS_CONTAINER_STOP:   u64 = 514;
pub const SYS_CONTAINER_DELETE: u64 = 515;
