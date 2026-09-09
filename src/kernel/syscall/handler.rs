//! Syscall dispatch handler
//!
//! Called from the arch-specific SYSCALL entry stub with registers saved.

use super::numbers::*;

/// Main syscall dispatcher. Called with the syscall number and arguments.
/// Returns the value to put in rax (result or error code).
pub fn dispatch(nr: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    match nr {
        SYS_WRITE  => sys_write(arg0, arg1, arg2),
        SYS_READ   => sys_read(arg0, arg1, arg2),
        SYS_EXIT   => sys_exit(arg0),
        SYS_GETPID => sys_getpid(),
        SYS_YIELD  => sys_yield(),
        _          => -38, // ENOSYS
    }
}

fn sys_write(_fd: u64, _buf: u64, _len: u64) -> i64 {
    // TODO: validate buf pointer, write to fd
    -38
}

fn sys_read(_fd: u64, _buf: u64, _len: u64) -> i64 {
    // TODO: validate buf pointer, read from fd
    -38
}

fn sys_exit(_code: u64) -> i64 {
    // TODO: terminate current process
    loop {}
}

fn sys_getpid() -> i64 {
    // TODO: return current process pid
    0
}

fn sys_yield() -> i64 {
    // TODO: voluntarily give up CPU
    0
}
