//! Syscall dispatch handler
//!
//! Called from the SYSCALL entry assembly stub in boot.s.
//! Convention: rdi=nr, rsi=arg0, rdx=arg1, rcx=arg2 → return i64 in rax.
//! Negative return = errno (Linux-compatible error codes).

use super::numbers::*;
use crate::kernel::process;
use crate::kernel::memory::vmm;

/// Exported as C symbol so boot.s SYSCALL stub can call it.
#[no_mangle]
pub extern "C" fn kernel_syscall_dispatch(nr: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    dispatch(nr, arg0, arg1, arg2)
}

pub fn dispatch(nr: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    match nr {
        SYS_READ    => sys_read(arg0, arg1, arg2),
        SYS_WRITE   => sys_write(arg0, arg1, arg2),
        SYS_OPEN    => sys_open(arg0, arg1, arg2),
        SYS_CLOSE   => sys_close(arg0),
        SYS_MMAP    => sys_mmap(arg0, arg1, arg2),
        SYS_MUNMAP  => sys_munmap(arg0, arg1),
        SYS_BRK     => sys_brk(arg0),
        SYS_GETPID  => sys_getpid(),
        SYS_GETPPID => sys_getppid(),
        SYS_FORK    => sys_fork(),
        SYS_EXIT    => sys_exit(arg0 as i32),
        SYS_WAITPID => sys_waitpid(arg0 as i32),
        SYS_YIELD   => sys_yield(),
        SYS_KILL    => sys_kill(arg0 as u32, arg1 as u8),
        SYS_SIGACTION => sys_sigaction(arg0 as u8, arg1),
        _           => -38, // ENOSYS
    }
}

// ── File I/O ──────────────────────────────────────────────────────────────────

fn sys_read(fd: u64, buf_ptr: u64, len: u64) -> i64 {
    // TODO: validate buf_ptr is in user address space
    // TODO: look up fd in current process's FdTable
    // TODO: dispatch to vfs::read()
    let _ = (fd, buf_ptr, len);
    -38 // ENOSYS
}

fn sys_write(fd: u64, buf_ptr: u64, len: u64) -> i64 {
    if buf_ptr == 0 || len == 0 { return -22; } // EINVAL
    // FD 1/2 (stdout/stderr) → serial output for now
    if fd == 1 || fd == 2 {
        let bytes = unsafe {
            core::slice::from_raw_parts(buf_ptr as *const u8, len as usize)
        };
        crate::drivers::char::serial::write(bytes);
        return len as i64;
    }
    // TODO: dispatch to vfs::write() for file descriptors
    -9 // EBADF
}

fn sys_open(_path_ptr: u64, _flags: u64, _mode: u64) -> i64 {
    // TODO: validate path, walk VFS, return new fd
    -38 // ENOSYS
}

fn sys_close(fd: u64) -> i64 {
    let idx = process::scheduler::round_robin::current();
    if idx == usize::MAX { return -3; } // ESRCH
    unsafe {
        let proc = process::PROCESS_TABLE[idx].assume_init_mut();
        if proc.fds.close(fd as usize) { 0 } else { -9 } // EBADF
    }
}

// ── Memory ───────────────────────────────────────────────────────────────────

fn sys_mmap(addr: u64, len: u64, prot: u64) -> i64 {
    if len == 0 { return -22; } // EINVAL
    let size  = (len + 0xFFF) & !0xFFF; // round up to page
    let vaddr = if addr != 0 { addr } else { 0x8000_0000 }; // default user addr
    let page_flags = crate::arch::x86_64::memory::paging::flags::USER_RW;
    if vmm::alloc_map(vaddr, size, page_flags) {
        vaddr as i64
    } else {
        -12 // ENOMEM
    }
}

fn sys_munmap(addr: u64, len: u64) -> i64 {
    let pages = (len + 0xFFF) / 4096;
    for i in 0..pages {
        vmm::unmap_free(addr + i * 4096);
    }
    0
}

fn sys_brk(new_brk: u64) -> i64 {
    // TODO: implement per-process brk pointer
    // For now return the requested address (pretend success)
    new_brk as i64
}

// ── Process ───────────────────────────────────────────────────────────────────

fn sys_getpid() -> i64 {
    let idx = process::scheduler::round_robin::current();
    if idx == usize::MAX { return 0; }
    unsafe { process::PROCESS_TABLE[idx].assume_init_ref().pid.0 as i64 }
}

fn sys_getppid() -> i64 {
    let idx = process::scheduler::round_robin::current();
    if idx == usize::MAX { return 0; }
    unsafe { process::PROCESS_TABLE[idx].assume_init_ref().ppid.0 as i64 }
}

fn sys_fork() -> i64 {
    match process::fork() {
        Ok(child_pid) => child_pid as i64,
        Err(_)        => -12, // ENOMEM
    }
}

fn sys_exit(code: i32) -> i64 {
    process::exit(code);
}

fn sys_waitpid(_pid: i32) -> i64 {
    match process::wait() {
        Some((child_pid, exit_code)) => {
            // Encode: upper 8 bits = exit code, lower = 0 (normal exit)
            ((exit_code as i64 & 0xFF) << 8) | (child_pid as i64)
        }
        None => -10, // ECHILD
    }
}

fn sys_yield() -> i64 {
    process::scheduler::yield_cpu();
    0
}

// ── Signals ───────────────────────────────────────────────────────────────────

fn sys_kill(target_pid: u32, sig: u8) -> i64 {
    unsafe {
        for i in 0..process::MAX_PROCESSES {
            if process::PROCESS_USED[i] {
                let proc = process::PROCESS_TABLE[i].assume_init_mut();
                if proc.pid.0 == target_pid {
                    proc.signals.send(sig);
                    return 0;
                }
            }
        }
    }
    -3 // ESRCH — process not found
}

fn sys_sigaction(sig: u8, handler_ptr: u64) -> i64 {
    use crate::kernel::ipc::signal::{SigAction, SigSet};
    let idx = process::scheduler::round_robin::current();
    if idx == usize::MAX { return -3; }
    let action = SigAction {
        handler: if handler_ptr == 0 { None } else { Some(handler_ptr) },
        mask:    SigSet::empty(),
        flags:   0,
    };
    unsafe {
        process::PROCESS_TABLE[idx].assume_init_mut().signals.set_action(sig, action);
    }
    0
}
