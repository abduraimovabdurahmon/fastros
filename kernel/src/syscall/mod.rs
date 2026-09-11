//! Linux x86_64 system-call ABI.
//!
//! User programs (ELF binaries in containers, and `fastman`'s own tools) make
//! `SYSCALL`s that land here via [`crate::arch::x86_64::syscall`]. Each handler
//! reads arguments from the [`UserFrame`], acts on the current process's VFS,
//! address space and descriptor table, and returns a value (or a negated
//! errno) in `rax` — exactly as Linux does, so unmodified binaries run.

mod file;
mod mem;
mod proc_sys;

use crate::arch::x86_64::syscall::UserFrame;
use crate::errno::{Errno, KResult};
use crate::proc;

/// Turn a `KResult<usize>` into the Linux convention: a non-negative value on
/// success, `-errno` on error.
pub fn ret(r: KResult<usize>) -> u64 {
    match r {
        Ok(v) => v as u64,
        Err(e) => (-(e as i32 as i64)) as u64,
    }
}

/// Dispatch one system call. Sets `frame.rax` to the result.
pub fn dispatch(frame: &mut UserFrame) {
    let nr = frame.rax;
    let a = frame.args();
    let r = handle(nr, a, frame);
    frame.rax = r;
    // A signal that arrived during the call (or the EINTR it caused) may be
    // fatal with no handler: act on it before returning to ring 3.
    proc::deliver_user_signals();
}

/// Log each unimplemented syscall number at most once (a tight loop calling a
/// missing syscall must not flood the kernel ring buffer).
fn warn_once(nr: u64) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static SEEN: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
    if nr >= 512 {
        return;
    }
    let (word, bit) = (nr as usize / 64, nr % 64);
    let old = SEEN[word].fetch_or(1 << bit, Ordering::Relaxed);
    if old & (1 << bit) == 0 {
        crate::kdebug!("syscall", "unimplemented syscall {nr} (pid {})", proc::current().pid);
    }
}

fn handle(nr: u64, a: [u64; 6], frame: &mut UserFrame) -> u64 {
    match nr {
        // ── file I/O ──
        0 => ret(file::read(a[0] as i32, a[1] as usize, a[2] as usize)),
        1 => ret(file::write(a[0] as i32, a[1] as usize, a[2] as usize)),
        2 => ret(file::open(a[0] as usize, a[1] as u32, a[2] as u16)),
        3 => ret(file::close(a[0] as i32)),
        4 => ret(file::stat(a[0] as usize, a[1] as usize, true)),
        5 => ret(file::fstat(a[0] as i32, a[1] as usize)),
        6 => ret(file::stat(a[0] as usize, a[1] as usize, false)),
        8 => ret(file::lseek(a[0] as i32, a[1] as i64, a[2] as u32)),
        16 => ret(file::ioctl(a[0] as i32, a[1] as u32, a[2] as usize)),
        17 => ret(file::pread(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as u64)),
        18 => ret(file::pwrite(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as u64)),
        19 => ret(file::readv(a[0] as i32, a[1] as usize, a[2] as usize)),
        20 => ret(file::writev(a[0] as i32, a[1] as usize, a[2] as usize)),
        21 => ret(file::access(a[0] as usize, a[1] as u32)),
        22 => ret(file::pipe(a[0] as usize, 0)),
        32 => ret(file::dup(a[0] as i32)),
        33 => ret(file::dup2(a[0] as i32, a[1] as i32)),
        72 => ret(file::fcntl(a[0] as i32, a[1] as u32, a[2] as usize)),
        79 => ret(file::getcwd(a[0] as usize, a[1] as usize)),
        80 => ret(file::chdir(a[0] as usize)),
        81 => ret(file::fchdir(a[0] as i32)),
        82 => ret(file::rename(a[0] as usize, a[1] as usize)),
        83 => ret(file::mkdir(a[0] as usize, a[1] as u16)),
        84 => ret(file::rmdir(a[0] as usize)),
        86 => ret(file::link(a[0] as usize, a[1] as usize)),
        87 => ret(file::unlink(a[0] as usize)),
        88 => ret(file::symlink(a[0] as usize, a[1] as usize)),
        89 => ret(file::readlink(a[0] as usize, a[1] as usize, a[2] as usize)),
        90 => ret(file::chmod(a[0] as usize, a[1] as u16)),
        95 => ret(proc_sys::umask(a[0] as u16)),
        217 => ret(file::getdents64(a[0] as i32, a[1] as usize, a[2] as usize)),
        257 => ret(file::openat(a[0] as i32, a[1] as usize, a[2] as u32, a[3] as u16)),
        262 => ret(file::newfstatat(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as i32)),
        292 => ret(file::dup3(a[0] as i32, a[1] as i32, a[2] as u32)),
        293 => ret(file::pipe(a[0] as usize, a[1] as u32)),

        // ── memory ──
        9 => ret(mem::mmap(a[0], a[1] as usize, a[2] as u32, a[3] as u32, a[4] as i32, a[5])),
        10 => ret(mem::mprotect(a[0] as usize, a[1] as usize, a[2] as u32)),
        11 => ret(mem::munmap(a[0] as usize, a[1] as usize)),
        12 => ret(mem::brk(a[0] as usize)),
        158 => ret(mem::arch_prctl(a[0] as u32, a[1])),

        // ── process / signals / info ──
        24 => {
            crate::sched::yield_now();
            0
        }
        35 => ret(proc_sys::nanosleep(a[0] as usize, a[1] as usize)),
        39 => proc::current().pid as u64,
        56 => ret(proc_sys::clone(a[0], a[1], frame)),
        57 | 58 => ret(proc_sys::fork(frame)),
        59 => ret(proc_sys::execve(a[0] as usize, a[1] as usize, a[2] as usize, frame)),
        60 => proc_sys::exit(a[0] as i32, false),
        61 => ret(proc_sys::wait4(a[0] as i64, a[1] as usize, a[2] as i32, a[3] as usize)),
        62 => ret(proc_sys::kill(a[0] as i64, a[1] as u32)),
        63 => ret(proc_sys::uname(a[0] as usize)),
        96 => ret(proc_sys::gettimeofday(a[0] as usize, a[1] as usize)),
        99 => ret(proc_sys::sysinfo(a[0] as usize)),
        102 | 107 => proc::current().cred().uid as u64,
        104 | 108 => proc::current().cred().gid as u64,
        110 => proc::current().ppid.load(core::sync::atomic::Ordering::Relaxed) as u64,
        111 => proc::current().pgid.load(core::sync::atomic::Ordering::Relaxed) as u64,
        186 => crate::proc::current_tid() as u64,
        201 => crate::time::unix_now(),
        218 => {
            // set_tid_address: we have no clear_child_tid; return the tid.
            crate::proc::current_tid() as u64
        }
        228 => ret(proc_sys::clock_gettime(a[0] as u32, a[1] as usize)),
        229 => ret(proc_sys::clock_getres(a[0] as u32, a[1] as usize)),
        230 => ret(proc_sys::clock_nanosleep(a[0] as u32, a[1] as i32, a[2] as usize, a[3] as usize)),
        231 => proc_sys::exit(a[0] as i32, true),
        318 => ret(proc_sys::getrandom(a[0] as usize, a[1] as usize, a[2] as u32)),

        // rt_sigaction, rt_sigprocmask, sigaltstack, set_robust_list,
        // prlimit64, rseq, prctl: accepted as no-ops so libc starts.
        13 | 14 | 131 | 273 | 302 | 334 | 157 => 0,

        // ── not implemented ──
        _ => {
            warn_once(nr);
            (-(Errno::ENOSYS as i32 as i64)) as u64
        }
    }
}
