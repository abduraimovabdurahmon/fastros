//! Linux x86_64 system-call ABI.
//!
//! User programs (ELF binaries in containers, and `fastman`'s own tools) make
//! `SYSCALL`s that land here via [`crate::arch::x86_64::syscall`]. Each handler
//! reads arguments from the [`UserFrame`], acts on the current process's VFS,
//! address space and descriptor table, and returns a value (or a negated
//! errno) in `rax` — exactly as Linux does, so unmodified binaries run.

mod file;
mod mem;
mod net;
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
    // A signal that arrived during the call may run a user handler (which
    // rewrites the frame to enter it) or, with no handler, take a fatal default
    // action before returning to ring 3.
    let mut regs = proc::signal::Regs::from_user(frame);
    proc::deliver_user_signals(&mut regs);
    regs.store_user(frame);
    // Give up the CPU if this task has used its slice, so a syscall-heavy loop
    // is as fair as a compute loop preempted by the timer.
    if crate::sched::need_resched() {
        crate::sched::schedule();
        let mut regs = proc::signal::Regs::from_user(frame);
        proc::deliver_user_signals(&mut regs);
        regs.store_user(frame);
    }
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

/// `ppoll` takes a `struct timespec*` (NULL = block forever); convert it to the
/// millisecond timeout `poll` expects (-1 for NULL/infinite).
pub fn ppoll_timeout_ms(ts: usize) -> i32 {
    if ts == 0 {
        return -1;
    }
    let sec: i64 = crate::uaccess::read_obj(ts).unwrap_or(0);
    let nsec: i64 = crate::uaccess::read_obj(ts + 8).unwrap_or(0);
    (sec.max(0) * 1000 + nsec.max(0) / 1_000_000).min(i32::MAX as i64) as i32
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
        // preadv/pwritev (+ the RWF-flags "2" variants); offset is fully in a[3]
        // on x86_64 (pos_h is always 0), flags in a[5] are accepted and ignored.
        295 => ret(file::preadv(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as i64)),
        296 => ret(file::pwritev(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as i64)),
        327 => ret(file::preadv(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as i64)),
        328 => ret(file::pwritev(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as i64)),
        21 => ret(file::access(a[0] as usize, a[1] as u32)),
        22 => ret(file::pipe(a[0] as usize, 0)),
        92 => ret(file::chown(a[0] as usize, a[1] as u32, a[2] as u32, true)),
        94 => ret(file::chown(a[0] as usize, a[1] as u32, a[2] as u32, false)),
        93 => ret(file::fchown(a[0] as i32, a[1] as u32, a[2] as u32)),
        260 => ret(file::fchownat(a[0] as i32, a[1] as usize, a[2] as u32, a[3] as u32, a[4] as i32)),
        137 => ret(file::statfs(a[0] as usize, a[1] as usize)),
        138 => ret(file::fstatfs(a[0] as i32, a[1] as usize)),
        269 => ret(file::faccessat(a[0] as i32, a[1] as usize, a[2] as u32)),
        439 => ret(file::faccessat(a[0] as i32, a[1] as usize, a[2] as u32)),
        32 => ret(file::dup(a[0] as i32)),
        33 => ret(file::dup2(a[0] as i32, a[1] as i32)),
        72 => ret(file::fcntl(a[0] as i32, a[1] as u32, a[2] as usize)),
        74 | 75 => ret(file::fsync(a[0] as i32)),
        76 => ret(file::truncate(a[0] as usize, a[1] as u64)),
        77 => ret(file::ftruncate(a[0] as i32, a[1] as u64)),
        285 => ret(file::fallocate(a[0] as i32, a[1] as i32, a[2] as u64, a[3] as u64)),
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
        206 => ret(file::io_setup(a[0] as u32, a[1] as usize)),
        207 => ret(file::io_destroy(a[0] as usize)),
        282 => ret(file::signalfd(a[0] as i32, a[1] as usize, a[2] as usize, 0)),
        289 => ret(file::signalfd(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as u32)),
        284 => ret(file::eventfd(a[0] as u32, 0)),
        290 => ret(file::eventfd(a[0] as u32, a[1] as u32)),

        // ── sockets ──
        41 => ret(net::socket(a[0] as i32, a[1] as i32, a[2] as i32)),
        42 => ret(net::connect(a[0] as i32, a[1] as usize, a[2] as usize)),
        43 => ret(net::accept(a[0] as i32, a[1] as usize, a[2] as usize)),
        44 => ret(net::sendto(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as i32, a[4] as usize, a[5] as usize)),
        45 => ret(net::recvfrom(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as i32, a[4] as usize, a[5] as usize)),
        48 => ret(net::shutdown(a[0] as i32, a[1] as i32)),
        49 => ret(net::bind(a[0] as i32, a[1] as usize, a[2] as usize)),
        50 => ret(net::listen(a[0] as i32, a[1] as i32)),
        51 => ret(net::getsockname(a[0] as i32, a[1] as usize, a[2] as usize)),
        52 => ret(net::getpeername(a[0] as i32, a[1] as usize, a[2] as usize)),
        54 => ret(net::setsockopt(a[0] as i32, a[1] as i32, a[2] as i32, a[3] as usize, a[4] as usize)),
        55 => ret(net::getsockopt(a[0] as i32, a[1] as i32, a[2] as i32, a[3] as usize, a[4] as usize)),
        288 => ret(net::accept4(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as i32)),
        53 => ret(net::socketpair(a[0] as i32, a[1] as i32, a[2] as i32, a[3] as usize)),
        130 => ret(proc_sys::rt_sigsuspend()),
        40 => ret(net::sendfile(a[0] as i32, a[1] as i32, a[2] as usize, a[3] as usize)),
        7 => ret(net::poll(a[0] as usize, a[1] as usize, a[2] as i32)),
        23 => ret(net::select(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as usize, a[4] as usize)),
        // pselect6/ppoll: the extra sigmask arg is accepted and ignored; the
        // timeout is a timespec, but poll/select read only its first two words,
        // and a timespec's {sec,nsec} match {sec,usec} closely enough here — for
        // ppoll (timespec) we convert to ms.
        270 => ret(net::pselect6(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as usize, a[4] as usize, a[5] as usize)),
        271 => ret(net::ppoll(a[0] as usize, a[1] as usize, a[2] as usize, a[3] as usize)),
        213 => ret(net::epoll_create(a[0] as i32)),
        232 => ret(net::epoll_wait(a[0] as i32, a[1] as usize, a[2] as i32, a[3] as i32)),
        233 => ret(net::epoll_ctl(a[0] as i32, a[1] as i32, a[2] as i32, a[3] as usize)),
        281 => ret(net::epoll_pwait(a[0] as i32, a[1] as usize, a[2] as i32, a[3] as i32, a[4] as usize)),
        291 => ret(net::epoll_create1(a[0] as i32)),

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
        34 => ret(proc_sys::pause()),
        200 => ret(proc_sys::tkill(a[0] as i32, a[1] as u32)),
        234 => ret(proc_sys::tgkill(a[0] as i32, a[1] as i32, a[2] as u32)),
        63 => ret(proc_sys::uname(a[0] as usize)),
        96 => ret(proc_sys::gettimeofday(a[0] as usize, a[1] as usize)),
        99 => ret(proc_sys::sysinfo(a[0] as usize)),
        102 | 107 => proc::current().cred().uid as u64,
        104 | 108 => proc::current().cred().gid as u64,
        110 => proc::current().ppid.load(core::sync::atomic::Ordering::Relaxed) as u64,
        111 => proc::current().pgid.load(core::sync::atomic::Ordering::Relaxed) as u64,
        112 => ret(proc_sys::setsid()),
        124 => proc::current().sid.load(core::sync::atomic::Ordering::Relaxed) as u64, // getsid
        118 => ret(proc_sys::getresuid(a[0] as usize, a[1] as usize, a[2] as usize)),
        120 => ret(proc_sys::getresgid(a[0] as usize, a[1] as usize, a[2] as usize)),
        121 => ret(proc_sys::getpgid(a[0] as i64)),
        186 => crate::proc::current_tid() as u64,
        201 => crate::time::unix_now(),
        218 => {
            // set_tid_address: we have no clear_child_tid; return the tid.
            crate::proc::current_tid() as u64
        }
        // ── System V shared memory ──
        29 => ret(crate::ipc::shmget(a[0] as i32, a[1] as usize, a[2] as i32)),
        30 => ret(crate::ipc::shmat(a[0] as i32, a[1] as usize, a[2] as i32)),
        31 => ret(crate::ipc::shmctl(a[0] as i32, a[1] as i32, a[2] as usize)),
        67 => ret(crate::ipc::shmdt(a[0] as usize)),
        // ── interval timers (SIGALRM) ──
        36 => ret(proc_sys::getitimer(a[0] as i32, a[1] as usize)),
        37 => ret(proc_sys::alarm(a[0] as u32)),
        38 => ret(proc_sys::setitimer(a[0] as i32, a[1] as usize, a[2] as usize)),
        202 => ret(proc_sys::futex(a[0] as usize, a[1] as i32, a[2] as u32, a[3] as usize, a[4] as usize, a[5] as u32)),
        204 => ret(proc_sys::sched_getaffinity(a[0] as i32, a[1] as usize, a[2] as usize)),
        228 => ret(proc_sys::clock_gettime(a[0] as u32, a[1] as usize)),
        229 => ret(proc_sys::clock_getres(a[0] as u32, a[1] as usize)),
        230 => ret(proc_sys::clock_nanosleep(a[0] as u32, a[1] as i32, a[2] as usize, a[3] as usize)),
        231 => proc_sys::exit(a[0] as i32, true),
        318 => ret(proc_sys::getrandom(a[0] as usize, a[1] as usize, a[2] as u32)),

        // ── signal dispositions ──
        13 => ret(proc_sys::rt_sigaction(a[0] as u32, a[1] as usize, a[2] as usize, a[3] as usize)),
        14 => ret(proc_sys::rt_sigprocmask(a[0] as i32, a[1] as usize, a[2] as usize, a[3] as usize)),
        15 => proc_sys::rt_sigreturn(frame),
        // sigaltstack, set_robust_list, rseq, prctl, sched_setaffinity,
        // fadvise64: accepted as no-ops so libc starts.
        131 | 273 | 334 | 157 | 203 | 221 => 0,
        // sync_file_range: an advisory flush hint. postgres itself falls back to
        // doing nothing when it is unavailable (real durability is the checkpoint
        // fsync), so a success no-op is correct and avoids per-write fsync cost.
        277 => 0,
        97 => ret(proc_sys::getrlimit(a[0] as u32, a[1] as usize)),
        160 => 0, // setrlimit: accepted, not enforced
        302 => ret(proc_sys::prlimit64(a[0] as i32, a[1] as u32, a[2] as usize, a[3] as usize)),

        // Credential setters: a rootless container already runs under the
        // caller's identity and is sandboxed regardless, so a server dropping
        // privileges (nginx worker setgid/setuid/setgroups) succeeds as a no-op
        // instead of failing and exiting. setuid=105 setgid=106
        // setreuid=113 setregid=114 setgroups=116 setresuid=117 setresgid=119
        // setfsuid=122 setfsgid=123 setsid handled elsewhere.
        105 | 106 | 113 | 114 | 116 | 117 | 119 | 122 | 123 => 0,
        // setpgid: job-control shells (bash) put each pipeline in its own group.
        109 => ret(proc_sys::setpgid(a[0] as i64, a[1] as i64)),
        // getgroups: no supplementary groups.
        115 => 0,

        // ── not implemented ──
        _ => {
            warn_once(nr);
            (-(Errno::ENOSYS as i32 as i64)) as u64
        }
    }
}
