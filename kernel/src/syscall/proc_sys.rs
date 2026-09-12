//! Process, signal, time and info system calls.

use crate::arch::x86_64::cpu;
use crate::arch::x86_64::syscall::UserFrame;
use crate::errno::{Errno, KResult};
use crate::proc::{self, ExitStatus, Spawn, WaitFor};
use crate::sched;
use crate::sync::{SpinLock, WaitQueue, WaitResult};
use crate::uaccess;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

pub fn umask(mask: u16) -> KResult<usize> {
    let p = proc::current();
    let mut fs = p.fs.lock();
    let old = fs.umask;
    fs.umask = mask & 0o777;
    Ok(old as usize)
}

pub fn exit(code: i32, _group: bool) -> ! {
    proc::exit_current(ExitStatus::Exited(code));
}

// ── signal dispositions and masks ────────────────────────────────────────────

use crate::proc::signal::{self, SigAction};

/// `rt_sigaction(sig, act, oact, sigsetsize)`. The kernel ABI struct is
/// {handler, flags, restorer, mask} — 32 bytes.
pub fn rt_sigaction(sig: u32, act: usize, oact: usize, _sigsetsize: usize) -> KResult<usize> {
    if sig < 1 || sig > 64 {
        return Err(Errno::EINVAL);
    }
    let me = proc::current();
    let prev = me.sigactions.lock()[sig as usize];
    if oact != 0 {
        uaccess::write_obj(oact, &prev.handler)?;
        uaccess::write_obj(oact + 8, &prev.flags)?;
        uaccess::write_obj(oact + 16, &prev.restorer)?;
        uaccess::write_obj(oact + 24, &prev.mask)?;
    }
    if act != 0 {
        // SIGKILL and SIGSTOP cannot be caught or ignored.
        if sig == signal::SIGKILL || sig == signal::SIGSTOP {
            return Err(Errno::EINVAL);
        }
        let na = SigAction {
            handler: uaccess::read_obj(act)?,
            flags: uaccess::read_obj(act + 8)?,
            restorer: uaccess::read_obj(act + 16)?,
            mask: uaccess::read_obj(act + 24)?,
        };
        me.sigactions.lock()[sig as usize] = na;
        // Keep the fast-path "ignored" bitmask in sync so that a signal set to
        // SIG_IGN (or SIG_DFL for a default-ignored signal) is dropped at post
        // time, and a real handler re-enables posting.
        let bit = 1u64 << (sig - 1);
        let ignore = na.handler == signal::SIG_IGN || (na.handler == signal::SIG_DFL && signal::ignored_by_default(sig));
        if ignore {
            me.ignored.fetch_or(bit, Ordering::Relaxed);
        } else {
            me.ignored.fetch_and(!bit, Ordering::Relaxed);
        }
    }
    Ok(0)
}

/// `rt_sigprocmask(how, set, oldset, sigsetsize)`.
pub fn rt_sigprocmask(how: i32, set: usize, oldset: usize, _sigsetsize: usize) -> KResult<usize> {
    const SIG_BLOCK: i32 = 0;
    const SIG_UNBLOCK: i32 = 1;
    const SIG_SETMASK: i32 = 2;
    let old = sched::with_current(|t| t.blocked());
    if oldset != 0 {
        uaccess::write_obj(oldset, &old)?;
    }
    if set != 0 {
        let m: u64 = uaccess::read_obj(set)?;
        let new = match how {
            SIG_BLOCK => old | m,
            SIG_UNBLOCK => old & !m,
            SIG_SETMASK => m,
            _ => return Err(Errno::EINVAL),
        };
        sched::with_current(|t| t.set_blocked(new));
    }
    Ok(0)
}

/// `rt_sigreturn`: restore the context a signal handler was set up over, and the
/// blocked mask that was in force before the handler ran, then resume that
/// context directly via iretq.
///
/// It must NOT return through the syscall/sysret path: sysret clobbers rcx and
/// r11, but an asynchronously interrupted context (e.g. a SIGALRM off the timer)
/// may have had live values there. `sigreturn_resume` restores all 18 registers.
pub fn rt_sigreturn(frame: &mut UserFrame) -> ! {
    let mut regs = signal::Regs::from_user(frame);
    let mask = match signal::restore_frame(&mut regs) {
        Ok(m) => m,
        // A corrupt sigframe means the process trampled its own stack: kill it.
        Err(_) => proc::exit_current(ExitStatus::Signaled(signal::SIGSEGV)),
    };
    sched::with_current(|t| t.set_blocked(mask));
    // Deliver any further pending, now-unblocked signal before resuming, so a
    // queued signal is not delayed until the next kernel entry.
    proc::deliver_user_signals(&mut regs);
    let image: [u64; 18] = [
        regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15,
        regs.rdi, regs.rsi, regs.rbp, regs.rbx, regs.rdx, regs.rax, regs.rcx, regs.rsp,
        regs.rip, regs.rflags,
    ];
    unsafe { crate::arch::x86_64::syscall::sigreturn_resume(&image) }
}

// ── interval timers (SIGALRM) ────────────────────────────────────────────────

const ITIMER_REAL: i32 = 0;

/// Read a `struct timeval` at `ptr` and return it in nanoseconds.
fn timeval_ns(ptr: usize) -> KResult<u64> {
    let sec: i64 = uaccess::read_obj(ptr)?;
    let usec: i64 = uaccess::read_obj(ptr + 8)?;
    Ok((sec.max(0) as u64) * 1_000_000_000 + (usec.max(0) as u64) * 1_000)
}

/// Write `ns` as a `struct timeval` at `ptr`.
fn write_timeval(ptr: usize, ns: u64) -> KResult<()> {
    uaccess::write_obj(ptr, &((ns / 1_000_000_000) as i64))?;
    uaccess::write_obj(ptr + 8, &(((ns % 1_000_000_000) / 1_000) as i64))
}

/// `setitimer(which, new, old)`. Only `ITIMER_REAL` actually arms; `new` is a
/// `struct itimerval { it_interval; it_value; }`.
pub fn setitimer(which: i32, new: usize, old: usize) -> KResult<usize> {
    let pid = proc::current().pid;
    let (prev_remaining, prev_interval) = if which == ITIMER_REAL && new != 0 {
        let interval_ns = timeval_ns(new)?;
        let value_ns = timeval_ns(new + 16)?;
        proc::itimer::set_real(pid, value_ns, interval_ns)
    } else if which == ITIMER_REAL {
        proc::itimer::get_real(pid) // new == NULL: query only
    } else {
        (0, 0) // VIRTUAL / PROF: accepted, never fires
    };
    if old != 0 {
        write_timeval(old, prev_interval)?;
        write_timeval(old + 16, prev_remaining)?;
    }
    Ok(0)
}

/// `getitimer(which, curr)`.
pub fn getitimer(which: i32, curr: usize) -> KResult<usize> {
    let (remaining, interval) = if which == ITIMER_REAL {
        proc::itimer::get_real(proc::current().pid)
    } else {
        (0, 0)
    };
    if curr != 0 {
        write_timeval(curr, interval)?;
        write_timeval(curr + 16, remaining)?;
    }
    Ok(0)
}

/// `alarm(seconds)`: a one-shot `ITIMER_REAL`. Returns the seconds left on any
/// previous alarm (rounded up).
pub fn alarm(seconds: u32) -> KResult<usize> {
    let pid = proc::current().pid;
    let (prev_remaining, _) = proc::itimer::set_real(pid, seconds as u64 * 1_000_000_000, 0);
    Ok(((prev_remaining + 999_999_999) / 1_000_000_000) as usize)
}

// ── fork / clone ───────────────────────────────────────────────────────────

/// Duplicate the current user process: forked COW address space, copied fd
/// table, credentials and fs context. The child returns 0.
pub fn fork(frame: &UserFrame) -> KResult<usize> {
    let parent = proc::current();
    let aspace = parent.aspace.lock().clone().ok_or(Errno::ENOSYS)?;
    let child_space = aspace.fork()?;
    let spawn = Spawn::from_parent(&parent, &parent.comm(), parent.cmdline());
    let mut child_frame = *frame;
    child_frame.rax = 0; // fork returns 0 in the child
    // The child inherits the parent's thread pointer (FS base): glibc resumes
    // right after the fork syscall and immediately reads %fs:0x10 (the TCB).
    let fs_base = crate::sched::with_current(|t| t.fs_base.load(core::sync::atomic::Ordering::Relaxed));
    let child = proc::start_user_with(spawn, child_space, child_frame, fs_base)?;
    Ok(child.pid as usize)
}

const CLONE_VM: u64 = 0x100;
const CLONE_VFORK: u64 = 0x4000;

/// `clone`. Plain `fork` semantics (a private, copy-on-write child) unless the
/// caller asks for the `vfork`/`posix_spawn` pattern (CLONE_VM|CLONE_VFORK): the
/// child runs on the provided stack and the parent is suspended until the child
/// execs or exits. We honour that by making a normal COW child on the given
/// stack and blocking the parent — functionally identical to vfork for its only
/// real use (a child that only rearranges fds and immediately execs), without
/// the hazard of two tasks sharing one address space.
pub fn clone(flags: u64, stack: u64, frame: &UserFrame) -> KResult<usize> {
    let vfork = flags & CLONE_VFORK != 0;
    if flags & CLONE_VM != 0 && !vfork {
        // Shared-address-space threads are not supported.
        return Err(Errno::ENOSYS);
    }
    let parent = proc::current();
    let aspace = parent.aspace.lock().clone().ok_or(Errno::ENOSYS)?;
    let child_space = aspace.fork()?;
    let mut spawn = Spawn::from_parent(&parent, &parent.comm(), parent.cmdline());
    spawn.vfork = vfork;
    let mut child_frame = *frame;
    child_frame.rax = 0;
    if stack != 0 {
        child_frame.rsp = stack;
    }
    let fs_base = crate::sched::with_current(|t| t.fs_base.load(core::sync::atomic::Ordering::Relaxed));
    let child = proc::start_user_with(spawn, child_space, child_frame, fs_base)?;
    if vfork {
        // Suspend until the child execs (its address space diverges) or exits.
        let c = child.clone();
        let _ = c.vfork_wq.wait_until_interruptible(|| (!c.vfork_pending.load(core::sync::atomic::Ordering::Acquire) || c.is_zombie()).then_some(()), None);
    }
    Ok(child.pid as usize)
}

// ── execve ─────────────────────────────────────────────────────────────────

fn read_str_array(addr: usize) -> KResult<Vec<String>> {
    if addr == 0 {
        return Ok(Vec::new());
    }
    let space = proc::current_aspace().ok_or(Errno::EFAULT)?;
    let mut out = Vec::new();
    let mut a = addr;
    loop {
        let ptr: u64 = uaccess::read_obj(a)?;
        if ptr == 0 {
            break;
        }
        let bytes = space.read_cstr(ptr as usize, 4096)?;
        out.push(String::from_utf8_lossy(&bytes).into_owned());
        a += 8;
        if out.len() > 4096 {
            return Err(Errno::E2BIG);
        }
    }
    Ok(out)
}

/// Replace the current process image with the program at `path`.
pub fn execve(path: usize, argv: usize, envp: usize, frame: &mut UserFrame) -> KResult<usize> {
    let me = proc::current();
    // Read everything from the OLD address space before it is torn down.
    let space = proc::current_aspace().ok_or(Errno::EFAULT)?;
    let path = String::from_utf8_lossy(&space.read_cstr(path, 4096)?).into_owned();
    let mut argv = read_str_array(argv)?;
    let envp = read_str_array(envp)?;
    if argv.is_empty() {
        argv.push(path.clone());
    }
    let ctx = crate::fs::ops::Ctx::of(&me);
    // Verify it is executable by this process.
    let meta = crate::fs::ops::stat(&ctx, &path, true)?;
    crate::fs::perm::check(&me.cred(), &meta, crate::fs::perm::MAY_EXEC)?;
    // Resolve `#!` interpreter scripts, rewriting argv accordingly.
    let (data, argv) = proc::elf::read_exec(&ctx, &path, &argv)?;

    let (new_space, new_frame) = proc::elf::load(&ctx, &data, &argv, &envp)?;
    // Point of no return: swap the address space and run the new image.
    me.fds.lock().close_on_exec();
    // execve resets caught signals to their default; SIG_IGN dispositions and
    // the blocked mask (per-task) persist across exec, as on Linux.
    {
        let ign = me.ignored.load(Ordering::Relaxed);
        let mut t = me.sigactions.lock();
        *t = signal::default_table();
        for sig in 1..=64u32 {
            if ign & (1 << (sig - 1)) != 0 {
                t[sig as usize].handler = signal::SIG_IGN;
            }
        }
    }
    *me.aspace.lock() = Some(new_space.clone());
    me.set_comm(path.rsplit('/').next().unwrap_or(&path));
    me.set_cmdline(argv);
    proc::set_current_cr3(new_space.pml4());
    proc::set_current_fs_base(0);
    unsafe { cpu::wrmsr(cpu::MSR_FS_BASE, 0) };
    new_space.activate();
    *frame = new_frame;
    // The address space has diverged from any vfork/posix_spawn parent: free it.
    me.vfork_release();
    Ok(0)
}

// ── wait / kill ────────────────────────────────────────────────────────────

pub fn wait4(pid: i64, status: usize, _options: i32, _rusage: usize) -> KResult<usize> {
    let me = proc::current();
    let which = match pid {
        p if p > 0 => WaitFor::Pid(p as u32),
        -1 => WaitFor::Any,
        0 => WaitFor::Group(me.pgid.load(core::sync::atomic::Ordering::Relaxed)),
        g => WaitFor::Group((-g) as u32),
    };
    match proc::wait(&me, which, false)? {
        Some((cpid, st)) => {
            if status != 0 {
                uaccess::write_obj(status, &st.wait_status())?;
            }
            Ok(cpid as usize)
        }
        None => Ok(0),
    }
}

pub fn kill(pid: i64, sig: u32) -> KResult<usize> {
    proc::kill(&proc::current(), pid, sig)?;
    Ok(0)
}

/// `tkill(tid, sig)`: signal a single thread. Our processes are single-threaded
/// (pid == tid), so a tid names its process; `raise`/`pthread_kill` land here.
pub fn tkill(tid: i32, sig: u32) -> KResult<usize> {
    if tid <= 0 || sig > 64 {
        return Err(Errno::EINVAL);
    }
    let p = proc::find(tid as u32).ok_or(Errno::ESRCH)?;
    if sig != 0 {
        p.signal(sig);
    }
    Ok(0)
}

/// `tgkill(tgid, tid, sig)`: the thread-group form `raise()` actually uses.
pub fn tgkill(_tgid: i32, tid: i32, sig: u32) -> KResult<usize> {
    tkill(tid, sig)
}

/// `pause`: sleep until a signal arrives, then return EINTR (the pending signal
/// is acted on at the syscall-return boundary).
pub fn pause() -> KResult<usize> {
    loop {
        if sched::with_current(|t| t.signal_pending()) {
            return Err(Errno::EINTR);
        }
        // Wakes early when a signal is delivered (send_signal wakes the task).
        let _ = sched::sleep_ms(3_600_000);
    }
}

// ── info ───────────────────────────────────────────────────────────────────

/// Linux `struct utsname`: six 65-byte fields.
pub fn uname(buf: usize) -> KResult<usize> {
    let mut out = [0u8; 65 * 6];
    let host = proc::current().uts.hostname.lock().clone();
    let fields = ["FastROS", host.as_str(), crate::VERSION, "#1 SMP PREEMPT_DYNAMIC", "x86_64", "(none)"];
    for (i, f) in fields.iter().enumerate() {
        let b = f.as_bytes();
        let n = b.len().min(64);
        out[i * 65..i * 65 + n].copy_from_slice(&b[..n]);
    }
    uaccess::copy_to(buf, &out)?;
    Ok(0)
}

/// `struct timespec { i64 sec; i64 nsec; }`.
fn write_timespec(addr: usize, sec: i64, nsec: i64) -> KResult<()> {
    uaccess::write_obj(addr, &sec)?;
    uaccess::write_obj(addr + 8, &nsec)
}

pub fn clock_gettime(clk: u32, tp: usize) -> KResult<usize> {
    match clk {
        0 => {
            // CLOCK_REALTIME
            let (s, ns) = crate::time::wall_clock();
            write_timespec(tp, s as i64, ns as i64)?;
        }
        _ => {
            // MONOTONIC and the rest: uptime.
            let ns = crate::time::now_ns();
            write_timespec(tp, (ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64)?;
        }
    }
    Ok(0)
}

pub fn clock_getres(_clk: u32, res: usize) -> KResult<usize> {
    if res != 0 {
        write_timespec(res, 0, 1)?;
    }
    Ok(0)
}

pub fn gettimeofday(tv: usize, _tz: usize) -> KResult<usize> {
    if tv != 0 {
        let (s, ns) = crate::time::wall_clock();
        uaccess::write_obj(tv, &(s as i64))?;
        uaccess::write_obj(tv + 8, &((ns / 1000) as i64))?;
    }
    Ok(0)
}

pub fn nanosleep(req: usize, rem: usize) -> KResult<usize> {
    let sec: i64 = uaccess::read_obj(req)?;
    let nsec: i64 = uaccess::read_obj(req + 8)?;
    let ms = (sec as u64).saturating_mul(1000) + (nsec as u64) / 1_000_000;
    if crate::sched::sleep_ms(ms) {
        Ok(0)
    } else {
        if rem != 0 {
            let _ = write_timespec(rem, 0, 0);
        }
        Err(Errno::EINTR)
    }
}

/// `clock_nanosleep(clockid, flags, req, rem)`. TIMER_ABSTIME is treated as a
/// relative sleep of the given duration (close enough for libc `sleep`).
pub fn clock_nanosleep(_clk: u32, _flags: i32, req: usize, rem: usize) -> KResult<usize> {
    nanosleep(req, rem)
}

/// `getresuid`/`getresgid`: report real=effective=saved = the current id.
pub fn getresuid(ruid: usize, euid: usize, suid: usize) -> KResult<usize> {
    let u = proc::current().cred().uid;
    for p in [ruid, euid, suid] {
        if p != 0 {
            uaccess::write_obj(p, &u)?;
        }
    }
    Ok(0)
}

pub fn getresgid(rgid: usize, egid: usize, sgid: usize) -> KResult<usize> {
    let g = proc::current().cred().gid;
    for p in [rgid, egid, sgid] {
        if p != 0 {
            uaccess::write_obj(p, &g)?;
        }
    }
    Ok(0)
}

/// `getpgid(pid)`: the process group of `pid` (0 = the caller).
pub fn getpgid(pid: i64) -> KResult<usize> {
    let p = if pid == 0 { proc::current() } else { proc::find(pid as u32).ok_or(Errno::ESRCH)? };
    Ok(p.pgid.load(core::sync::atomic::Ordering::Relaxed) as usize)
}

/// `setsid`: start a new session and process group led by the caller, detaching
/// its controlling terminal. Daemons (postgres' pg_ctl) rely on this to
/// background themselves. Fails with EPERM if the caller already leads a group.
pub fn setsid() -> KResult<usize> {
    let p = proc::current();
    if p.pgid.load(Ordering::Relaxed) == p.pid {
        return Err(Errno::EPERM);
    }
    p.sid.store(p.pid, Ordering::Relaxed);
    p.pgid.store(p.pid, Ordering::Relaxed);
    *p.ctty.lock() = None;
    Ok(p.pid as usize)
}

/// Resource limits. We enforce none, but programs (nginx) read `RLIMIT_NOFILE`
/// to size their connection tables, so report a generous, sane value rather
/// than zero.
const RLIMIT_NOFILE: u32 = 7;
fn rlimit_for(resource: u32) -> (u64, u64) {
    match resource {
        RLIMIT_NOFILE => (65536, 65536),
        _ => (u64::MAX, u64::MAX), // RLIM_INFINITY
    }
}

pub fn prlimit64(_pid: i32, resource: u32, _new: usize, old: usize) -> KResult<usize> {
    if old != 0 {
        let (cur, max) = rlimit_for(resource);
        uaccess::write_obj(old, &cur)?;
        uaccess::write_obj(old + 8, &max)?;
    }
    Ok(0)
}

pub fn getrlimit(resource: u32, rlim: usize) -> KResult<usize> {
    let (cur, max) = rlimit_for(resource);
    uaccess::write_obj(rlim, &cur)?;
    uaccess::write_obj(rlim + 8, &max)?;
    Ok(0)
}

/// `rt_sigsuspend`: wait until a signal arrives, then return EINTR (its only
/// return). We don't swap the signal mask (handlers are not yet delivered to
/// user mode), so this is a plain interruptible wait — enough for a service
/// master loop that parks here between events.
pub fn rt_sigsuspend() -> KResult<usize> {
    let _ = crate::sched::sleep_ms(1000);
    Err(Errno::EINTR)
}

/// `sched_getaffinity(pid, cpusetsize, mask)`: report a single online CPU.
/// glibc's `get_nprocs()` derives the worker count from this, so a program like
/// nginx sizes its worker pool from what we return here.
pub fn sched_getaffinity(_pid: i32, cpusetsize: usize, mask: usize) -> KResult<usize> {
    let n = cpusetsize.min(128);
    if n == 0 {
        return Err(Errno::EINVAL);
    }
    let mut buf = alloc::vec![0u8; n];
    buf[0] = 0x01; // CPU 0 online
    uaccess::copy_to(mask, &buf)?;
    Ok(n)
}

/// Linux `struct sysinfo` (partial: the fields programs actually read).
pub fn sysinfo(info: usize) -> KResult<usize> {
    let m = crate::mm::stats();
    let mut buf = [0u8; 112];
    let put = |buf: &mut [u8], off: usize, v: u64| buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put(&mut buf, 0, crate::time::uptime_secs()); // uptime
    // loads[3] at 8..32
    put(&mut buf, 32, m.total_bytes); // totalram
    put(&mut buf, 40, m.free_bytes); // freeram
    put(&mut buf, 72, 1); // mem_unit
    // procs at 88 (u16)
    let n = crate::proc::all().len() as u16;
    buf[88..90].copy_from_slice(&n.to_le_bytes());
    uaccess::copy_to(info, &buf)?;
    Ok(0)
}

pub fn getrandom(buf: usize, len: usize, _flags: u32) -> KResult<usize> {
    let mut tmp = alloc::vec![0u8; len.min(1 << 20)];
    crate::crypto::rng::fill(&mut tmp);
    uaccess::copy_to(buf, &tmp)?;
    Ok(tmp.len())
}

// ── futex ────────────────────────────────────────────────────────────────────
//
// glibc and musl build every mutex, condition variable and thread join on top
// of futex, so real dynamic binaries (nginx, postgres) cannot run without it.
// Futexes are keyed by the *physical* frame backing the word, so a futex in
// shared memory is matched across processes. A wake bumps a per-bucket
// generation and wakes the queue; waiters re-check the generation, which makes
// spurious wakeups impossible to miss (and futex users must already tolerate
// spurious wakeups).

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;
const FUTEX_REQUEUE: i32 = 3;
const FUTEX_CMP_REQUEUE: i32 = 4;
const FUTEX_WAIT_BITSET: i32 = 9;
const FUTEX_WAKE_BITSET: i32 = 10;
const FUTEX_PRIVATE_FLAG: i32 = 128;
const FUTEX_CLOCK_REALTIME: i32 = 256;

struct FutexBucket {
    wq: WaitQueue,
    generation: AtomicU64,
}

static FUTEXES: SpinLock<BTreeMap<u64, Arc<FutexBucket>>> = SpinLock::new(BTreeMap::new());

fn futex_bucket(key: u64) -> Arc<FutexBucket> {
    let mut t = FUTEXES.lock();
    t.entry(key).or_insert_with(|| Arc::new(FutexBucket { wq: WaitQueue::new(), generation: AtomicU64::new(0) })).clone()
}

fn futex_existing(key: u64) -> Option<Arc<FutexBucket>> {
    FUTEXES.lock().get(&key).cloned()
}

/// Read a `struct timespec` timeout; relative for FUTEX_WAIT, absolute
/// (CLOCK_MONOTONIC) for FUTEX_WAIT_BITSET. Returns an absolute ns deadline.
fn futex_deadline(ptr: usize, absolute: bool) -> KResult<Option<u64>> {
    if ptr == 0 {
        return Ok(None);
    }
    let sec: i64 = uaccess::read_obj(ptr)?;
    let nsec: i64 = uaccess::read_obj(ptr + 8)?;
    let ns = (sec.max(0) as u64).saturating_mul(1_000_000_000).saturating_add(nsec.max(0) as u64);
    Ok(Some(if absolute { ns } else { crate::time::now_ns().saturating_add(ns) }))
}

pub fn futex(uaddr: usize, op: i32, val: u32, timeout: usize, _uaddr2: usize, _val3: u32) -> KResult<usize> {
    let cmd = op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    let space = proc::current_aspace().ok_or(Errno::EFAULT)?;
    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let key = space.phys_translate(uaddr)?;
            let cur: u32 = uaccess::read_obj(uaddr)?;
            if cur != val {
                return Err(Errno::EAGAIN);
            }
            let b = futex_bucket(key);
            let g = b.generation.load(Ordering::Acquire);
            let deadline = futex_deadline(timeout, cmd == FUTEX_WAIT_BITSET)?;
            match b.wq.wait_until_interruptible(|| (b.generation.load(Ordering::Acquire) != g).then_some(()), deadline) {
                Ok(()) => Ok(0),
                Err(WaitResult::TimedOut) => Err(Errno::ETIMEDOUT),
                Err(WaitResult::Interrupted) => Err(Errno::EINTR),
            }
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let key = space.phys_translate(uaddr)?;
            if let Some(b) = futex_existing(key) {
                b.generation.fetch_add(1, Ordering::Release);
                b.wq.wake_all();
            }
            // The exact count is not tracked; callers use it only as "were any
            // woken", so report the number requested.
            Ok(val as usize)
        }
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            // Approximate requeue by waking the source waiters; they re-acquire.
            let key = space.phys_translate(uaddr)?;
            if let Some(b) = futex_existing(key) {
                b.generation.fetch_add(1, Ordering::Release);
                b.wq.wake_all();
            }
            Ok(0)
        }
        _ => Ok(0),
    }
}
