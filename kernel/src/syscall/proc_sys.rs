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

// ── prctl / seccomp / capabilities ───────────────────────────────────────────

use super::seccomp;

// prctl operations we implement.
const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_GET_NO_NEW_PRIVS: i32 = 39;
const PR_SET_SECCOMP: i32 = 22;
const PR_GET_SECCOMP: i32 = 21;
const PR_CAPBSET_READ: i32 = 23;
const PR_CAPBSET_DROP: i32 = 24;
const PR_SET_NAME: i32 = 15;
const PR_GET_NAME: i32 = 16;

// SECCOMP modes as passed to PR_SET_SECCOMP.
const SECCOMP_MODE_STRICT: u64 = 1;
const SECCOMP_MODE_FILTER: u64 = 2;

pub fn prctl(option: i32, arg2: u64, arg3: u64, _arg4: u64, _arg5: u64) -> KResult<usize> {
    let p = proc::current();
    match option {
        PR_SET_NO_NEW_PRIVS => {
            if arg2 == 1 {
                p.no_new_privs.store(true, Ordering::Release);
            }
            Ok(0)
        }
        PR_GET_NO_NEW_PRIVS => Ok(p.no_new_privs.load(Ordering::Relaxed) as usize),
        PR_SET_SECCOMP => match arg2 {
            SECCOMP_MODE_STRICT => seccomp::set_strict(),
            SECCOMP_MODE_FILTER => seccomp::install_filter(arg3 as usize),
            _ => Err(Errno::EINVAL),
        },
        PR_GET_SECCOMP => Ok(if p.seccomp_active.load(Ordering::Relaxed) { 2 } else { 0 }),
        PR_CAPBSET_READ => {
            if arg2 > seccomp::CAP_LAST as u64 {
                return Err(Errno::EINVAL);
            }
            Ok((p.caps.load(Ordering::Relaxed) >> arg2 & 1) as usize)
        }
        PR_CAPBSET_DROP => {
            if arg2 > seccomp::CAP_LAST as u64 {
                return Err(Errno::EINVAL);
            }
            // Dropping a bounding-set capability requires CAP_SETPCAP on Linux;
            // we allow a process to drop its own caps freely (only ever reduces
            // privilege), which is what container hardening needs.
            p.caps.fetch_and(!(1u64 << arg2), Ordering::AcqRel);
            Ok(0)
        }
        PR_SET_NAME => {
            let mut buf = [0u8; 16];
            let _ = uaccess::copy_from(arg2 as usize, &mut buf);
            let end = buf.iter().position(|&c| c == 0).unwrap_or(16);
            p.set_comm(&String::from_utf8_lossy(&buf[..end]));
            Ok(0)
        }
        PR_GET_NAME => {
            let mut name = p.comm().into_bytes();
            name.resize(16, 0);
            uaccess::copy_to(arg2 as usize, &name[..16])?;
            Ok(0)
        }
        // Other prctl options (PDEATHSIG, DUMPABLE, THP, …): accept as no-ops.
        _ => Ok(0),
    }
}

pub fn seccomp(op: u32, _flags: u32, args: usize) -> KResult<usize> {
    match op as u64 {
        seccomp::SECCOMP_SET_MODE_STRICT => seccomp::set_strict(),
        seccomp::SECCOMP_SET_MODE_FILTER => seccomp::install_filter(args),
        _ => Err(Errno::EINVAL),
    }
}

/// `capget`: report the current capability set. Linux packs caps into two
/// 32-bit words (v3 header); we mirror the effective set into permitted and
/// inheritable and ignore the target pid (self only).
pub fn capget(hdrp: usize, datap: usize) -> KResult<usize> {
    if hdrp == 0 {
        return Err(Errno::EFAULT);
    }
    let caps = proc::current().caps.load(Ordering::Relaxed);
    if datap != 0 {
        let lo = (caps & 0xffff_ffff) as u32;
        let hi = (caps >> 32) as u32;
        // Two __user_cap_data_struct { effective, permitted, inheritable }.
        for word in 0..2 {
            let v = if word == 0 { lo } else { hi };
            let base = datap + word * 12;
            uaccess::write_obj(base, &v)?; // effective
            uaccess::write_obj(base + 4, &v)?; // permitted
            uaccess::write_obj(base + 8, &v)?; // inheritable
        }
    }
    Ok(0)
}

/// `capset`: set the (effective) capability set. A process may only clear bits
/// or keep ones it already holds — it can never grant itself new capabilities.
pub fn capset(hdrp: usize, datap: usize) -> KResult<usize> {
    if hdrp == 0 || datap == 0 {
        return Err(Errno::EFAULT);
    }
    let e0: u32 = uaccess::read_obj(datap)?;
    let e1: u32 = uaccess::read_obj(datap + 12)?;
    let requested = (e0 as u64) | ((e1 as u64) << 32);
    let p = proc::current();
    let cur = p.caps.load(Ordering::Relaxed);
    // Never allow gaining a capability not already held.
    p.caps.store(requested & cur, Ordering::Release);
    Ok(0)
}

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

/// `sigaltstack(new, old)`: get/set this thread's alternate signal stack. Go
/// installs one per M and its async-preemption handler runs there (SA_ONSTACK);
/// without a real implementation the runtime aborts when a signal arrives off
/// the expected stack. `stack_t` (x86_64): ss_sp @0, ss_flags @8, ss_size @16.
pub fn sigaltstack(new: usize, old: usize) -> KResult<usize> {
    const SS_DISABLE: i32 = 2;
    const SS_ONSTACK: i32 = 1;
    const MINSIGSTKSZ: u64 = 2048;
    let (cur_sp, cur_size) = sched::with_current(|t| {
        (
            t.sas_sp.load(core::sync::atomic::Ordering::Relaxed),
            t.sas_size.load(core::sync::atomic::Ordering::Relaxed),
        )
    });
    if old != 0 {
        // Report SS_ONSTACK if the interrupted context is currently on it — we
        // don't nest handlers, so "on stack" is reported only when installed and
        // the caller's sp is inside it; a plain query just returns the config.
        let flags = if cur_size == 0 { SS_DISABLE } else { 0 };
        uaccess::write_obj(old, &cur_sp)?;
        uaccess::write_obj(old + 8, &flags)?;
        uaccess::write_obj(old + 16, &cur_size)?;
    }
    if new != 0 {
        let sp: u64 = uaccess::read_obj(new)?;
        let flags: i32 = uaccess::read_obj(new + 8)?;
        let size: u64 = uaccess::read_obj(new + 16)?;
        if flags & SS_DISABLE != 0 {
            sched::with_current(|t| {
                t.sas_sp.store(0, core::sync::atomic::Ordering::Relaxed);
                t.sas_size.store(0, core::sync::atomic::Ordering::Relaxed);
            });
        } else {
            if flags & !SS_ONSTACK != 0 {
                return Err(Errno::EINVAL);
            }
            if size < MINSIGSTKSZ {
                return Err(Errno::ENOMEM);
            }
            sched::with_current(|t| {
                t.sas_sp.store(sp, core::sync::atomic::Ordering::Relaxed);
                t.sas_size.store(size, core::sync::atomic::Ordering::Relaxed);
            });
        }
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
const CLONE_SETTLS: u64 = 0x80000;
const CLONE_PARENT_SETTID: u64 = 0x100000;
const CLONE_CHILD_CLEARTID: u64 = 0x200000;
const CLONE_CHILD_SETTID: u64 = 0x1000000;

/// `clone`. CLONE_VM without CLONE_VFORK creates a thread (a task sharing the
/// process's address space, fds and signal handlers — pthread_create). The
/// vfork/posix_spawn pattern (CLONE_VM|CLONE_VFORK) makes a COW child on the
/// given stack and suspends the parent until it execs or exits. Otherwise it is
/// a plain copy-on-write `fork`.
pub fn clone(flags: u64, stack: u64, ptid: usize, ctid: usize, tls: u64, frame: &UserFrame) -> KResult<usize> {
    let vfork = flags & CLONE_VFORK != 0;
    if flags & CLONE_VM != 0 && !vfork {
        // Thread creation.
        let tls_opt = (flags & CLONE_SETTLS != 0).then_some(tls);
        let ptid_p = if flags & CLONE_PARENT_SETTID != 0 { ptid } else { 0 };
        let ctid_set = if flags & CLONE_CHILD_SETTID != 0 { ctid } else { 0 };
        let ctid_clear = if flags & CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 };
        return proc::start_thread(stack, tls_opt, ptid_p, ctid_set, ctid_clear, frame);
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
    //
    // POSIX: execve replaces the entire thread group. Terminate every OTHER
    // thread of this process now — BEFORE the address space is swapped below —
    // or a sibling left runnable would execute in the freed/replaced space and
    // fault (this is exactly what wedged multithreaded Go binaries: gosu calls
    // syscall.Exec while its runtime still has worker threads). Collect first,
    // then reap without holding the task list lock.
    let mytid = crate::sched::current_tid();
    let siblings: Vec<alloc::sync::Arc<crate::sched::Task>> =
        me.tasks().into_iter().filter(|t| t.tid != mytid).collect();
    for t in &siblings {
        crate::sched::kill_task(t);
    }
    me.retain_only_task(mytid);
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
    // Record the absolute executable path for /proc/<pid>/exe. gosu and the Go
    // runtime read this symlink at startup and abort if it does not resolve.
    let exe_path = if path.starts_with('/') {
        path.clone()
    } else {
        let cwd = me.fs.lock().cwd.path();
        if cwd.ends_with('/') { alloc::format!("{cwd}{path}") } else { alloc::format!("{cwd}/{path}") }
    };
    me.set_exe(&exe_path);
    me.set_cmdline(argv);
    proc::set_current_cr3(new_space.pml4());
    proc::set_current_fs_base(0);
    // The old alternate signal stack pointed into the now-replaced address space.
    sched::with_current(|t| {
        t.sas_sp.store(0, Ordering::Relaxed);
        t.sas_size.store(0, Ordering::Relaxed);
    });
    unsafe { cpu::wrmsr(cpu::MSR_FS_BASE, 0) };
    new_space.activate();
    *frame = new_frame;
    // The address space has diverged from any vfork/posix_spawn parent: free it.
    me.vfork_release();
    Ok(0)
}

// ── wait / kill ────────────────────────────────────────────────────────────

pub fn wait4(pid: i64, status: usize, options: i32, _rusage: usize) -> KResult<usize> {
    const WNOHANG: i32 = 1;
    let me = proc::current();
    let which = match pid {
        p if p > 0 => WaitFor::Pid(p as u32),
        -1 => WaitFor::Any,
        0 => WaitFor::Group(me.pgid.load(core::sync::atomic::Ordering::Relaxed)),
        g => WaitFor::Group((-g) as u32),
    };
    // WNOHANG: reap only an already-exited child, never block. postgres'
    // postmaster polls with wait4(-1, WNOHANG) in its reaper; blocking here would
    // trap the whole event loop and it would never accept connections.
    let nohang = options & WNOHANG != 0;
    match proc::wait(&me, which, nohang)? {
        Some((cpid, st)) => {
            if status != 0 {
                uaccess::write_obj(status, &st.wait_status())?;
            }
            Ok(cpid as usize)
        }
        None => Ok(0),
    }
}

/// `getrusage(who, usage)`: fill a `struct rusage` (144 bytes) with the CPU time
/// and peak RSS. Zero-filling it fixes programs (postgres) that print garbage
/// deltas when the call is a no-op.
pub fn getrusage(who: i32, usage: usize) -> KResult<usize> {
    const RUSAGE_CHILDREN: i32 = -1;
    let p = proc::current();
    let cpu_ns = if who == RUSAGE_CHILDREN { p.children_cpu.load(Ordering::Relaxed) } else { p.cpu_ns() };
    let sec = (cpu_ns / 1_000_000_000) as i64;
    let usec = ((cpu_ns % 1_000_000_000) / 1000) as i64;
    let maxrss_kb = p.aspace.lock().as_ref().map(|a| a.rss_bytes() / 1024).unwrap_or(0) as i64;
    let mut buf = [0u8; 144];
    buf[0..8].copy_from_slice(&sec.to_le_bytes()); // ru_utime.tv_sec
    buf[8..16].copy_from_slice(&usec.to_le_bytes()); // ru_utime.tv_usec
    // ru_stime stays 0 (we bill everything as user time).
    buf[32..40].copy_from_slice(&maxrss_kb.to_le_bytes()); // ru_maxrss (KiB)
    uaccess::copy_to(usage, &buf)?;
    Ok(0)
}

pub fn kill(pid: i64, sig: u32) -> KResult<usize> {
    // In a PID namespace, a positive pid is a vpid → translate to the global id
    // (so `kill 1` in a container hits its init, never the host's).
    let pid = if pid > 0 { proc::to_global_pid(pid as u32) as i64 } else { pid };
    proc::kill(&proc::current(), pid, sig)?;
    Ok(0)
}

/// `tkill(tid, sig)`: signal a single thread. Our processes are single-threaded
/// (pid == tid), so a tid names its process; `raise`/`pthread_kill` land here.
pub fn tkill(tid: i32, sig: u32) -> KResult<usize> {
    if tid <= 0 || sig > 64 {
        return Err(Errno::EINVAL);
    }
    // `tid` is a THREAD id, not a process id: look up the task, then its owning
    // process. The previous `proc::find(tid)` treated the tid as a pid, so a
    // multi-threaded program (any Go binary — gosu in the postgres image) could
    // not signal its own threads. That broke Go's async preemption (SIGURG to a
    // specific M) and thread stack dumps, wedging the runtime with one M holding
    // the only P forever.
    let task = crate::sched::find(tid as u32).ok_or(Errno::ESRCH)?;
    let owner = proc::find(task.owner.load(core::sync::atomic::Ordering::Relaxed)).ok_or(Errno::ESRCH)?;
    if sig != 0 {
        // Same permission rule as kill(2): only root or a matching uid may
        // signal a process. Without this, any user could tkill (e.g. SIGKILL)
        // another user's process — tkill must not be a hole around kill().
        let cred = proc::current().cred();
        let tc = owner.cred();
        if !cred.is_root() && cred.euid != tc.uid && cred.uid != tc.uid {
            return Err(Errno::EPERM);
        }
        owner.signal_task(&task, sig);
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
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        return Err(Errno::EINVAL);
    }
    // Keep NANOSECOND precision. Rounding to whole milliseconds turned a Go
    // runtime `usleep(20µs)` into sleep_ms(0) — a no-op — so gosu (postgres
    // image) busy-spun on nanosleep forever instead of yielding to the thread
    // it was waiting for. sleep_ns blocks the task until the deadline.
    let ns = (sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
    sleep_ns_intr(ns, rem)
}

/// Sleep `ns` nanoseconds; on interruption write the (approximate) remaining
/// time to `rem` if non-NULL and return EINTR, matching `nanosleep(2)`.
fn sleep_ns_intr(ns: u64, rem: usize) -> KResult<usize> {
    if crate::sched::sleep_ns(ns) {
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
pub fn clock_nanosleep(clk: u32, flags: i32, req: usize, rem: usize) -> KResult<usize> {
    const TIMER_ABSTIME: i32 = 1;
    let sec: i64 = uaccess::read_obj(req)?;
    let nsec: i64 = uaccess::read_obj(req + 8)?;
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        return Err(Errno::EINVAL);
    }
    let target = (sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
    if flags & TIMER_ABSTIME != 0 {
        // Absolute deadline in clock `clk`: sleep until it, i.e. for
        // (target - now). CLOCK_REALTIME(0) uses wall time, everything else
        // the monotonic uptime — matching clock_gettime above.
        let now = if clk == 0 {
            let (s, ns) = crate::time::wall_clock();
            (s as u64).saturating_mul(1_000_000_000).saturating_add(ns as u64)
        } else {
            crate::time::now_ns()
        };
        // ABSTIME reports no remaining time on interruption.
        sleep_ns_intr(target.saturating_sub(now), 0)
    } else {
        sleep_ns_intr(target, rem)
    }
}

/// `getresuid`/`getresgid`: report real=effective=saved = the current id.
pub fn getresuid(ruid: usize, euid: usize, suid: usize) -> KResult<usize> {
    let c = proc::current().cred();
    for (p, v) in [(ruid, c.uid), (euid, c.euid), (suid, c.suid)] {
        if p != 0 {
            uaccess::write_obj(p, &v)?;
        }
    }
    Ok(0)
}

pub fn getresgid(rgid: usize, egid: usize, sgid: usize) -> KResult<usize> {
    let c = proc::current().cred();
    for (p, v) in [(rgid, c.gid), (egid, c.egid), (sgid, c.sgid)] {
        if p != 0 {
            uaccess::write_obj(p, &v)?;
        }
    }
    Ok(0)
}

// ── credential changes (setuid family) ──────────────────────────────────────
//
// These MUST take effect, not no-op: programs drop privileges through them and
// then check the result. docker-entrypoint re-execs `gosu` until it is no longer
// root (an endless loop if setuid silently does nothing), and postgres refuses
// to run as root. A silent no-op is also a security hole — a process that thinks
// it dropped privileges keeps root. Permission rules follow Linux: root may set
// any id; a non-root process may only switch among its real/effective/saved ids.

const KEEP: u32 = u32::MAX; // -1: leave this id unchanged (setres*/setre*)

pub fn setuid(uid: u32) -> KResult<usize> {
    let me = proc::current();
    let mut c = me.cred.lock();
    if c.euid == 0 {
        c.uid = uid;
        c.euid = uid;
        c.suid = uid;
    } else if uid == c.uid || uid == c.euid || uid == c.suid {
        c.euid = uid;
    } else {
        return Err(Errno::EPERM);
    }
    Ok(0)
}

pub fn setgid(gid: u32) -> KResult<usize> {
    let me = proc::current();
    let mut c = me.cred.lock();
    if c.euid == 0 {
        c.gid = gid;
        c.egid = gid;
        c.sgid = gid;
    } else if gid == c.gid || gid == c.egid || gid == c.sgid {
        c.egid = gid;
    } else {
        return Err(Errno::EPERM);
    }
    Ok(0)
}

pub fn setresuid(r: u32, e: u32, s: u32) -> KResult<usize> {
    let me = proc::current();
    let mut c = me.cred.lock();
    let root = c.euid == 0;
    let allowed = |v: u32| v == KEEP || root || v == c.uid || v == c.euid || v == c.suid;
    if !allowed(r) || !allowed(e) || !allowed(s) {
        return Err(Errno::EPERM);
    }
    if r != KEEP {
        c.uid = r;
    }
    if e != KEEP {
        c.euid = e;
    }
    if s != KEEP {
        c.suid = s;
    }
    Ok(0)
}

pub fn setresgid(r: u32, e: u32, s: u32) -> KResult<usize> {
    let me = proc::current();
    let mut c = me.cred.lock();
    let root = c.euid == 0;
    let allowed = |v: u32| v == KEEP || root || v == c.gid || v == c.egid || v == c.sgid;
    if !allowed(r) || !allowed(e) || !allowed(s) {
        return Err(Errno::EPERM);
    }
    if r != KEEP {
        c.gid = r;
    }
    if e != KEEP {
        c.egid = e;
    }
    if s != KEEP {
        c.sgid = s;
    }
    Ok(0)
}

pub fn setreuid(ruid: u32, euid: u32) -> KResult<usize> {
    let me = proc::current();
    let mut c = me.cred.lock();
    let root = c.euid == 0;
    let allowed = |v: u32| v == KEEP || root || v == c.uid || v == c.euid || v == c.suid;
    if !allowed(ruid) || !allowed(euid) {
        return Err(Errno::EPERM);
    }
    let old_ruid = c.uid;
    if ruid != KEEP {
        c.uid = ruid;
    }
    if euid != KEEP {
        c.euid = euid;
    }
    // If the real uid was set, or the effective uid moved to something other than
    // the previous real uid, the saved uid tracks the new effective uid (Linux).
    if ruid != KEEP || (euid != KEEP && euid != old_ruid) {
        c.suid = c.euid;
    }
    Ok(0)
}

pub fn setregid(rgid: u32, egid: u32) -> KResult<usize> {
    let me = proc::current();
    let mut c = me.cred.lock();
    let root = c.euid == 0;
    let allowed = |v: u32| v == KEEP || root || v == c.gid || v == c.egid || v == c.sgid;
    if !allowed(rgid) || !allowed(egid) {
        return Err(Errno::EPERM);
    }
    let old_rgid = c.gid;
    if rgid != KEEP {
        c.gid = rgid;
    }
    if egid != KEEP {
        c.egid = egid;
    }
    if rgid != KEEP || (egid != KEEP && egid != old_rgid) {
        c.sgid = c.egid;
    }
    Ok(0)
}

/// `setgroups(size, list)`: replace the supplementary group list (root only).
pub fn setgroups(size: usize, list: usize) -> KResult<usize> {
    let me = proc::current();
    if me.cred.lock().euid != 0 {
        return Err(Errno::EPERM);
    }
    if size > 65536 {
        return Err(Errno::EINVAL);
    }
    let mut groups = alloc::vec::Vec::with_capacity(size);
    for i in 0..size {
        let g: u32 = uaccess::read_obj(list + i * 4)?;
        groups.push(g);
    }
    me.cred.lock().groups = groups;
    Ok(0)
}

/// `getpgid(pid)`: the process group of `pid` (0 = the caller).
pub fn getpgid(pid: i64) -> KResult<usize> {
    let p = if pid == 0 { proc::current() } else { proc::find(pid as u32).ok_or(Errno::ESRCH)? };
    Ok(p.pgid.load(core::sync::atomic::Ordering::Relaxed) as usize)
}

/// `setpgid(pid, pgid)`: put a process into a process group — the mechanism a
/// job-control shell (bash) uses to place each pipeline in its own group. A
/// `pid` of 0 means the caller; a `pgid` of 0 means "use `pid`" (become a group
/// leader). Only the caller or one of its children may be moved, and a child
/// that has already `execve`'d cannot. We don't enforce the session checks, but
/// implementing this (rather than ENOSYS) stops bash printing
/// "child setpgid: Function not implemented" on every command.
pub fn setpgid(pid: i64, pgid: i64) -> KResult<usize> {
    if pid < 0 || pgid < 0 {
        return Err(Errno::EINVAL);
    }
    let me = proc::current();
    let target = if pid == 0 || pid as u32 == me.pid { me.clone() } else { proc::find(pid as u32).ok_or(Errno::ESRCH)? };
    // Only self or a child may be repositioned.
    if target.pid != me.pid && target.ppid.load(Ordering::Relaxed) != me.pid {
        return Err(Errno::ESRCH);
    }
    let new = if pgid == 0 { target.pid } else { pgid as u32 };
    target.pgid.store(new, Ordering::Relaxed);
    Ok(0)
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

/// Wake any waiters on the futex at `uaddr` (used for a thread's clear_child_tid
/// on exit, so `pthread_join` returns).
pub fn futex_wake_addr(uaddr: usize) {
    if let Some(space) = proc::current_aspace() {
        if let Ok(key) = space.phys_translate(uaddr) {
            if let Some(b) = futex_existing(key) {
                b.generation.fetch_add(1, Ordering::Release);
                b.wq.wake_all();
            }
        }
    }
}

pub fn futex(uaddr: usize, op: i32, val: u32, timeout: usize, _uaddr2: usize, _val3: u32) -> KResult<usize> {
    let cmd = op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    let space = proc::current_aspace().ok_or(Errno::EFAULT)?;
    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let key = space.phys_translate(uaddr)?;
            // Snapshot the generation BEFORE reading the futex word. If a
            // concurrent FUTEX_WAKE lands between the value read and this load,
            // the bump would already be folded into `g` and we would then sleep
            // waiting for the *next* bump that never comes — a lost wakeup that
            // strands, e.g., the Go runtime's main thread. With `g` taken first:
            // a wake after it makes `generation != g` true (wait returns at
            // once), and a wake before it changed the word (cur != val → EAGAIN).
            let b = futex_bucket(key);
            let g = b.generation.load(Ordering::Acquire);
            let cur: u32 = uaccess::read_obj(uaddr)?;
            if cur != val {
                return Err(Errno::EAGAIN);
            }
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
