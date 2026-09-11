//! Process, signal, time and info system calls.

use crate::arch::x86_64::cpu;
use crate::arch::x86_64::syscall::UserFrame;
use crate::errno::{Errno, KResult};
use crate::proc::{self, ExitStatus, Spawn, WaitFor};
use crate::uaccess;
use alloc::string::String;
use alloc::vec::Vec;

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

/// A subset of `clone`: without CLONE_VM it is `fork`. Thread creation
/// (CLONE_VM, shared address space) is not supported yet.
pub fn clone(flags: u64, _stack: u64, frame: &UserFrame) -> KResult<usize> {
    if flags & CLONE_VM != 0 {
        return Err(Errno::ENOSYS);
    }
    fork(frame)
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
    let data = crate::fs::ops::read_file(&ctx, &path)?;
    if data.len() < 4 || &data[..4] != b"\x7fELF" {
        // Interpreter scripts (#!) could be handled here later.
        return Err(Errno::ENOEXEC);
    }
    // Verify it is executable by this process.
    let meta = crate::fs::ops::stat(&ctx, &path, true)?;
    crate::fs::perm::check(&me.cred(), &meta, crate::fs::perm::MAY_EXEC)?;

    let (new_space, new_frame) = proc::elf::load(&ctx, &data, &argv, &envp)?;
    // Point of no return: swap the address space and run the new image.
    me.fds.lock().close_on_exec();
    *me.aspace.lock() = Some(new_space.clone());
    me.set_comm(path.rsplit('/').next().unwrap_or(&path));
    me.set_cmdline(argv);
    proc::set_current_cr3(new_space.pml4());
    proc::set_current_fs_base(0);
    unsafe { cpu::wrmsr(cpu::MSR_FS_BASE, 0) };
    new_space.activate();
    *frame = new_frame;
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
