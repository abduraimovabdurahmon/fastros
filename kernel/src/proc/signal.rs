//! Signal numbers, default dispositions, and user-handler dispatch
//! (Linux x86_64 values and `rt_sigframe` layout).

use crate::errno::{Errno, KResult};
use crate::uaccess;

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGSTKFLT: u32 = 16;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGURG: u32 = 23;
pub const SIGXCPU: u32 = 24;
pub const SIGXFSZ: u32 = 25;
pub const SIGVTALRM: u32 = 26;
pub const SIGPROF: u32 = 27;
pub const SIGWINCH: u32 = 28;
pub const SIGIO: u32 = 29;
pub const SIGPWR: u32 = 30;
pub const SIGSYS: u32 = 31;
pub const NSIG: u32 = 64;

const NAMES: [&str; 32] = [
    "", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM",
    "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF",
    "WINCH", "IO", "PWR", "SYS",
];

/// `TERM` for 15, `RTMIN+2` for 36...
pub fn name(sig: u32) -> alloc::string::String {
    use alloc::string::ToString;
    if (1..32).contains(&sig) {
        NAMES[sig as usize].to_string()
    } else if (32..=64).contains(&sig) {
        alloc::format!("RTMIN+{}", sig - 32)
    } else {
        alloc::format!("{sig}")
    }
}

/// Parse `TERM`, `SIGTERM`, `term` or `15`.
pub fn parse(s: &str) -> Option<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return (n <= NSIG).then_some(n);
    }
    let up = s.to_ascii_uppercase();
    let bare = up.strip_prefix("SIG").unwrap_or(&up);
    NAMES.iter().position(|&n| !n.is_empty() && n == bare).map(|i| i as u32)
}

/// Signals whose default action stops the process (we treat stop as a no-op
/// for now — no job control for user containers yet).
pub fn stops_by_default(sig: u32) -> bool {
    matches!(sig, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU)
}

/// Would this signal, with no handler installed, terminate the process?
pub fn terminates_by_default(sig: u32) -> bool {
    sig != 0 && !ignored_by_default(sig) && !stops_by_default(sig)
}

/// Signals whose default action is to ignore them.
pub fn ignored_by_default(sig: u32) -> bool {
    matches!(sig, SIGCHLD | SIGWINCH | SIGURG | SIGCONT)
}

// ── user signal handlers (sigaction / rt_sigreturn) ─────────────────────────

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

pub const SA_SIGINFO: u64 = 0x0000_0004;
pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;

/// One process-wide signal disposition (the kernel `rt_sigaction` layout:
/// handler, flags, restorer, mask — in that order).
#[derive(Clone, Copy)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

impl SigAction {
    pub const DFL: SigAction = SigAction { handler: SIG_DFL, flags: 0, restorer: 0, mask: 0 };
}

/// Signal disposition table, indexed by signal number (1..=64); index 0 unused.
pub type SigTable = [SigAction; 65];

pub const fn default_table() -> SigTable {
    [SigAction::DFL; 65]
}

/// A normalized snapshot of the interrupted user register state. Both the
/// syscall-return frame ([`crate::arch::x86_64::syscall::UserFrame`]) and the
/// interrupt frame ([`crate::arch::x86_64::trap::TrapFrame`]) convert to and
/// from this, so handler dispatch is written once for both entry paths.
#[derive(Clone, Copy, Default)]
pub struct Regs {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl Regs {
    /// Snapshot the syscall-return frame. `UserFrame` does not store rcx/r11
    /// (SYSCALL clobbers them and sysret reuses them for rip/rflags), so they
    /// are reconstructed — harmless, as the interrupted point is post-syscall.
    pub fn from_user(f: &crate::arch::x86_64::syscall::UserFrame) -> Regs {
        Regs {
            r8: f.r8, r9: f.r9, r10: f.r10, r11: f.rflags,
            r12: f.r12, r13: f.r13, r14: f.r14, r15: f.r15,
            rdi: f.rdi, rsi: f.rsi, rbp: f.rbp, rbx: f.rbx,
            rdx: f.rdx, rax: f.rax, rcx: f.rip, rsp: f.rsp,
            rip: f.rip, rflags: f.rflags,
        }
    }
    pub fn store_user(&self, f: &mut crate::arch::x86_64::syscall::UserFrame) {
        f.r8 = self.r8; f.r9 = self.r9; f.r10 = self.r10;
        f.r12 = self.r12; f.r13 = self.r13; f.r14 = self.r14; f.r15 = self.r15;
        f.rdi = self.rdi; f.rsi = self.rsi; f.rbp = self.rbp; f.rbx = self.rbx;
        f.rdx = self.rdx; f.rax = self.rax; f.rsp = self.rsp;
        f.rip = self.rip; f.rflags = self.rflags;
    }
    pub fn from_trap(f: &crate::arch::x86_64::trap::TrapFrame) -> Regs {
        Regs {
            r8: f.r8, r9: f.r9, r10: f.r10, r11: f.r11,
            r12: f.r12, r13: f.r13, r14: f.r14, r15: f.r15,
            rdi: f.rdi, rsi: f.rsi, rbp: f.rbp, rbx: f.rbx,
            rdx: f.rdx, rax: f.rax, rcx: f.rcx, rsp: f.rsp,
            rip: f.rip, rflags: f.rflags,
        }
    }
    pub fn store_trap(&self, f: &mut crate::arch::x86_64::trap::TrapFrame) {
        f.r8 = self.r8; f.r9 = self.r9; f.r10 = self.r10; f.r11 = self.r11;
        f.r12 = self.r12; f.r13 = self.r13; f.r14 = self.r14; f.r15 = self.r15;
        f.rdi = self.rdi; f.rsi = self.rsi; f.rbp = self.rbp; f.rbx = self.rbx;
        f.rdx = self.rdx; f.rax = self.rax; f.rcx = self.rcx; f.rsp = self.rsp;
        f.rip = self.rip; f.rflags = self.rflags;
    }
}

// `struct ucontext` / `struct sigcontext` (x86_64) offsets we build and read.
const UC_SIZE: usize = 512;
const UC_MCTX: usize = 40; // offsetof(ucontext, uc_mcontext)
const UC_SIGMASK: usize = 40 + 256; // offsetof(ucontext, uc_sigmask)
const SIGINFO_SIZE: usize = 128;

/// Write a `struct sigcontext` (mcontext) for `r` into `buf` at `UC_MCTX`.
fn write_mcontext(buf: &mut [u8], r: &Regs) {
    let mut put = |off: usize, v: u64| buf[UC_MCTX + off..UC_MCTX + off + 8].copy_from_slice(&v.to_le_bytes());
    put(0, r.r8);
    put(8, r.r9);
    put(16, r.r10);
    put(24, r.r11);
    put(32, r.r12);
    put(40, r.r13);
    put(48, r.r14);
    put(56, r.r15);
    put(64, r.rdi);
    put(72, r.rsi);
    put(80, r.rbp);
    put(88, r.rbx);
    put(96, r.rdx);
    put(104, r.rax);
    put(112, r.rcx);
    put(120, r.rsp);
    put(128, r.rip);
    put(136, r.rflags);
}

/// Read back the registers a handler's `ucontext` (at user address `uc`) holds.
fn read_mcontext(uc: usize) -> KResult<Regs> {
    let mut b = [0u8; UC_SIZE];
    uaccess::copy_from(uc, &mut b)?;
    let get = |off: usize| -> u64 {
        let mut v = [0u8; 8];
        v.copy_from_slice(&b[UC_MCTX + off..UC_MCTX + off + 8]);
        u64::from_le_bytes(v)
    };
    Ok(Regs {
        r8: get(0),
        r9: get(8),
        r10: get(16),
        r11: get(24),
        r12: get(32),
        r13: get(40),
        r14: get(48),
        r15: get(56),
        rdi: get(64),
        rsi: get(72),
        rbp: get(80),
        rbx: get(88),
        rdx: get(96),
        rax: get(104),
        rcx: get(112),
        rsp: get(120),
        rip: get(128),
        rflags: get(136),
    })
}

/// The old signal mask a handler's `ucontext` saved (restored on sigreturn).
fn read_sigmask(uc: usize) -> KResult<u64> {
    let mut b = [0u8; 8];
    uaccess::copy_from(uc + UC_SIGMASK, &mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Build an `rt_sigframe` on the user stack and return the register state that
/// enters the handler. On handler return the (libc-provided) `restorer` invokes
/// `rt_sigreturn`, which [`restore_frame`] undoes.
pub fn setup_frame(regs: &Regs, sig: u32, act: &SigAction, old_mask: u64) -> KResult<Regs> {
    // Lay the frame out below the interrupted stack pointer, past the red zone.
    let mut sp = (regs.rsp as usize).checked_sub(128).ok_or(Errno::EFAULT)?;
    sp &= !15;
    sp -= SIGINFO_SIZE;
    let info = sp;
    sp -= UC_SIZE;
    let uc = sp; // 16-aligned
    sp -= 8;
    let frame = sp; // pretcode slot; frame % 16 == 8, and uc == frame + 8

    // siginfo: si_signo, si_errno, si_code (enough for a POSIX handler).
    let mut si = [0u8; SIGINFO_SIZE];
    si[0..4].copy_from_slice(&(sig as i32).to_le_bytes());
    uaccess::copy_to(info, &si)?;

    // ucontext: mcontext with the saved regs + the old blocked mask.
    let mut ucb = [0u8; UC_SIZE];
    write_mcontext(&mut ucb, regs);
    ucb[UC_SIGMASK..UC_SIGMASK + 8].copy_from_slice(&old_mask.to_le_bytes());
    uaccess::copy_to(uc, &ucb)?;

    // pretcode = the libc restorer trampoline (`mov rt_sigreturn; syscall`).
    uaccess::copy_to(frame, &act.restorer.to_le_bytes())?;

    let siginfo = act.flags & SA_SIGINFO != 0;
    let mut nr = *regs;
    nr.rip = act.handler;
    nr.rsp = frame as u64;
    nr.rdi = sig as u64;
    nr.rsi = if siginfo { info as u64 } else { 0 };
    nr.rdx = if siginfo { uc as u64 } else { 0 };
    nr.rax = 0; // no vector registers passed (varargs ABI)
    nr.rflags &= !0x400; // clear DF, as the ABI requires at a call boundary
    Ok(nr)
}

/// `rt_sigreturn`: the user stack pointer sits at the `ucontext`; restore the
/// saved register state and return the blocked mask to reinstate.
pub fn restore_frame(regs: &mut Regs) -> KResult<u64> {
    let uc = regs.rsp as usize;
    let saved = read_mcontext(uc)?;
    let mask = read_sigmask(uc)?;
    *regs = saved;
    Ok(mask)
}

/// Human description (as `strsignal` / shells print on abnormal exit).
pub fn describe(sig: u32) -> &'static str {
    match sig {
        SIGHUP => "Hangup",
        SIGINT => "Interrupt",
        SIGQUIT => "Quit",
        SIGILL => "Illegal instruction",
        SIGTRAP => "Trace/breakpoint trap",
        SIGABRT => "Aborted",
        SIGBUS => "Bus error",
        SIGFPE => "Floating point exception",
        SIGKILL => "Killed",
        SIGUSR1 => "User defined signal 1",
        SIGSEGV => "Segmentation fault",
        SIGUSR2 => "User defined signal 2",
        SIGPIPE => "Broken pipe",
        SIGALRM => "Alarm clock",
        SIGTERM => "Terminated",
        SIGSTOP => "Stopped (signal)",
        SIGTSTP => "Stopped",
        SIGXCPU => "CPU time limit exceeded",
        SIGSYS => "Bad system call",
        _ => "Unknown signal",
    }
}
