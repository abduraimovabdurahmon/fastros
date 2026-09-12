//! seccomp (classic-BPF syscall filtering) and POSIX capabilities.
//!
//! seccomp lets a process install cBPF programs that are run on every syscall it
//! makes; each returns an action (allow, return an errno, trap, or kill). This
//! is the same mechanism Docker/Kubernetes use to shrink a container's kernel
//! attack surface — a FastROS container can be locked to a syscall allowlist.
//!
//! Capabilities split root's power into a bitmask so a process can hold only the
//! few privileges it needs (e.g. `CAP_NET_BIND_SERVICE` to bind a low port)
//! instead of all-or-nothing uid 0.

use crate::errno::{Errno, KResult};
use crate::uaccess;
use alloc::sync::Arc;
use alloc::vec::Vec;

// ── capabilities ─────────────────────────────────────────────────────────────

pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_BOOT: u32 = 22;
pub const CAP_LAST: u32 = 40;

/// The full capability set (uid 0 default).
pub const CAP_ALL: u64 = (1u64 << (CAP_LAST + 1)) - 1;

/// A process's default capabilities: everything for root, nothing otherwise —
/// exactly Linux's rule for a process with no file capabilities.
pub fn default_caps(uid: u32) -> u64 {
    if uid == 0 {
        CAP_ALL
    } else {
        0
    }
}

/// Does the current process hold `cap`?
pub fn current_has_cap(cap: u32) -> bool {
    if cap > CAP_LAST {
        return false;
    }
    crate::proc::current().caps.load(core::sync::atomic::Ordering::Relaxed) & (1u64 << cap) != 0
}

/// Parse a capability name (`NET_BIND_SERVICE` or `CAP_NET_BIND_SERVICE`,
/// case-insensitive) or a raw number, into its bit index.
pub fn cap_by_name(name: &str) -> Option<u32> {
    let n = name.trim().to_ascii_uppercase();
    let n = n.strip_prefix("CAP_").unwrap_or(&n);
    Some(match n {
        "NET_BIND_SERVICE" => CAP_NET_BIND_SERVICE,
        "NET_RAW" => CAP_NET_RAW,
        "SYS_ADMIN" => CAP_SYS_ADMIN,
        "SYS_BOOT" => CAP_SYS_BOOT,
        "CHOWN" => 0,
        "DAC_OVERRIDE" => 1,
        "KILL" => 5,
        "SETGID" => 6,
        "SETUID" => 7,
        "NET_ADMIN" => 12,
        "SYS_CHROOT" => 18,
        "SYS_PTRACE" => 19,
        "MKNOD" => 27,
        _ => n.parse().ok()?,
    })
}

// ── seccomp cBPF ─────────────────────────────────────────────────────────────

/// One classic-BPF instruction (`struct sock_filter`).
#[derive(Clone, Copy)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// The installed seccomp state of a process: its stacked cBPF programs, shared
/// (via `Arc`) with forked children and kept across `execve`.
#[derive(Default)]
pub struct Filters {
    /// `SECCOMP_MODE_STRICT`: only read/write/exit/rt_sigreturn are permitted.
    pub strict: bool,
    /// Stacked filter programs (all are run; the most severe action wins).
    pub progs: Vec<Vec<SockFilter>>,
}

// AUDIT_ARCH_X86_64.
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

// seccomp operations / modes.
pub const SECCOMP_SET_MODE_STRICT: u64 = 0;
pub const SECCOMP_SET_MODE_FILTER: u64 = 1;

// Return-value action classes (`ret & SECCOMP_RET_ACTION_FULL`).
const RET_ACTION_FULL: u32 = 0xffff_0000;
const RET_DATA: u32 = 0x0000_ffff;
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_KILL_THREAD: u32 = 0x0000_0000;
pub const RET_TRAP: u32 = 0x0003_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const RET_TRACE: u32 = 0x7ff0_0000;
pub const RET_LOG: u32 = 0x7ffc_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;

/// What a filter evaluation decided.
pub enum Action {
    Allow,
    Errno(u16),
    Trap,
    KillThread,
    KillProcess,
}

/// The `seccomp_data` a filter sees: syscall number, arch, instruction pointer
/// and the six syscall arguments — laid out exactly as the kernel ABI, so byte
/// offsets used by real filters (nr@0, arch@4, ip@8, args@16..64) line up.
pub struct Data {
    pub buf: [u8; 64],
}

impl Data {
    pub fn new(nr: u64, ip: u64, args: &[u64; 6]) -> Data {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&(nr as u32).to_le_bytes());
        buf[4..8].copy_from_slice(&AUDIT_ARCH_X86_64.to_le_bytes());
        buf[8..16].copy_from_slice(&ip.to_le_bytes());
        for (i, a) in args.iter().enumerate() {
            buf[16 + i * 8..24 + i * 8].copy_from_slice(&a.to_le_bytes());
        }
        Data { buf }
    }

    fn word(&self, k: u32) -> Option<u32> {
        let k = k as usize;
        if k + 4 > self.buf.len() {
            return None;
        }
        Some(u32::from_le_bytes([self.buf[k], self.buf[k + 1], self.buf[k + 2], self.buf[k + 3]]))
    }
}

// BPF instruction encoding (classes and sub-fields).
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IMM: u16 = 0x00;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;

const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_AND: u16 = 0x50;
const BPF_OR: u16 = 0x40;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;

const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;
const BPF_A: u16 = 0x10;

const BPF_CLASS: u16 = 0x07;

/// Run one cBPF program against `data`, returning its 32-bit action value.
/// A malformed program (out-of-range load/jump, missing return) is treated as
/// `KILL_PROCESS` — a filter that cannot be trusted must not fail open.
fn run_prog(prog: &[SockFilter], data: &Data) -> u32 {
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut mem = [0u32; 16];
    let mut pc = 0usize;
    let mut steps = 0usize;
    while pc < prog.len() {
        steps += 1;
        if steps > 4096 {
            return RET_KILL_PROCESS;
        }
        let ins = prog[pc];
        let class = ins.code & BPF_CLASS;
        let modes = ins.code & 0xe0;
        let src = ins.code & 0x08;
        let op = ins.code & 0xf0;
        match class {
            BPF_LD => {
                a = match modes {
                    BPF_ABS => match data.word(ins.k) {
                        Some(w) => w,
                        None => return RET_KILL_PROCESS,
                    },
                    BPF_IMM => ins.k,
                    BPF_MEM => *mem.get(ins.k as usize).unwrap_or(&0),
                    BPF_LEN => 64,
                    _ => return RET_KILL_PROCESS,
                };
            }
            BPF_LDX => {
                x = match modes {
                    BPF_IMM => ins.k,
                    BPF_MEM => *mem.get(ins.k as usize).unwrap_or(&0),
                    BPF_LEN => 64,
                    _ => return RET_KILL_PROCESS,
                };
            }
            BPF_ALU => {
                let val = if src == BPF_X { x } else { ins.k };
                a = match op {
                    BPF_ADD => a.wrapping_add(val),
                    BPF_SUB => a.wrapping_sub(val),
                    BPF_AND => a & val,
                    BPF_OR => a | val,
                    BPF_LSH => a.wrapping_shl(val),
                    BPF_RSH => a.wrapping_shr(val),
                    _ => a,
                };
            }
            BPF_JMP => {
                if op == BPF_JA {
                    pc = pc.wrapping_add(1 + ins.k as usize);
                    continue;
                }
                let val = if src == BPF_X { x } else { ins.k };
                let cond = match op {
                    BPF_JEQ => a == val,
                    BPF_JGT => a > val,
                    BPF_JGE => a >= val,
                    BPF_JSET => (a & val) != 0,
                    _ => false,
                };
                let off = if cond { ins.jt } else { ins.jf } as usize;
                pc = pc.wrapping_add(1 + off);
                continue;
            }
            BPF_RET => {
                return if (ins.code & 0x18) == BPF_A { a } else { ins.k };
            }
            BPF_MISC => { /* tax/txa: rarely used by seccomp filters */ }
            _ => return RET_KILL_PROCESS,
        }
        pc += 1;
    }
    // Fell off the end without a return: reject.
    RET_KILL_PROCESS
}

impl Filters {
    /// Decide the action for a syscall. Strict mode is checked first; then every
    /// stacked program runs and the most severe action wins (Linux precedence).
    pub fn decide(&self, nr: u64, ip: u64, args: &[u64; 6]) -> Action {
        if self.strict {
            // read, write, exit, rt_sigreturn, exit_group.
            return match nr {
                0 | 1 | 15 | 60 | 231 => Action::Allow,
                _ => Action::KillProcess,
            };
        }
        let data = Data::new(nr, ip, args);
        // Track the winning raw action by severity.
        let mut best: Option<u32> = None;
        for prog in &self.progs {
            let r = run_prog(prog, &data);
            best = Some(match best {
                None => r,
                Some(cur) => more_severe(cur, r),
            });
        }
        match best {
            None => Action::Allow,
            Some(r) => classify(r),
        }
    }
}

/// Linux precedence: KILL_PROCESS beats everything; otherwise the numerically
/// smallest action value is the most restrictive.
fn more_severe(a: u32, b: u32) -> u32 {
    if a == RET_KILL_PROCESS || b == RET_KILL_PROCESS {
        return RET_KILL_PROCESS;
    }
    if (a & RET_ACTION_FULL) <= (b & RET_ACTION_FULL) {
        a
    } else {
        b
    }
}

fn classify(r: u32) -> Action {
    match r & RET_ACTION_FULL {
        RET_KILL_PROCESS => Action::KillProcess,
        RET_KILL_THREAD => Action::KillThread,
        RET_TRAP => Action::Trap,
        RET_ERRNO => Action::Errno((r & RET_DATA) as u16),
        // TRACE with no tracer behaves like ERRNO(ENOSYS) on Linux; we allow so a
        // process is never mysteriously broken. LOG and ALLOW allow.
        RET_TRACE | RET_LOG | RET_ALLOW => Action::Allow,
        _ => Action::Allow,
    }
}

/// Read a `struct sock_fprog { u16 len; sock_filter *filter; }` from user memory
/// and copy its program in. Length is capped like Linux (BPF_MAXINSNS = 4096).
fn read_fprog(prog_ptr: usize) -> KResult<Vec<SockFilter>> {
    if prog_ptr == 0 {
        return Err(Errno::EFAULT);
    }
    let len: u16 = uaccess::read_obj(prog_ptr)?;
    if len == 0 || len as usize > 4096 {
        return Err(Errno::EINVAL);
    }
    let filter_ptr: u64 = uaccess::read_obj(prog_ptr + 8)?;
    if filter_ptr == 0 {
        return Err(Errno::EFAULT);
    }
    let mut prog = Vec::with_capacity(len as usize);
    for i in 0..len as usize {
        let base = filter_ptr as usize + i * 8;
        let code: u16 = uaccess::read_obj(base)?;
        let jt: u8 = uaccess::read_obj(base + 2)?;
        let jf: u8 = uaccess::read_obj(base + 3)?;
        let k: u32 = uaccess::read_obj(base + 4)?;
        prog.push(SockFilter { code, jt, jf, k });
    }
    Ok(prog)
}

/// Install a cBPF filter (`seccomp(SET_MODE_FILTER)` / `prctl(PR_SET_SECCOMP,
/// FILTER)`). Requires `no_new_privs` or `CAP_SYS_ADMIN`, as on Linux.
pub fn install_filter(prog_ptr: usize) -> KResult<usize> {
    let p = crate::proc::current();
    if !p.no_new_privs.load(core::sync::atomic::Ordering::Relaxed) && !current_has_cap(CAP_SYS_ADMIN) {
        return Err(Errno::EACCES);
    }
    let prog = read_fprog(prog_ptr)?;
    let mut guard = p.seccomp.lock();
    let mut filters = match guard.take() {
        Some(f) => Filters { strict: f.strict, progs: f.progs.clone() },
        None => Filters::default(),
    };
    filters.progs.push(prog);
    *guard = Some(Arc::new(filters));
    p.seccomp_active.store(true, core::sync::atomic::Ordering::Release);
    Ok(0)
}

/// Enter strict mode (`seccomp(SET_MODE_STRICT)` / `prctl(PR_SET_SECCOMP,
/// STRICT)`): only read/write/exit/rt_sigreturn are allowed thereafter.
pub fn set_strict() -> KResult<usize> {
    let p = crate::proc::current();
    let mut guard = p.seccomp.lock();
    let progs = guard.take().map(|f| f.progs.clone()).unwrap_or_default();
    *guard = Some(Arc::new(Filters { strict: true, progs }));
    p.seccomp_active.store(true, core::sync::atomic::Ordering::Release);
    Ok(0)
}
