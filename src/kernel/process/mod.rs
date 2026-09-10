//! Process & thread management
//!
//! Lifecycle: Created → Ready → Running → Blocked → Zombie → (reaped by parent)
//!
//! Global tables (static arrays — no alloc needed):
//!   PROCESS_TABLE[MAX_PROCESSES] — all process slots
//!   THREAD_TABLE[MAX_THREADS]    — all thread slots

pub mod fd;
pub mod process;
pub mod scheduler;
pub mod thread;

use core::mem::MaybeUninit;
use crate::kernel::memory::pmm;

pub const MAX_PROCESSES: usize = 64;
pub const MAX_THREADS:   usize = 128;

// Kernel stack size per process: 16 KB
const KSTACK_PAGES: usize = 4;
const KSTACK_SIZE:  u64   = (KSTACK_PAGES * 4096) as u64;

pub static mut PROCESS_TABLE: [MaybeUninit<process::Process>; MAX_PROCESSES] =
    unsafe { MaybeUninit::uninit().assume_init() };
pub static mut PROCESS_USED:  [bool; MAX_PROCESSES] = [false; MAX_PROCESSES];
pub static mut PROCESS_COUNT: usize = 0;

pub static mut THREAD_TABLE: [MaybeUninit<thread::Thread>; MAX_THREADS] =
    unsafe { MaybeUninit::uninit().assume_init() };
pub static mut THREAD_USED:  [bool; MAX_THREADS] = [false; MAX_THREADS];

static mut NEXT_PID: u32 = 1;
static mut NEXT_TID: u32 = 1;

pub fn init() {
    scheduler::init();
}

// ── PID / TID allocation ──────────────────────────────────────────────────────

fn alloc_pid() -> u32 {
    unsafe { let p = NEXT_PID; NEXT_PID += 1; p }
}

fn alloc_tid() -> u32 {
    unsafe { let t = NEXT_TID; NEXT_TID += 1; t }
}

fn alloc_proc_slot() -> Option<usize> {
    unsafe {
        for (i, used) in PROCESS_USED.iter_mut().enumerate() {
            if !*used { *used = true; PROCESS_COUNT += 1; return Some(i); }
        }
        None
    }
}

fn alloc_thread_slot() -> Option<usize> {
    unsafe {
        for (i, used) in THREAD_USED.iter_mut().enumerate() {
            if !*used { *used = true; return Some(i); }
        }
        None
    }
}

// ── Spawn a kernel thread ─────────────────────────────────────────────────────

/// Create a new kernel thread that starts executing at `entry`.
/// Runs in kernel mode (ring 0) with its own 16 KB stack.
pub fn spawn_kthread(entry: fn() -> !) -> Option<usize> {
    let proc_idx   = alloc_proc_slot()?;
    let thread_idx = alloc_thread_slot()?;
    let pid = alloc_pid();
    let tid = alloc_tid();

    let kstack_phys = pmm::alloc_frames(KSTACK_PAGES)?;
    let kstack_top  = kstack_phys + KSTACK_SIZE;

    let p = process::Process::new(pid, 0, 0, kstack_top);
    let t = thread::Thread::new(tid, proc_idx, entry as u64, kstack_top);

    unsafe {
        PROCESS_TABLE[proc_idx].write(p);
        THREAD_TABLE[thread_idx].write(t);
    }
    scheduler::round_robin::enqueue(proc_idx);
    Some(proc_idx)
}

// ── fork() ───────────────────────────────────────────────────────────────────

/// Create a child process that is a copy of the current process.
/// Returns child_pid to parent.
pub fn fork() -> Result<u32, &'static str> {
    let parent_idx = scheduler::round_robin::current();
    if parent_idx == usize::MAX { return Err("no current process"); }

    let proc_idx   = alloc_proc_slot().ok_or("process table full")?;
    let thread_idx = alloc_thread_slot().ok_or("thread table full")?;

    let child_pid = alloc_pid();
    let child_tid = alloc_tid();

    let (parent_pid, parent_cr3, parent_kstack_top, parent_fds, parent_signals) = unsafe {
        let p = PROCESS_TABLE[parent_idx].assume_init_ref();
        (p.pid, p.cr3, p.kstack_top, p.fds, p.signals)
    };

    let kstack_phys = pmm::alloc_frames(KSTACK_PAGES).ok_or("OOM: fork kstack")?;
    let kstack_top  = kstack_phys + KSTACK_SIZE;

    let mut child = process::Process::new(child_pid, parent_pid.0, parent_cr3, kstack_top);
    child.fds     = parent_fds.fork_copy();
    child.signals = parent_signals;

    // Child thread starts with zeroed context; real fork needs full context copy
    let child_thread = thread::Thread::new(child_tid, proc_idx, 0, kstack_top);

    unsafe {
        PROCESS_TABLE[proc_idx].write(child);
        THREAD_TABLE[thread_idx].write(child_thread);
    }
    scheduler::round_robin::enqueue(proc_idx);

    let _ = parent_kstack_top;
    Ok(child_pid)
}

// ── exit() ───────────────────────────────────────────────────────────────────

/// Mark the current process as Zombie with the given exit code.
pub fn exit(code: i32) -> ! {
    unsafe {
        let idx = scheduler::round_robin::CURRENT_IDX;
        if idx < MAX_PROCESSES && PROCESS_USED[idx] {
            let p = PROCESS_TABLE[idx].assume_init_mut();
            p.state     = process::ProcessState::Zombie;
            p.exit_code = code;

            let ppid = p.ppid.0;
            for i in 0..MAX_PROCESSES {
                if PROCESS_USED[i] {
                    let parent = PROCESS_TABLE[i].assume_init_ref();
                    if parent.pid.0 == ppid {
                        PROCESS_TABLE[i].assume_init_mut().signals.send(
                            crate::kernel::ipc::signal::SIGCHLD
                        );
                        break;
                    }
                }
            }
        }
        scheduler::round_robin::CURRENT_IDX = usize::MAX;
    }
    scheduler::schedule_after_exit();
}

// ── wait() ───────────────────────────────────────────────────────────────────

/// Wait for any zombie child.  Returns (child_pid, exit_code) or None.
pub fn wait() -> Option<(u32, i32)> {
    unsafe {
        let parent_idx = scheduler::round_robin::CURRENT_IDX;
        if parent_idx == usize::MAX { return None; }
        let parent_pid = PROCESS_TABLE[parent_idx].assume_init_ref().pid.0;

        for i in 0..MAX_PROCESSES {
            if !PROCESS_USED[i] { continue; }
            let p = PROCESS_TABLE[i].assume_init_ref();
            if p.ppid.0 == parent_pid && p.state == process::ProcessState::Zombie {
                let pid  = p.pid.0;
                let code = p.exit_code;
                PROCESS_TABLE[i].assume_init_drop();
                PROCESS_USED[i]  = false;
                PROCESS_COUNT   -= 1;
                return Some((pid, code));
            }
        }
        None
    }
}
