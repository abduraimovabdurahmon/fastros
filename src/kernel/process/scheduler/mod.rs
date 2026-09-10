//! CPU Scheduler — decides which thread runs next.
//!
//! Default algorithm: Round-Robin (equal time slice per thread).
//! Preemption: driven by the timer IRQ (100 Hz → 10 ms slices).

pub mod round_robin;

use crate::kernel::process::{
    PROCESS_TABLE, PROCESS_USED, THREAD_TABLE, THREAD_USED, MAX_PROCESSES
};
use crate::kernel::process::process::ProcessState;
use crate::kernel::process::thread::Context;

extern "C" {
    /// Assembly context switch — saves old context, restores new context.
    /// old = NULL → only restores (used to start the first thread).
    fn context_switch(old: *mut Context, new: *const Context);
}

pub fn init() {}

/// Called by the timer IRQ every 10 ms (100 Hz).
pub fn tick() {
    schedule();
}

/// Voluntarily yield the CPU.
pub fn yield_cpu() {
    schedule();
}

/// Core scheduling function.
pub fn schedule() {
    let next_idx = match round_robin::dequeue() {
        Some(i) => i,
        None    => return,
    };

    unsafe {
        let current_idx = round_robin::CURRENT_IDX;

        // Re-enqueue current process if still running
        if current_idx != usize::MAX && PROCESS_USED[current_idx] {
            let state = PROCESS_TABLE[current_idx].assume_init_ref().state;
            if state == ProcessState::Running {
                PROCESS_TABLE[current_idx].assume_init_mut().state = ProcessState::Ready;
                round_robin::enqueue(current_idx);
            }
        }

        // Activate next process
        PROCESS_TABLE[next_idx].assume_init_mut().state = ProcessState::Running;
        round_robin::CURRENT_IDX = next_idx;

        // Save old thread context pointer
        let old_ctx: *mut Context = if current_idx != usize::MAX && PROCESS_USED[current_idx] {
            find_thread_ctx_mut(current_idx)
        } else {
            core::ptr::null_mut()
        };

        // Find new thread context
        let new_ctx: *const Context = find_thread_ctx(next_idx);
        if new_ctx.is_null() { return; }

        // Update TSS rsp0 for the new process
        let kstack = PROCESS_TABLE[next_idx].assume_init_ref().kstack_top;
        crate::arch::x86_64::boot::gdt::set_kernel_stack(kstack);

        // Switch address space if needed
        let cr3 = PROCESS_TABLE[next_idx].assume_init_ref().cr3;
        if cr3 != 0 {
            core::arch::asm!("mov cr3, {0}", in(reg) cr3, options(nostack));
        }

        context_switch(old_ctx, new_ctx);
    }
}

/// Called by exit() — switch away from the exiting process forever.
pub fn schedule_after_exit() -> ! {
    unsafe { round_robin::CURRENT_IDX = usize::MAX; }
    schedule();
    loop { unsafe { core::arch::asm!("hlt", options(nomem, nostack)); } }
}

/// Block the current process.
pub fn block_current() {
    unsafe {
        let idx = round_robin::CURRENT_IDX;
        if idx == usize::MAX { return; }
        if PROCESS_USED[idx] {
            PROCESS_TABLE[idx].assume_init_mut().state = ProcessState::Blocked;
        }
        round_robin::CURRENT_IDX = usize::MAX;
    }
    schedule();
}

/// Wake a blocked process.
pub fn wake(proc_idx: usize) {
    unsafe {
        if proc_idx < MAX_PROCESSES && PROCESS_USED[proc_idx] {
            let state = PROCESS_TABLE[proc_idx].assume_init_ref().state;
            if state == ProcessState::Blocked {
                PROCESS_TABLE[proc_idx].assume_init_mut().state = ProcessState::Ready;
                round_robin::enqueue(proc_idx);
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

unsafe fn find_thread_ctx(proc_idx: usize) -> *const Context {
    for t in 0..THREAD_TABLE.len() {
        if THREAD_USED[t] {
            let thread = THREAD_TABLE[t].assume_init_ref();
            if thread.proc_idx == proc_idx {
                return &thread.context as *const Context;
            }
        }
    }
    core::ptr::null()
}

unsafe fn find_thread_ctx_mut(proc_idx: usize) -> *mut Context {
    for t in 0..THREAD_TABLE.len() {
        if THREAD_USED[t] {
            let thread = THREAD_TABLE[t].assume_init_mut();
            if thread.proc_idx == proc_idx {
                return &mut thread.context as *mut Context;
            }
        }
    }
    core::ptr::null_mut()
}
