//! Kernel stack switching between tasks.
//!
//! `switch_stacks(prev_rsp, next_rsp)` pushes the callee-saved registers on
//! the current stack, stores RSP into `*prev_rsp`, loads `next_rsp` and pops
//! the next task's registers. A new task's stack is prepared by
//! [`prepare_stack`] so the first switch "returns" into `task_entry_asm`.

core::arch::global_asm!(
    r#"
    .section .text.switch_stacks, "ax"
    .global switch_stacks
switch_stacks:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

    .global task_entry_asm
task_entry_asm:
    /* Terminate frame-pointer chains here and give `task_entry` the SysV
       entry alignment (RSP = 16n before the call pushes the return address). */
    xor ebp, ebp
    and rsp, -16
    call task_entry
    ud2
"#
);

extern "C" {
    pub fn switch_stacks(prev_rsp: *mut usize, next_rsp: usize);
    fn task_entry_asm();
}

/// Lay out a fresh stack so that `switch_stacks` into it starts `task_entry`.
/// Returns the initial saved RSP.
pub fn prepare_stack(top: usize) -> usize {
    let top = top & !15;
    // Popped by switch_stacks: r15 r14 r13 r12 rbx rbp, then `ret` into
    // task_entry_asm; the last slot is padding.
    let frame: [usize; 8] = [0, 0, 0, 0, 0, 0, task_entry_asm as usize, 0];
    let rsp = top - frame.len() * 8;
    unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), rsp as *mut usize, frame.len()) };
    rsp
}
