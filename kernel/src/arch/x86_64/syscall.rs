//! `SYSCALL`/`SYSRET` fast system-call entry, and entering user mode.
//!
//! On `SYSCALL` the CPU saves RIP→RCX and RFLAGS→R11, loads CS/SS from
//! `STAR`, RIP from `LSTAR`, masks RFLAGS with `SFMASK`, and does **not**
//! switch the stack. The stub therefore `swapgs`es to the per-CPU area, saves
//! the user RSP and loads the kernel stack, builds a [`UserFrame`] on it,
//! enables interrupts and calls the Rust dispatcher; on return it restores
//! the frame and `sysretq`s back to ring 3.
//!
//! The same [`UserFrame`] layout is used to *enter* user mode ([`enter_user`],
//! via `iretq`), so `execve` and `fork` build a frame and jump into it.

use super::cpu::{self, MSR_KERNEL_GS_BASE, MSR_LSTAR, MSR_SFMASK, MSR_STAR};
use super::gdt;

/// The user register state saved by the syscall stub (and used to enter user
/// mode). Field order matches the pushes in `syscall_entry`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct UserFrame {
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
    /// Syscall number on entry, return value on exit.
    pub rax: u64,
    /// User RIP (SYSCALL saved it in RCX).
    pub rip: u64,
    /// User RFLAGS (SYSCALL saved it in R11).
    pub rflags: u64,
    pub rsp: u64,
}

impl UserFrame {
    /// A fresh process context: entry point, stack, cleared registers, IF set.
    pub fn new(entry: usize, stack: usize) -> UserFrame {
        UserFrame { rip: entry as u64, rsp: stack as u64, rflags: 0x202, ..Default::default() }
    }
    pub fn args(&self) -> [u64; 6] {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9]
    }
}

/// Per-CPU scratch reached through the kernel GS base during syscall entry.
#[repr(C)]
struct PerCpu {
    /// gs:0 — top of the current task's kernel stack.
    kernel_rsp: u64,
    /// gs:8 — saved user RSP across the stack switch.
    user_rsp_scratch: u64,
}

static mut PERCPU: PerCpu = PerCpu { kernel_rsp: 0, user_rsp_scratch: 0 };

core::arch::global_asm!(
    r#"
    .section .text.syscall, "ax"
    .global syscall_entry
syscall_entry:
    swapgs                      /* GS -> kernel per-CPU area */
    mov gs:[8], rsp             /* save user RSP */
    mov rsp, gs:[0]             /* load the kernel stack top */
    /* Build a UserFrame (see the struct's field order). */
    push qword ptr gs:[8]       /* rsp */
    push r11                    /* rflags */
    push rcx                    /* rip */
    push rax
    push r9
    push r8
    push r10
    push rdx
    push rsi
    push rdi
    push r15
    push r14
    push r13
    push r12
    push rbp
    push rbx
    cld
    mov rdi, rsp                /* &mut UserFrame */
    sti
    call syscall_dispatch
    cli
    pop rbx
    pop rbp
    pop r12
    pop r13
    pop r14
    pop r15
    pop rdi
    pop rsi
    pop rdx
    pop r10
    pop r8
    pop r9
    pop rax
    pop rcx                     /* rip -> rcx for sysretq */
    pop r11                    /* rflags -> r11 for sysretq */
    pop rsp                    /* user RSP */
    swapgs
    sysretq
"#
);

extern "C" {
    fn syscall_entry();
}

/// The Rust side of the syscall stub.
#[no_mangle]
extern "C" fn syscall_dispatch(frame: &mut UserFrame) {
    crate::syscall::dispatch(frame);
}

/// Wire up `SYSCALL`: enable SCE, point LSTAR at the stub, set the selector
/// bases in STAR, and mask IF/DF/AC on entry via SFMASK.
pub fn init() {
    unsafe {
        // Kernel mode keeps the per-CPU pointer in GS_BASE; user mode keeps
        // it in KERNEL_GS_BASE. `swapgs` at every ring boundary flips them.
        cpu::wrmsr(cpu::MSR_GS_BASE, &raw const PERCPU as u64);
        cpu::wrmsr(MSR_KERNEL_GS_BASE, 0);
        let efer = cpu::rdmsr(cpu::MSR_EFER);
        cpu::wrmsr(cpu::MSR_EFER, efer | cpu::EFER_SCE);
        // STAR[47:32] = kernel CS (SYSCALL loads CS=this, SS=this+8);
        // STAR[63:48] = SYSRET base (CS=base+16, SS=base+8) — see gdt.rs.
        let star = ((gdt::KERNEL_CS as u64) << 32) | ((gdt::SYSRET_BASE as u64) << 48);
        cpu::wrmsr(MSR_STAR, star);
        cpu::wrmsr(MSR_LSTAR, syscall_entry as u64);
        cpu::wrmsr(MSR_SFMASK, cpu::RFLAGS_IF | (1 << 10) | cpu::RFLAGS_AC);
    }
}

/// Update the kernel stack the next `SYSCALL` will switch to (called by the
/// scheduler for the task about to run).
pub fn set_kernel_stack(top: u64) {
    unsafe { core::ptr::addr_of_mut!(PERCPU.kernel_rsp).write(top) };
}

core::arch::global_asm!(
    r#"
    .section .text.enter_user, "ax"
    .global enter_user_asm
enter_user_asm:
    /* rdi = *const UserFrame. Load the GP registers, then iretq to ring 3. */
    mov rbx, [rdi + 0]
    mov rbp, [rdi + 8]
    mov r12, [rdi + 16]
    mov r13, [rdi + 24]
    mov r14, [rdi + 32]
    mov r15, [rdi + 40]
    mov rsi, [rdi + 56]
    mov rdx, [rdi + 64]
    mov r10, [rdi + 72]
    mov r8,  [rdi + 80]
    mov r9,  [rdi + 88]
    mov rax, [rdi + 96]
    /* Build the iretq frame: SS, RSP, RFLAGS, CS, RIP. */
    push {user_ss}
    push qword ptr [rdi + 120]  /* rsp */
    push qword ptr [rdi + 112]  /* rflags */
    push {user_cs}
    push qword ptr [rdi + 104]  /* rip */
    mov rdi, [rdi + 48]         /* rdi last: it held the frame pointer */
    swapgs                      /* kernel GS -> user GS for ring 3 */
    iretq
"#,
    user_ss = const gdt::USER_DS as u64,
    user_cs = const gdt::USER_CS as u64,
);

extern "C" {
    fn enter_user_asm(frame: *const UserFrame) -> !;
}

/// Enter user mode with `frame` (initial exec, and the fork child's return).
///
/// # Safety
/// The current CR3 must be the target address space and `frame` must describe
/// a valid ring-3 context (canonical RIP, user stack).
pub unsafe fn enter_user(frame: &UserFrame) -> ! {
    unsafe { enter_user_asm(frame as *const UserFrame) }
}

core::arch::global_asm!(
    r#"
    .section .text.sigreturn_resume, "ax"
    .global sigreturn_resume_asm
sigreturn_resume_asm:
    /* rdi = *const [u64; 18] in the fixed order:
       r8,r9,r10,r11,r12,r13,r14,r15, rdi,rsi,rbp,rbx,rdx,rax,rcx,rsp, rip,rflags.
       Restore EVERY GP register (rcx and r11 too — this is why sigreturn cannot
       use sysret) and iretq back to the exact interrupted ring-3 context. */
    mov r8,  [rdi + 0]
    mov r9,  [rdi + 8]
    mov r10, [rdi + 16]
    mov r11, [rdi + 24]
    mov r12, [rdi + 32]
    mov r13, [rdi + 40]
    mov r14, [rdi + 48]
    mov r15, [rdi + 56]
    mov rsi, [rdi + 72]
    mov rbp, [rdi + 80]
    mov rbx, [rdi + 88]
    mov rdx, [rdi + 96]
    mov rax, [rdi + 104]
    mov rcx, [rdi + 112]
    /* iretq frame: SS, RSP, RFLAGS, CS, RIP */
    push {user_ss}
    push qword ptr [rdi + 120]
    push qword ptr [rdi + 136]
    push {user_cs}
    push qword ptr [rdi + 128]
    mov rdi, [rdi + 64]         /* rdi last */
    swapgs
    iretq
"#,
    user_ss = const gdt::USER_DS as u64,
    user_cs = const gdt::USER_CS as u64,
);

extern "C" {
    fn sigreturn_resume_asm(regs: *const u64) -> !;
}

/// Resume a signal-interrupted ring-3 context from `rt_sigreturn`. `regs` is the
/// 18-word register image (see the asm for the order). Unlike a normal syscall
/// return this restores rcx/r11, so an asynchronously interrupted computation
/// resumes with every register intact.
///
/// # Safety
/// `regs` must describe a valid ring-3 context in the current address space.
pub unsafe fn sigreturn_resume(regs: &[u64; 18]) -> ! {
    unsafe { sigreturn_resume_asm(regs.as_ptr()) }
}
