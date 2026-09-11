//! Interrupt/exception entry: one 16-byte stub per vector, a common path that
//! saves every general-purpose register into a [`TrapFrame`] on the current
//! kernel stack, and the IDT that points at the stubs.
//!
//! The frame is the single source of truth for the interrupted context, both
//! for kernel faults (register dump in the panic report) and — later — for
//! user mode (signal delivery, preemption, `ptrace`-like inspection).

use super::gdt;

core::arch::global_asm!(
    r#"
    .section .text.trap_stubs, "ax"
    .balign 16
    .global trap_stubs
trap_stubs:
    .set vec, 0
    .rept 256
    .balign 16
    /* Vectors that push an error code themselves; the rest get a dummy 0. */
    .if (vec == 8) || (vec == 10) || (vec == 11) || (vec == 12) || (vec == 13) || (vec == 14) || (vec == 17) || (vec == 21) || (vec == 29) || (vec == 30)
    .else
    push 0
    .endif
    push vec
    jmp trap_common
    .set vec, vec + 1
    .endr

    .balign 16
trap_common:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    cld
    /* Came from ring 3? Then GS holds the user base: swap in the kernel's.
       CS sits at offset 144 (15 GP regs + vector + error). */
    test byte ptr [rsp + 144], 3
    jz 1f
    swapgs
1:
    mov rdi, rsp
    call trap_dispatch
    .global trap_return
trap_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    /* Returning to ring 3? Restore the user GS base first. CS is at [rsp+8]
       now (rip, cs, ...). */
    test byte ptr [rsp + 8], 3
    jz 2f
    swapgs
2:
    iretq
"#
);

extern "C" {
    static trap_stubs: u8;
    pub fn trap_return();
}

/// Register state of the interrupted context, exactly as `trap_common` laid it out.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrame {
    pub fn from_user(&self) -> bool {
        self.cs & 3 == 3
    }
}

#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Gate {
    off_lo: u16,
    sel: u16,
    ist: u8,
    attr: u8,
    off_mid: u16,
    off_hi: u32,
    _res: u32,
}

static mut IDT: [Gate; 256] = [Gate { off_lo: 0, sel: 0, ist: 0, attr: 0, off_mid: 0, off_hi: 0, _res: 0 }; 256];

pub const VEC_IRQ_BASE: u8 = 32;
pub const VEC_SPURIOUS: u8 = 0xFF;

pub fn init_idt() {
    let base = unsafe { core::ptr::addr_of!(trap_stubs) as u64 };
    for v in 0..256usize {
        let addr = base + (v as u64) * 16;
        let ist = match v {
            8 => gdt::IST_DOUBLE_FAULT,
            2 => gdt::IST_NMI,
            18 => gdt::IST_MACHINE_CHECK,
            _ => 0,
        };
        // Interrupt gates (IF cleared on entry). Breakpoint is reachable from
        // ring 3 so debuggers inside containers work; everything else is DPL 0.
        let dpl: u8 = if v == 3 { 3 } else { 0 };
        unsafe {
            IDT[v] = Gate {
                off_lo: addr as u16,
                sel: gdt::KERNEL_CS,
                ist,
                attr: 0x8E | (dpl << 5),
                off_mid: (addr >> 16) as u16,
                off_hi: (addr >> 32) as u32,
                _res: 0,
            };
        }
    }
    let ptr = IdtPointer { limit: (core::mem::size_of::<[Gate; 256]>() - 1) as u16, base: &raw const IDT as u64 };
    unsafe { core::arch::asm!("lidt [{}]", in(reg) &ptr, options(nostack)) };
}

/// Human-readable exception names (Intel SDM vol. 3, table 6-1).
pub fn exception_name(v: u64) -> &'static str {
    match v {
        0 => "#DE divide error",
        1 => "#DB debug",
        2 => "NMI",
        3 => "#BP breakpoint",
        4 => "#OF overflow",
        5 => "#BR bound range exceeded",
        6 => "#UD invalid opcode",
        7 => "#NM device not available",
        8 => "#DF double fault",
        10 => "#TS invalid TSS",
        11 => "#NP segment not present",
        12 => "#SS stack-segment fault",
        13 => "#GP general protection",
        14 => "#PF page fault",
        16 => "#MF x87 floating-point",
        17 => "#AC alignment check",
        18 => "#MC machine check",
        19 => "#XM SIMD floating-point",
        20 => "#VE virtualization",
        21 => "#CP control protection",
        _ => "reserved exception",
    }
}

#[no_mangle]
extern "C" fn trap_dispatch(tf: &mut TrapFrame) {
    crate::trap::dispatch(tf);
}
