//! Interrupt Descriptor Table (IDT)
//!
//! 256 × 16-byte gate descriptors.
//! Vectors:
//!   0–31   CPU exceptions (divide-by-zero, page fault, GPF …)
//!   32–47  Hardware IRQs  (PIC-remapped: IRQ0=32, IRQ1=33 …)
//!   0x80   Legacy int 0x80 syscall (backup, main path is SYSCALL)

use super::pic;
use crate::arch::x86_64::boot::gdt::KERNEL_CODE_SEL;

// ── Interrupt stack frame pushed by the CPU ──────────────────────────────────

#[repr(C)]
pub struct InterruptStackFrame {
    pub rip:    u64,
    pub cs:     u64,
    pub rflags: u64,
    pub rsp:    u64,
    pub ss:     u64,
}

// ── IDT entry (gate descriptor, 128-bit) ─────────────────────────────────────

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low:  u16,
    selector:    u16,
    ist:         u8,  // 0 = current stack, 1–7 = IST entry
    type_attr:   u8,  // gate type | DPL | present
    offset_mid:  u16,
    offset_high: u32,
    _reserved:   u32,
}

impl IdtEntry {
    const fn missing() -> Self {
        Self { offset_low: 0, selector: 0, ist: 0, type_attr: 0,
               offset_mid: 0, offset_high: 0, _reserved: 0 }
    }

    fn new(handler: u64, sel: u16, ist: u8, flags: u8) -> Self {
        Self {
            offset_low:  (handler & 0xFFFF) as u16,
            selector:    sel,
            ist,
            type_attr:   flags,
            offset_mid:  ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            _reserved:   0,
        }
    }
}

const INT_GATE:   u8 = 0x8E; // present, ring 0, interrupt gate (clears IF)
const TRAP_GATE:  u8 = 0x8F; // present, ring 0, trap gate (keeps IF)
const USER_GATE:  u8 = 0xEE; // present, ring 3, interrupt gate (for int 0x80)

// ── Static IDT ───────────────────────────────────────────────────────────────

static mut IDT: [IdtEntry; 256] = [IdtEntry::missing(); 256];

#[repr(C, packed)]
struct IdtPtr { limit: u16, base: u64 }

// ── Exception handlers ────────────────────────────────────────────────────────

/// Write a panic message directly to VGA text buffer and halt.
/// Used only in exception handlers where we cannot trust any kernel state.
fn arch_panic(msg: &[u8]) -> ! {
    let vga = 0xB8000 as *mut u8;
    for (i, &b) in msg.iter().enumerate().take(160) {
        unsafe {
            *vga.add(i * 2)     = b;
            *vga.add(i * 2 + 1) = 0x4F; // white on red
        }
    }
    loop { unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack, noreturn)); } }
}

extern "x86-interrupt" fn ex_divide_error(frame: InterruptStackFrame) {
    let _ = frame;
    arch_panic(b"EXCEPTION: #DE divide error");
}

extern "x86-interrupt" fn ex_debug(frame: InterruptStackFrame) {
    let _ = frame;
    arch_panic(b"EXCEPTION: #DB debug");
}

extern "x86-interrupt" fn ex_nmi(frame: InterruptStackFrame) {
    let _ = frame;
    arch_panic(b"EXCEPTION: NMI non-maskable interrupt");
}

extern "x86-interrupt" fn ex_breakpoint(frame: InterruptStackFrame) {
    let _ = frame;
    // Breakpoints are resumable — do not halt in debug builds.
    // TODO: notify debugger subsystem
}

extern "x86-interrupt" fn ex_overflow(frame: InterruptStackFrame) {
    let _ = frame;
    arch_panic(b"EXCEPTION: #OF overflow");
}

extern "x86-interrupt" fn ex_bound_range(frame: InterruptStackFrame) {
    let _ = frame;
    arch_panic(b"EXCEPTION: #BR bound range exceeded");
}

extern "x86-interrupt" fn ex_invalid_opcode(frame: InterruptStackFrame) {
    let _ = frame;
    arch_panic(b"EXCEPTION: #UD invalid opcode");
}

extern "x86-interrupt" fn ex_device_not_available(frame: InterruptStackFrame) {
    let _ = frame;
    arch_panic(b"EXCEPTION: #NM device not available (FPU/SSE)");
}

extern "x86-interrupt" fn ex_double_fault(frame: InterruptStackFrame, _code: u64) -> ! {
    let _ = frame;
    arch_panic(b"EXCEPTION: #DF double fault");
}

extern "x86-interrupt" fn ex_invalid_tss(frame: InterruptStackFrame, code: u64) {
    let _ = (frame, code);
    arch_panic(b"EXCEPTION: #TS invalid TSS");
}

extern "x86-interrupt" fn ex_segment_not_present(frame: InterruptStackFrame, code: u64) {
    let _ = (frame, code);
    arch_panic(b"EXCEPTION: #NP segment not present");
}

extern "x86-interrupt" fn ex_stack_fault(frame: InterruptStackFrame, code: u64) {
    let _ = (frame, code);
    arch_panic(b"EXCEPTION: #SS stack segment fault");
}

extern "x86-interrupt" fn ex_general_protection(frame: InterruptStackFrame, code: u64) {
    let _ = (frame, code);
    arch_panic(b"EXCEPTION: #GP general protection fault");
}

/// Page fault handler.
/// Reads CR2 (fault address) and error code, then calls the kernel page-fault hook.
extern "x86-interrupt" fn ex_page_fault(frame: InterruptStackFrame, error_code: u64) {
    let cr2: u64;
    unsafe { core::arch::asm!("mov {0}, cr2", out(reg) cr2, options(nomem, nostack)); }

    // Error code bits:
    //   0 = page was present (1) or not (0)
    //   1 = write access (1) or read (0)
    //   2 = user mode (1) or kernel (0)
    let present = (error_code & 1) != 0;
    let write   = (error_code & 2) != 0;
    let user    = (error_code & 4) != 0;

    unsafe {
        if let Some(hook) = PAGE_FAULT_HOOK {
            if hook(cr2, present, write, user, frame.rip) {
                return; // page fault was handled (e.g. demand paging)
            }
        }
    }

    // Unhandled page fault
    arch_panic(b"EXCEPTION: #PF page fault (unhandled)");
}

extern "x86-interrupt" fn ex_x87_fpe(frame: InterruptStackFrame) {
    let _ = frame;
    arch_panic(b"EXCEPTION: #MF x87 floating-point error");
}

extern "x86-interrupt" fn ex_alignment_check(frame: InterruptStackFrame, code: u64) {
    let _ = (frame, code);
    arch_panic(b"EXCEPTION: #AC alignment check");
}

extern "x86-interrupt" fn ex_machine_check(frame: InterruptStackFrame) -> ! {
    let _ = frame;
    arch_panic(b"EXCEPTION: #MC machine check");
}

extern "x86-interrupt" fn ex_simd_fpe(frame: InterruptStackFrame) {
    let _ = frame;
    arch_panic(b"EXCEPTION: #XM SIMD floating-point error");
}

// ── IRQ handlers ─────────────────────────────────────────────────────────────

extern "x86-interrupt" fn irq_timer(frame: InterruptStackFrame) {
    let _ = frame;
    crate::arch::x86_64::cpu::timer::on_tick();
    pic::end_of_interrupt(0);
    // Scheduler tick is called from main.rs via TIMER_HOOK
    unsafe {
        if let Some(hook) = TIMER_HOOK { hook(); }
    }
}

extern "x86-interrupt" fn irq_keyboard(frame: InterruptStackFrame) {
    let _ = frame;
    // TODO: read scancode from 0x60, push to keyboard driver ring buffer
    pic::end_of_interrupt(1);
}

extern "x86-interrupt" fn irq_spurious(frame: InterruptStackFrame) {
    let _ = frame;
    // Do NOT send EOI for spurious IRQs
}

// ── Kernel hooks (set from main.rs) ──────────────────────────────────────────

/// Called every timer tick (IRQ 0).  Set to `kernel::process::scheduler::tick`.
pub static mut TIMER_HOOK: Option<fn()> = None;

/// Called on page fault.  Returns true if the fault was handled (demand page).
/// Signature: (fault_addr, present, write, user, rip) → handled
pub static mut PAGE_FAULT_HOOK: Option<fn(u64, bool, bool, bool, u64) -> bool> = None;

// ── Load IDT ─────────────────────────────────────────────────────────────────

pub fn load() {
    unsafe {
        let set = |vec: usize, handler: u64, flags: u8| {
            IDT[vec] = IdtEntry::new(handler, KERNEL_CODE_SEL, 0, flags);
        };

        // CPU exceptions
        set(0,  ex_divide_error              as u64, INT_GATE);
        set(1,  ex_debug                     as u64, TRAP_GATE);
        set(2,  ex_nmi                       as u64, INT_GATE);
        set(3,  ex_breakpoint                as u64, TRAP_GATE);
        set(4,  ex_overflow                  as u64, TRAP_GATE);
        set(5,  ex_bound_range               as u64, INT_GATE);
        set(6,  ex_invalid_opcode            as u64, INT_GATE);
        set(7,  ex_device_not_available      as u64, INT_GATE);
        set(8,  ex_double_fault              as u64, INT_GATE);
        set(10, ex_invalid_tss               as u64, INT_GATE);
        set(11, ex_segment_not_present       as u64, INT_GATE);
        set(12, ex_stack_fault               as u64, INT_GATE);
        set(13, ex_general_protection        as u64, INT_GATE);
        set(14, ex_page_fault                as u64, INT_GATE);
        set(16, ex_x87_fpe                   as u64, INT_GATE);
        set(17, ex_alignment_check           as u64, INT_GATE);
        set(18, ex_machine_check             as u64, INT_GATE);
        set(19, ex_simd_fpe                  as u64, INT_GATE);

        // Hardware IRQs (after PIC remap: IRQ0 → vector 32)
        set(32, irq_timer                    as u64, INT_GATE);
        set(33, irq_keyboard                 as u64, INT_GATE);
        // IRQ 7 and IRQ 15 are spurious
        set(39, irq_spurious                 as u64, INT_GATE);
        set(47, irq_spurious                 as u64, INT_GATE);

        let ptr = IdtPtr {
            limit: (256 * core::mem::size_of::<IdtEntry>() - 1) as u16,
            base:  IDT.as_ptr() as u64,
        };
        core::arch::asm!("lidt [{0}]", in(reg) &ptr, options(nostack));
    }
}
