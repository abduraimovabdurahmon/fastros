//! x86_64 architecture module
//!
//! Initialization order (hardware dependencies):
//!   1. GDT + TSS  — needed before IDT (selectors) and SYSCALL
//!   2. IDT + PIC  — enables exception handling + hardware IRQs
//!   3. CPU init   — SYSCALL MSRs, PIT timer

pub mod boot;
pub mod cpu;
pub mod interrupts;
pub mod io;
pub mod memory;

pub fn init() {
    boot::init_gdt();          // install GDT, load TSS
    interrupts::init_idt();    // remap PIC, load IDT, enable interrupts
    cpu::init();               // SYSCALL MSRs, PIT timer at 100 Hz
}

/// Hook called every 10 ms (100 Hz timer tick).
/// Set this to `kernel::process::scheduler::tick` after scheduler init.
pub fn set_timer_hook(f: fn()) {
    interrupts::set_timer_hook(f);
}

/// Hook called on page fault.
/// Set this to the VMM page-fault handler after VMM init.
pub fn set_page_fault_hook(f: fn(u64, bool, bool, bool, u64) -> bool) {
    interrupts::set_page_fault_hook(f);
}
