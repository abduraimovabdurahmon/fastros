//! x86_64 Interrupt handling: IDT, PIC, APIC

pub mod apic;
pub mod idt;
pub mod pic;

/// Initialize interrupt handling:
///   1. Remap PIC (so IRQs don't conflict with CPU exception vectors)
///   2. Mask all IRQs (drivers will unmask selectively)
///   3. Load the IDT
///   4. Enable interrupts
pub fn init_idt() {
    pic::remap();
    pic::mask_all();
    idt::load();
    // Unmask IRQ 0 (timer) — required for preemptive scheduling
    pic::unmask(0);
    unsafe { core::arch::asm!("sti", options(nostack)); }
}

/// Set the function called on every timer tick (IRQ 0).
/// Called from main.rs after both arch and kernel are initialized.
pub fn set_timer_hook(f: fn()) {
    unsafe { idt::TIMER_HOOK = Some(f); }
}

/// Set the page-fault handler.
/// Called from main.rs after VMM is initialized.
pub fn set_page_fault_hook(f: fn(u64, bool, bool, bool, u64) -> bool) {
    unsafe { idt::PAGE_FAULT_HOOK = Some(f); }
}
