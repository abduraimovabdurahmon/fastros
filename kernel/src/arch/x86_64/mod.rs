//! x86_64 support: boot stub, descriptor tables, traps, interrupt
//! controller, timers, paging and context switching.

pub mod boot;
pub mod context;
pub mod cpu;
pub mod gdt;
pub mod paging;
pub mod pic;
pub mod pit;
pub mod port;
pub mod rtc;
pub mod syscall;
pub mod trap;

/// First-stage CPU setup: runs before memory management exists.
pub fn early_init() {
    cpu::detect();
    gdt::init();
    trap::init_idt();
    syscall::init();
}

/// Interrupt controller + tick source (needs the heap for handler tables).
pub fn init_interrupts(tick_hz: u32) {
    pic::init(trap::VEC_IRQ_BASE);
    pit::start_periodic(tick_hz);
    pic::unmask(0);
}
