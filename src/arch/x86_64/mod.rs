//! x86_64 architecture module
//!
//! Initializes all x86_64 hardware in the correct order.

pub mod boot;
pub mod cpu;
pub mod interrupts;
pub mod io;
pub mod memory;

pub fn init() {
    boot::init_gdt();
    interrupts::init_idt();
}
