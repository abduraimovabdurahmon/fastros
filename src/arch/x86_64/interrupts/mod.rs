//! x86_64 Interrupt handling: IDT, PIC, APIC

pub mod apic;
pub mod idt;
pub mod pic;

pub fn init_idt() {
    idt::load();
}
