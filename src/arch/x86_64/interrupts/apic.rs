//! APIC — Advanced Programmable Interrupt Controller
//!
//! Modern replacement for the legacy 8259 PIC.
//! Two components:
//!   - Local APIC (LAPIC): one per CPU core, handles timer + IPI
//!   - I/O APIC: global, routes hardware IRQs to LAPICs
//!
//! Required for SMP (symmetric multiprocessing).

// TODO: Read APIC base from MSR (IA32_APIC_BASE = 0x1B).
// TODO: Map LAPIC MMIO registers.
// TODO: Initialize IOAPIC for IRQ routing.
// TODO: Implement LAPIC timer for scheduler preemption.

pub fn init() {
    // TODO
}
