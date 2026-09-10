//! Legacy 8259 PIC — Programmable Interrupt Controller
//!
//! Two cascaded chips: master (IRQ 0–7) + slave (IRQ 8–15).
//! Default vectors conflict with CPU exceptions (0–31), so we remap:
//!   IRQ  0–7  → vector 0x20–0x27
//!   IRQ  8–15 → vector 0x28–0x2F

use crate::arch::x86_64::io::{inb, io_wait, outb};

const MASTER_CMD:  u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD:   u16 = 0xA0;
const SLAVE_DATA:  u16 = 0xA1;

pub const IRQ_BASE: u8 = 0x20; // IRQ 0 → vector 32

/// Remap both PICs and mask all IRQs (drivers unmask selectively).
pub fn remap() {
    unsafe {
        // Save existing masks
        let mask_m = inb(MASTER_DATA);
        let mask_s = inb(SLAVE_DATA);

        // ICW1: start init sequence (cascade mode)
        outb(MASTER_CMD,  0x11); io_wait();
        outb(SLAVE_CMD,   0x11); io_wait();
        // ICW2: vector offsets
        outb(MASTER_DATA, IRQ_BASE);     io_wait(); // master IRQs → 0x20+
        outb(SLAVE_DATA,  IRQ_BASE + 8); io_wait(); // slave  IRQs → 0x28+
        // ICW3: cascade wiring
        outb(MASTER_DATA, 0x04); io_wait(); // master: slave on IRQ2 (bit 2)
        outb(SLAVE_DATA,  0x02); io_wait(); // slave:  cascade identity = 2
        // ICW4: 8086 mode
        outb(MASTER_DATA, 0x01); io_wait();
        outb(SLAVE_DATA,  0x01); io_wait();

        // Restore masks (or mask all — drivers will unmask what they need)
        outb(MASTER_DATA, mask_m);
        outb(SLAVE_DATA,  mask_s);
    }
}

/// Mask all IRQs — call after remap, before enabling specific drivers.
pub fn mask_all() {
    unsafe {
        outb(MASTER_DATA, 0xFF);
        outb(SLAVE_DATA,  0xFF);
    }
}

/// Unmask a single IRQ line (0–15).
pub fn unmask(irq: u8) {
    unsafe {
        if irq < 8 {
            let mask = inb(MASTER_DATA) & !(1 << irq);
            outb(MASTER_DATA, mask);
        } else {
            let mask = inb(SLAVE_DATA) & !(1 << (irq - 8));
            outb(SLAVE_DATA, mask);
            // Also unmask IRQ2 on master (cascade line)
            let master_mask = inb(MASTER_DATA) & !(1 << 2);
            outb(MASTER_DATA, master_mask);
        }
    }
}

/// Send End-Of-Interrupt to acknowledge an IRQ.
/// Must be called at the end of every IRQ handler.
pub fn end_of_interrupt(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(SLAVE_CMD, 0x20); // EOI to slave
        }
        outb(MASTER_CMD, 0x20);    // EOI to master (always)
    }
}
