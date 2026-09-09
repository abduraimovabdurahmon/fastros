//! Legacy 8259 PIC (Programmable Interrupt Controller)
//!
//! Two cascaded PIC chips (master + slave) handle IRQ 0–15.
//! Must be remapped away from CPU exception vectors (0–31).
//! Usually replaced by APIC on modern systems, but needed for QEMU basic mode.
//!
//! Default x86 mapping (WRONG — conflicts with CPU exceptions):
//!   IRQ 0–7  → INT 0x08–0x0F
//!   IRQ 8–15 → INT 0x70–0x77
//!
//! Our remapping:
//!   IRQ 0–7  → INT 0x20–0x27
//!   IRQ 8–15 → INT 0x28–0x2F

const MASTER_CMD:  u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD:   u16 = 0xA0;
const SLAVE_DATA:  u16 = 0xA1;

const ICW1_INIT: u8 = 0x11;
const ICW4_8086: u8 = 0x01;

const MASTER_OFFSET: u8 = 0x20; // IRQ 0 → vector 32
const SLAVE_OFFSET:  u8 = 0x28; // IRQ 8 → vector 40

pub fn remap() {
    // TODO: remap PIC using port I/O (in/out instructions via hal::io)
}

pub fn end_of_interrupt(irq: u8) {
    if irq >= 8 {
        // Send EOI to slave
        // TODO: out(SLAVE_CMD, 0x20)
    }
    // Send EOI to master
    // TODO: out(MASTER_CMD, 0x20)
}

pub fn mask_all() {
    // TODO: out(MASTER_DATA, 0xFF); out(SLAVE_DATA, 0xFF)
}
