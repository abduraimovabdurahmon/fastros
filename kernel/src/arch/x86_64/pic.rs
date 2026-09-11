//! Legacy 8259A PIC pair, remapped to vectors 32..48.

use super::port::{inb, io_wait, outb};
use crate::sync::SpinLock;

const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xA0;
const SLAVE_DATA: u16 = 0xA1;

/// Cached interrupt masks (bit set = line masked).
static MASK: SpinLock<u16> = SpinLock::new(0xFFFF);

pub fn init(base: u8) {
    unsafe {
        outb(MASTER_CMD, 0x11);
        io_wait();
        outb(SLAVE_CMD, 0x11);
        io_wait();
        outb(MASTER_DATA, base);
        io_wait();
        outb(SLAVE_DATA, base + 8);
        io_wait();
        outb(MASTER_DATA, 0x04); // slave on IRQ 2
        io_wait();
        outb(SLAVE_DATA, 0x02);
        io_wait();
        outb(MASTER_DATA, 0x01); // 8086 mode
        io_wait();
        outb(SLAVE_DATA, 0x01);
        io_wait();
    }
    write_mask(0xFFFF & !(1 << 2)); // everything masked except the cascade
}

fn write_mask(mask: u16) {
    *MASK.lock() = mask;
    unsafe {
        outb(MASTER_DATA, mask as u8);
        outb(SLAVE_DATA, (mask >> 8) as u8);
    }
}

pub fn unmask(irq: u8) {
    let m = *MASK.lock() & !(1u16 << irq);
    write_mask(m);
}

pub fn mask(irq: u8) {
    let m = *MASK.lock() | (1u16 << irq);
    write_mask(m);
}

pub fn eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(SLAVE_CMD, 0x20);
        }
        outb(MASTER_CMD, 0x20);
    }
}

/// In-service register: distinguishes a real IRQ 7/15 from a spurious one.
pub fn is_spurious(irq: u8) -> bool {
    unsafe {
        match irq {
            7 => {
                outb(MASTER_CMD, 0x0B);
                inb(MASTER_CMD) & 0x80 == 0
            }
            15 => {
                outb(SLAVE_CMD, 0x0B);
                let spurious = inb(SLAVE_CMD) & 0x80 == 0;
                if spurious {
                    outb(MASTER_CMD, 0x20); // the master did see the cascade IRQ
                }
                spurious
            }
            _ => false,
        }
    }
}
