//! 16550 UART on COM1: the kernel console and log sink.

use crate::arch::port::{inb, outb};
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

const COM1: u16 = 0x3F8;

static PRESENT: AtomicBool = AtomicBool::new(false);
pub static LOCK: SpinLock<()> = SpinLock::new(());

pub fn init() {
    unsafe {
        outb(COM1 + 1, 0x00); // no interrupts (enabled later for console input)
        outb(COM1 + 3, 0x80); // DLAB
        outb(COM1, 0x01); // 115200 baud
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03); // 8N1
        outb(COM1 + 2, 0xC7); // FIFO on, clear, 14-byte threshold
        outb(COM1 + 4, 0x0B); // DTR RTS OUT2
        // Loopback self-test.
        outb(COM1 + 4, 0x1E);
        outb(COM1, 0xAE);
        let ok = inb(COM1) == 0xAE;
        outb(COM1 + 4, 0x0F);
        PRESENT.store(ok, Ordering::Relaxed);
    }
}

#[inline]
fn put(b: u8) {
    unsafe {
        let mut spins = 0u32;
        while inb(COM1 + 5) & 0x20 == 0 && spins < 100_000 {
            spins += 1;
            core::hint::spin_loop();
        }
        outb(COM1, b);
    }
}

/// Write bytes (LF → CRLF). Caller holds `LOCK` or is the panic path.
pub fn write_raw(s: &[u8]) {
    if !PRESENT.load(Ordering::Relaxed) {
        return;
    }
    for &b in s {
        if b == b'\n' {
            put(b'\r');
        }
        put(b);
    }
}

pub fn write(s: &[u8]) {
    let _g = LOCK.lock();
    write_raw(s);
}

/// Non-blocking read of one received byte.
pub fn read_byte() -> Option<u8> {
    if !PRESENT.load(Ordering::Relaxed) {
        return None;
    }
    unsafe { (inb(COM1 + 5) & 1 != 0).then(|| inb(COM1)) }
}

/// Enable the "data available" interrupt (IRQ 4) for console input.
pub fn enable_rx_irq() {
    unsafe { outb(COM1 + 1, 0x01) };
}

/// Write bytes exactly as given (terminal output already processed).
pub fn write_verbatim(s: &[u8]) {
    if !PRESENT.load(Ordering::Relaxed) {
        return;
    }
    let _g = LOCK.lock();
    for &b in s {
        put(b);
    }
}
