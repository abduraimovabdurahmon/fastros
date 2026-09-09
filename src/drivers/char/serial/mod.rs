//! UART 16550 Serial Driver (COM1–COM4)
//!
//! COM1 = port 0x3F8, IRQ 4
//! COM2 = port 0x2F8, IRQ 3
//!
//! Essential for early kernel debugging — visible in QEMU terminal via -serial stdio.
//! Much faster than VGA for debug output during boot.

const COM1: u16 = 0x3F8;

pub fn init() {
    unsafe {
        // Disable interrupts
        outb(COM1 + 1, 0x00);
        // Enable DLAB (baud rate divisor)
        outb(COM1 + 3, 0x80);
        // Set baud rate divisor = 3 (38400 baud)
        outb(COM1 + 0, 0x03);
        outb(COM1 + 1, 0x00);
        // 8 bits, no parity, 1 stop bit
        outb(COM1 + 3, 0x03);
        // Enable FIFO, clear, 14-byte threshold
        outb(COM1 + 2, 0xC7);
        // Enable IRQs, RTS/DSR set
        outb(COM1 + 4, 0x0B);
    }
}

pub fn write_byte(byte: u8) {
    unsafe {
        // Wait until transmit buffer is empty
        while (inb(COM1 + 5) & 0x20) == 0 {}
        outb(COM1, byte);
    }
}

pub fn write(msg: &[u8]) {
    for &byte in msg {
        if byte == b'\n' { write_byte(b'\r'); }
        write_byte(byte);
    }
}

unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}

unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
    val
}
