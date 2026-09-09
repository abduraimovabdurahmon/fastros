//! x86_64 I/O port access (in/out instructions)
//!
//! Implements hal::IoInterface for x86_64.

/// Read a byte from an I/O port.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
    value
}

/// Write a byte to an I/O port.
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
}

/// Read a 16-bit word from an I/O port.
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    core::arch::asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack));
    value
}

/// Write a 16-bit word to an I/O port.
#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack));
}

/// Read a 32-bit dword from an I/O port.
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    core::arch::asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack));
    value
}

/// Write a 32-bit dword to an I/O port.
#[inline]
pub unsafe fn outl(port: u16, value: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack));
}

/// Small I/O delay (write to unused port 0x80).
#[inline]
pub unsafe fn io_wait() {
    outb(0x80, 0);
}
