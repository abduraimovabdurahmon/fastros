//! x86 port I/O.

use core::arch::asm;

#[inline]
pub unsafe fn outb(port: u16, v: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags));
    }
}
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    unsafe {
        let v: u8;
        asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags));
        v
    }
}
#[inline]
pub unsafe fn outw(port: u16, v: u16) {
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags));
    }
}
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    unsafe {
        let v: u16;
        asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack, preserves_flags));
        v
    }
}
#[inline]
pub unsafe fn outl(port: u16, v: u32) {
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags));
    }
}
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    unsafe {
        let v: u32;
        asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack, preserves_flags));
        v
    }
}
/// Read `buf.len()` 16-bit words from `port` (ATA PIO data transfers).
#[inline]
pub unsafe fn insw(port: u16, buf: &mut [u16]) {
    unsafe {
        asm!("rep insw", in("dx") port, inout("rdi") buf.as_mut_ptr() => _,
             inout("rcx") buf.len() => _, options(nostack, preserves_flags));
    }
}
/// Write `buf.len()` 16-bit words to `port`.
#[inline]
pub unsafe fn outsw(port: u16, buf: &[u16]) {
    unsafe {
        asm!("rep outsw", in("dx") port, inout("rsi") buf.as_ptr() => _,
             inout("rcx") buf.len() => _, options(nostack, preserves_flags, readonly));
    }
}
/// A write to an unused port takes ~1 µs: the classic ISA settle delay.
#[inline]
pub fn io_wait() {
    unsafe { outb(0x80, 0) }
}
