//! no_std formatting utilities
//!
//! Provides integer-to-string conversion without heap allocation.
//! Used for kernel debug output (VGA, serial).

/// Write a u64 as decimal into a fixed buffer. Returns the written slice.
pub fn u64_to_dec(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    if n == 0 {
        buf[19] = b'0';
        return &buf[19..];
    }
    let mut i = 20;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}

/// Write a u64 as lowercase hex (with "0x" prefix) into a fixed buffer.
pub fn u64_to_hex(mut n: u64, buf: &mut [u8; 18]) -> &[u8] {
    buf[0] = b'0';
    buf[1] = b'x';
    let hex = b"0123456789abcdef";
    for i in 0..16 {
        buf[17 - i] = hex[(n & 0xF) as usize];
        n >>= 4;
    }
    &buf[..]
}
