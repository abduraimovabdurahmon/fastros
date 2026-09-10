//! Internet checksum — RFC 1071.
//!
//! One's complement sum of 16-bit words.
//! Used by IP, ICMP, TCP, UDP headers.
//!
//! Linux equivalent: include/net/checksum.h  lib/checksum.c

/// Compute the Internet checksum over `data`.
pub fn compute(data: &[u8]) -> u16 {
    fold(accumulate(data, 0))
}

/// Accumulate `data` into a running 32-bit partial sum.
/// Call multiple times for pseudo-header + payload, then `fold()`.
pub fn accumulate(data: &[u8], mut acc: u32) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        acc = acc.wrapping_add(((data[i] as u32) << 8) | data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        // odd trailing byte — pad with zero (big-endian)
        acc = acc.wrapping_add((data[i] as u32) << 8);
    }
    acc
}

/// Fold a 32-bit accumulator into a 16-bit one's complement checksum.
pub fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}
