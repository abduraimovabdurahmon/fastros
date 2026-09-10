//! Poly1305 one-time MAC (RFC 8439 §2.5).
//!
//! Authenticates messages using a 256-bit one-time key.
//! Used in chacha20-poly1305@openssh.com.
//!
//! Field: GF(2^130 - 5), using 130-bit integers represented as 5 × u64 limbs.

/// Compute Poly1305 MAC over `msg` using `key` (32 bytes).
/// Returns a 16-byte tag.
pub fn mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // Split key: r (16 bytes, clamped) + s (16 bytes)
    let mut r = [0u64; 3]; // 130-bit accumulator for r
    let s0 = u64::from_le_bytes(key[16..24].try_into().unwrap());
    let s1 = u64::from_le_bytes(key[24..32].try_into().unwrap());

    // Clamp r (RFC 8439 §2.5.1)
    let r0 = u64::from_le_bytes(key[0..8].try_into().unwrap())   & 0x0FFFFFFC0FFFFFFF;
    let r1 = u64::from_le_bytes(key[8..16].try_into().unwrap())  & 0x0FFFFFFC0FFFFFFC;

    // Accumulator
    let mut h = [0u128; 3]; // h[0], h[1], h[2] — 44-bit limbs each

    let r0 = r0 as u128;
    let r1 = r1 as u128;

    // Process 16-byte blocks
    let mut i = 0;
    while i < msg.len() {
        let block_len = (msg.len() - i).min(16);
        let mut block = [0u8; 17];
        block[..block_len].copy_from_slice(&msg[i..i+block_len]);
        block[block_len] = 1; // always add 2^(8*block_len) — the 1 bit

        // Interpret block as 130-bit integer (little-endian)
        let n0 = u128::from_le_bytes(block[0..16].try_into().unwrap());
        let n1 = block[16] as u128;

        // h += n
        h[0] += n0 & 0x3FFFFFFFFFFFF;          // low 44 bits
        h[1] += (n0 >> 44) & 0x3FFFFFFFFFFFF;   // next 44 bits
        h[2] += (n0 >> 88) | (n1 << 40);        // high 42 bits + carry bit

        // h *= r  (mod 2^130 - 5)
        // Full 130-bit × 130-bit mod (2^130-5) using schoolbook
        // h = h[0] + h[1]*2^44 + h[2]*2^88
        // r = r0 + r1*2^64 (but stored as two 64-bit halves)
        // We compute d = h*r mod (2^130-5)
        let d0: u128 = h[0]*r0 + h[2]*(r1*5*(1<<14));  // simplified
        let d1: u128 = h[0]*r1 + h[1]*r0 + h[2]*(r0>>44)*5;
        let d2: u128 = h[1]*r1 + h[2]*(r0 & 0x3FFFFFFFFFFF);

        // Propagate carries in 44-bit limbs
        let c0 = d0 >> 44;
        let c1 = (d1 + c0) >> 44;
        let c2 = (d2 + c1) >> 44;
        h[0] = (d0 & 0x3FFFFFFFFFFFF).wrapping_add(c2.wrapping_mul(5));
        h[1] = (d1 + (d0 >> 44)) & 0x3FFFFFFFFFFFF;
        h[2] = (d2 + ((d1 + (d0 >> 44)) >> 44)) & 0x3FFFFFFFFFFFF;
        let c = h[0] >> 44;
        h[0] &= 0x3FFFFFFFFFFFF;
        h[1] += c;
        let c = h[1] >> 44;
        h[1] &= 0x3FFFFFFFFFFFF;
        h[2] += c;

        i += 16;
    }

    // Fully reduce h mod (2^130 - 5)
    let mut c = h[2] >> 42;
    h[2] &= 0x3FFFFFFFFFF;
    h[0] += c * 5;
    c = h[0] >> 44; h[0] &= 0x3FFFFFFFFFFFF;
    h[1] += c;      c = h[1] >> 44; h[1] &= 0x3FFFFFFFFFFFF;
    h[2] += c;

    // If h >= 2^130 - 5, subtract 2^130 - 5
    let g0 = h[0].wrapping_add(5);
    let c  = g0 >> 44; let g0 = g0 & 0x3FFFFFFFFFFFF;
    let g1 = h[1].wrapping_add(c);
    let c  = g1 >> 44; let g1 = g1 & 0x3FFFFFFFFFFFF;
    let g2 = h[2].wrapping_add(c);
    let mask = !((g2 >> 42).wrapping_sub(1)); // all ones if g2 >= 2^42
    h[0] = (h[0] & !mask) | (g0 & mask);
    h[1] = (h[1] & !mask) | (g1 & mask);
    h[2] = (h[2] & !mask) | (g2 & mask);

    // Serialize h as 128-bit little-endian
    let n = (h[0] | (h[1] << 44) | (h[2] << 88)) as u128;

    // t = h + s (128-bit addition, wrapping)
    let t = n.wrapping_add(s0 as u128).wrapping_add((s1 as u128) << 64);

    let mut tag = [0u8; 16];
    tag.copy_from_slice(&t.to_le_bytes());
    tag
}
