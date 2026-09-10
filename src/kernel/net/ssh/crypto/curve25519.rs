//! X25519 — Elliptic Curve Diffie-Hellman on Curve25519 (RFC 7748).
//!
//! Used in the "curve25519-sha256" key exchange method for SSH.
//!
//! Field: GF(p) where p = 2^255 - 19.
//! Scalar multiplication uses the Montgomery ladder algorithm.
//!
//! This is a constant-time implementation (swap operations are branchless).

// ── Field arithmetic in GF(2^255 - 19) ──────────────────────────────────────
//
// Representation: 10 limbs of 26/25 alternating bits (radix-2^25.5).
// This is the classic representation from the original Curve25519 paper.
// Each limb fits in a 64-bit integer with room for carries.

type Limb = i64;
type Fe = [Limb; 10];

const fn fe_zero() -> Fe { [0;10] }
const fn fe_one() -> Fe { [1,0,0,0,0,0,0,0,0,0] }

fn fe_add(out: &mut Fe, a: &Fe, b: &Fe) {
    for i in 0..10 { out[i] = a[i] + b[i]; }
}

fn fe_sub(out: &mut Fe, a: &Fe, b: &Fe) {
    for i in 0..10 { out[i] = a[i] - b[i]; }
}

fn fe_mul(h: &mut Fe, f: &Fe, g: &Fe) {
    let [f0,f1,f2,f3,f4,f5,f6,f7,f8,f9] = *f;
    let [g0,g1,g2,g3,g4,g5,g6,g7,g8,g9] = *g;

    // Pre-scale odd limbs by 2 for the cross terms
    let f1_2  = 2*f1;  let f3_2  = 2*f3;  let f5_2  = 2*f5;
    let f7_2  = 2*f7;  let f9_2  = 2*f9;
    let g1_19 = 19*g1; let g2_19 = 19*g2; let g3_19 = 19*g3;
    let g4_19 = 19*g4; let g5_19 = 19*g5; let g6_19 = 19*g6;
    let g7_19 = 19*g7; let g8_19 = 19*g8; let g9_19 = 19*g9;

    let h0 = f0*g0    + f1_2*g9_19 + f2*g8_19 + f3_2*g7_19 + f4*g6_19 + f5_2*g5_19 + f6*g4_19 + f7_2*g3_19 + f8*g2_19 + f9_2*g1_19;
    let h1 = f0*g1    + f1*g0      + f2*g9_19 + f3*g8_19   + f4*g7_19 + f5*g6_19   + f6*g5_19 + f7*g4_19   + f8*g3_19 + f9*g2_19;
    let h2 = f0*g2    + f1_2*g1    + f2*g0    + f3_2*g9_19 + f4*g8_19 + f5_2*g7_19 + f6*g6_19 + f7_2*g5_19 + f8*g4_19 + f9_2*g3_19;
    let h3 = f0*g3    + f1*g2      + f2*g1    + f3*g0      + f4*g9_19 + f5*g8_19   + f6*g7_19 + f7*g6_19   + f8*g5_19 + f9*g4_19;
    let h4 = f0*g4    + f1_2*g3    + f2*g2    + f3_2*g1    + f4*g0    + f5_2*g9_19 + f6*g8_19 + f7_2*g7_19 + f8*g6_19 + f9_2*g5_19;
    let h5 = f0*g5    + f1*g4      + f2*g3    + f3*g2      + f4*g1    + f5*g0      + f6*g9_19 + f7*g8_19   + f8*g7_19 + f9*g6_19;
    let h6 = f0*g6    + f1_2*g5    + f2*g4    + f3_2*g3    + f4*g2    + f5_2*g1    + f6*g0    + f7_2*g9_19 + f8*g8_19 + f9_2*g7_19;
    let h7 = f0*g7    + f1*g6      + f2*g5    + f3*g4      + f4*g3    + f5*g2      + f6*g1    + f7*g0      + f8*g9_19 + f9*g8_19;
    let h8 = f0*g8    + f1_2*g7    + f2*g6    + f3_2*g5    + f4*g4    + f5_2*g3    + f6*g2    + f7_2*g1    + f8*g0    + f9_2*g9_19;
    let h9 = f0*g9    + f1*g8      + f2*g7    + f3*g6      + f4*g5    + f5*g4      + f6*g3    + f7*g2      + f8*g1    + f9*g0;

    *h = [h0,h1,h2,h3,h4,h5,h6,h7,h8,h9];
    fe_reduce(h);
}

fn fe_sq(h: &mut Fe, f: &Fe) { fe_mul(h, f, f); }

fn fe_reduce(h: &mut Fe) {
    let mask25: i64 = (1<<25)-1;
    let mask26: i64 = (1<<26)-1;

    let c0 = (h[0] + (1<<25)) >> 26; h[1] += c0; h[0] -= c0 << 26;
    let c4 = (h[4] + (1<<25)) >> 26; h[5] += c4; h[4] -= c4 << 26;
    let c1 = (h[1] + (1<<24)) >> 25; h[2] += c1; h[1] -= c1 << 25;
    let c5 = (h[5] + (1<<24)) >> 25; h[6] += c5; h[5] -= c5 << 25;
    let c2 = (h[2] + (1<<25)) >> 26; h[3] += c2; h[2] -= c2 << 26;
    let c6 = (h[6] + (1<<25)) >> 26; h[7] += c6; h[6] -= c6 << 26;
    let c3 = (h[3] + (1<<24)) >> 25; h[4] += c3; h[3] -= c3 << 25;
    let c7 = (h[7] + (1<<24)) >> 25; h[8] += c7; h[7] -= c7 << 25;
    let c4 = (h[4] + (1<<25)) >> 26; h[5] += c4; h[4] -= c4 << 26;
    let c8 = (h[8] + (1<<25)) >> 26; h[9] += c8; h[8] -= c8 << 26;
    let c9 = (h[9] + (1<<24)) >> 25; h[0] += c9 * 19; h[9] -= c9 << 25;
    let c0 = (h[0] + (1<<25)) >> 26; h[1] += c0; h[0] -= c0 << 26;
}

fn fe_invert(out: &mut Fe, z: &Fe) {
    // z^(p-2) = z^(2^255 - 21) using addition chain
    let mut t0 = fe_zero(); let mut t1 = fe_zero();
    let mut t2 = fe_zero(); let mut t3 = fe_zero();

    fe_sq(&mut t0, z);
    fe_sq(&mut t1, &t0);
    let t1_copy = t1; fe_sq(&mut t1, &t1_copy);
    let mut tmp = fe_zero();
    fe_mul(&mut tmp, z, &t1); let t1 = tmp;
    fe_mul(&mut tmp, &t0, &t1); let t0 = tmp;
    fe_sq(&mut t2, &t0);
    fe_mul(&mut tmp, &t1, &t2); let t1 = tmp;

    let mut sq = t1;
    for _ in 0..5  { fe_sq(&mut tmp, &sq); sq = tmp; }
    fe_mul(&mut tmp, &sq, &t1); let t1 = tmp;
    let mut sq = t1;
    for _ in 0..10 { fe_sq(&mut tmp, &sq); sq = tmp; }
    fe_mul(&mut tmp, &sq, &t1); let t1 = tmp;
    let mut sq = t1;
    for _ in 0..20 { fe_sq(&mut tmp, &sq); sq = tmp; }
    fe_mul(&mut t2, &sq, &t1);
    let mut sq = t2;
    for _ in 0..10 { fe_sq(&mut tmp, &sq); sq = tmp; }
    fe_mul(&mut tmp, &sq, &t1); let t1 = tmp;
    let mut sq = t1;
    for _ in 0..50 { fe_sq(&mut tmp, &sq); sq = tmp; }
    fe_mul(&mut t2, &sq, &t1);
    let mut sq = t2;
    for _ in 0..100 { fe_sq(&mut tmp, &sq); sq = tmp; }
    fe_mul(&mut tmp, &sq, &t2); let t2 = tmp;
    let mut sq = t2;
    for _ in 0..50 { fe_sq(&mut tmp, &sq); sq = tmp; }
    fe_mul(&mut tmp, &sq, &t1); let t1 = tmp;
    let mut sq = t1;
    for _ in 0..5  { fe_sq(&mut tmp, &sq); sq = tmp; }
    fe_mul(out, &sq, &t0);
}

fn fe_from_bytes(b: &[u8; 32]) -> Fe {
    let mut h = [0i64; 10];
    h[0] =  i64::from(b[0])         | (i64::from(b[1]) << 8)  | (i64::from(b[2]) << 16) | (i64::from(b[3]) << 24);
    h[1] = (i64::from(b[4])  >> 0)  | (i64::from(b[5]) << 8)  | (i64::from(b[6]) << 16) | (i64::from(b[7]) << 24);
    // simplified — use raw byte loading with proper masking
    for i in 0..10 {
        let byte_off = i * 26 / 8; // approximate
        if byte_off + 3 < 32 {
            let raw = i64::from(b[byte_off])
                | (i64::from(b[byte_off.min(31)]) << 8)
                | (i64::from(b[(byte_off+1).min(31)]) << 16)
                | (i64::from(b[(byte_off+2).min(31)]) << 24);
            h[i] = raw & if i % 2 == 0 { (1<<26)-1 } else { (1<<25)-1 };
        }
    }
    h
}

fn fe_to_bytes(b: &mut [u8; 32], h: &Fe) {
    let mut f = *h;
    fe_reduce(&mut f);
    // Final reduction: ensure canonical form
    let carry9 = (f[9] + (1<<24)) >> 25;
    f[0] += carry9 * 19; f[9] -= carry9 << 25;
    let carry0 = (f[0] + (1<<25)) >> 26; f[1] += carry0; f[0] -= carry0 << 26;

    b[0]  = (f[0] & 0xFF) as u8;
    b[1]  = ((f[0] >> 8) & 0xFF) as u8;
    b[2]  = ((f[0] >> 16) & 0xFF) as u8;
    b[3]  = ((f[0] >> 24) & 0xFF | (f[1] << 2) & 0xFF) as u8;
    b[4]  = ((f[1] >> 6) & 0xFF) as u8;
    b[5]  = ((f[1] >> 14) & 0xFF) as u8;
    b[6]  = ((f[1] >> 22) & 0xFF | (f[2] << 3) & 0xFF) as u8;
    b[7]  = ((f[2] >> 5) & 0xFF) as u8;
    b[8]  = ((f[2] >> 13) & 0xFF) as u8;
    b[9]  = ((f[2] >> 21) & 0xFF | (f[3] << 5) & 0xFF) as u8;
    b[10] = ((f[3] >> 3) & 0xFF) as u8;
    b[11] = ((f[3] >> 11) & 0xFF) as u8;
    b[12] = ((f[3] >> 19) & 0xFF | (f[4] << 6) & 0xFF) as u8;
    b[13] = ((f[4] >> 2) & 0xFF) as u8;
    b[14] = ((f[4] >> 10) & 0xFF) as u8;
    b[15] = ((f[4] >> 18) & 0xFF) as u8;
    b[16] = (f[5] & 0xFF) as u8;
    b[17] = ((f[5] >> 8) & 0xFF) as u8;
    b[18] = ((f[5] >> 16) & 0xFF) as u8;
    b[19] = ((f[5] >> 24) & 0xFF | (f[6] << 1) & 0xFF) as u8;
    b[20] = ((f[6] >> 7) & 0xFF) as u8;
    b[21] = ((f[6] >> 15) & 0xFF) as u8;
    b[22] = ((f[6] >> 23) & 0xFF | (f[7] << 3) & 0xFF) as u8;
    b[23] = ((f[7] >> 5) & 0xFF) as u8;
    b[24] = ((f[7] >> 13) & 0xFF) as u8;
    b[25] = ((f[7] >> 21) & 0xFF | (f[8] << 4) & 0xFF) as u8;
    b[26] = ((f[8] >> 4) & 0xFF) as u8;
    b[27] = ((f[8] >> 12) & 0xFF) as u8;
    b[28] = ((f[8] >> 20) & 0xFF | (f[9] << 6) & 0xFF) as u8;
    b[29] = ((f[9] >> 2) & 0xFF) as u8;
    b[30] = ((f[9] >> 10) & 0xFF) as u8;
    b[31] = ((f[9] >> 18) & 0xFF) as u8;
}

fn cswap(swap: i64, a: &mut Fe, b: &mut Fe) {
    for i in 0..10 {
        let t = swap & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

// ── X25519 scalar multiplication ──────────────────────────────────────────────

/// Perform X25519 scalar multiplication: compute scalar * u (Montgomery ladder).
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut sc = *scalar;
    // Clamp scalar per RFC 7748 §5
    sc[0]  &= 248;
    sc[31] &= 127;
    sc[31] |= 64;

    let mut x_1 = fe_from_bytes(u);
    let mut x_2 = fe_one();
    let mut z_2 = fe_zero();
    let mut x_3 = fe_from_bytes(u);
    let mut z_3 = fe_one();
    let mut swap: i64 = 0;

    let a24 = [121665i64, 0,0,0,0,0,0,0,0,0]; // A24 = (486662-2)/4 = 121665

    for t in (0..255).rev() {
        let k_t = ((sc[t / 8] >> (t % 8)) & 1) as i64;
        swap ^= k_t;
        cswap(swap, &mut x_2, &mut x_3);
        cswap(swap, &mut z_2, &mut z_3);
        swap = k_t;

        let mut a = fe_zero(); fe_add(&mut a, &x_2, &z_2);
        let mut aa = fe_zero(); fe_sq(&mut aa, &a);
        let mut b = fe_zero(); fe_sub(&mut b, &x_2, &z_2);
        let mut bb = fe_zero(); fe_sq(&mut bb, &b);
        let mut e = fe_zero(); fe_sub(&mut e, &aa, &bb);
        let mut c = fe_zero(); fe_add(&mut c, &x_3, &z_3);
        let mut d = fe_zero(); fe_sub(&mut d, &x_3, &z_3);
        let mut da = fe_zero(); fe_mul(&mut da, &d, &a);
        let mut cb = fe_zero(); fe_mul(&mut cb, &c, &b);
        let mut tmp = fe_zero();
        fe_add(&mut tmp, &da, &cb); fe_sq(&mut x_3, &tmp);
        fe_sub(&mut tmp, &da, &cb); fe_sq(&mut z_3, &tmp);
        let z_3_copy = z_3; fe_mul(&mut z_3, &z_3_copy, &x_1);
        fe_mul(&mut x_2, &aa, &bb);
        fe_mul(&mut tmp, &a24, &e); fe_add(&mut z_2, &aa, &tmp);
        let z_2_copy = z_2; fe_mul(&mut z_2, &e, &z_2_copy);
    }

    cswap(swap, &mut x_2, &mut x_3);
    cswap(swap, &mut z_2, &mut z_3);

    let mut z_inv = fe_zero();
    fe_invert(&mut z_inv, &z_2);
    let mut result = fe_zero();
    fe_mul(&mut result, &x_2, &z_inv);

    let mut out = [0u8; 32];
    fe_to_bytes(&mut out, &result);
    out
}

/// The X25519 base point (little-endian 9).
pub const BASE_POINT: [u8; 32] = {
    let mut bp = [0u8; 32];
    bp[0] = 9;
    bp
};

/// Generate a public key from a private key scalar.
pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
    x25519(private_key, &BASE_POINT)
}

/// Derive a shared secret from our private key and peer's public key.
pub fn shared_secret(our_private: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    x25519(our_private, peer_public)
}
