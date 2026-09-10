//! SHA-256 — Secure Hash Algorithm 256-bit (FIPS 180-4).
//!
//! Used by HMAC-SHA256 (transport MAC) and key derivation.
//! Pure Rust, no_std, no alloc.

// Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub struct Sha256 {
    state:  [u32; 8],
    buf:    [u8; 64],
    buflen: usize,
    total:  u64,
}

impl Sha256 {
    pub const fn new() -> Self {
        Self { state: H0, buf: [0; 64], buflen: 0, total: 0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut off = 0;
        self.total += data.len() as u64;

        // Fill partial buffer first
        if self.buflen > 0 {
            let need = 64 - self.buflen;
            let take = data.len().min(need);
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            off += take;
            if self.buflen == 64 {
                self.compress();
                self.buflen = 0;
            }
        }

        // Process full blocks
        while off + 64 <= data.len() {
            self.buf.copy_from_slice(&data[off..off + 64]);
            self.compress();
            off += 64;
        }

        // Keep remainder
        let rem = data.len() - off;
        if rem > 0 {
            self.buf[..rem].copy_from_slice(&data[off..]);
            self.buflen = rem;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        // Padding: append bit '1' then zeros then 64-bit length
        let bit_len = self.total * 8;
        self.buf[self.buflen] = 0x80;
        self.buflen += 1;

        if self.buflen > 56 {
            // Not enough room — pad with zeros, compress, start fresh block
            for i in self.buflen..64 { self.buf[i] = 0; }
            self.compress();
            self.buflen = 0;
        }
        for i in self.buflen..56 { self.buf[i] = 0; }
        // Append 64-bit message length in bits, big-endian
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.compress();

        let mut out = [0u8; 32];
        for (i, &w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self) {
        // Prepare message schedule W[0..64]
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(self.buf[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19)  ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..64 {
            let s1    = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch    = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0    = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj   = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g; g = f; f = e;
            e = d.wrapping_add(temp1);
            d = c; c = b; b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

pub fn hash2(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize()
}
