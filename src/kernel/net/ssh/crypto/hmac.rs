//! HMAC-SHA256 — Hash-based Message Authentication Code (RFC 2104).
//!
//! Used for SSH transport layer MAC (when not using AEAD).

use super::sha256::Sha256;

const BLOCK: usize = 64;

pub struct HmacSha256 {
    inner: Sha256,
    okey:  [u8; BLOCK],
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK];
        if key.len() > BLOCK {
            // Keys longer than block size are hashed first
            let h = super::sha256::hash(key);
            k[..32].copy_from_slice(&h);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut ikey = [0u8; BLOCK];
        let mut okey = [0u8; BLOCK];
        for i in 0..BLOCK { ikey[i] = k[i] ^ 0x36; okey[i] = k[i] ^ 0x5C; }

        let mut inner = Sha256::new();
        inner.update(&ikey);
        Self { inner, okey }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let inner_hash = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.okey);
        outer.update(&inner_hash);
        outer.finalize()
    }
}

pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = HmacSha256::new(key);
    h.update(data);
    h.finalize()
}

pub fn mac2(key: &[u8], a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = HmacSha256::new(key);
    h.update(a);
    h.update(b);
    h.finalize()
}
