//! HMAC-SHA-256 backed by the audited `hmac` + `sha2` crates (no_std, no alloc).
//! Used for SSH transport layer packet authentication.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacInner = Hmac<Sha256>;

pub struct HmacSha256(HmacInner);

impl HmacSha256 {
    /// Create a new HMAC-SHA256 context. Accepts any key length.
    pub fn new(key: &[u8]) -> Self {
        // new_from_slice accepts any key length per RFC 2104; never returns Err.
        Self(HmacInner::new_from_slice(key).unwrap())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let out = self.0.finalize().into_bytes();
        out.as_slice().try_into().unwrap()
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
