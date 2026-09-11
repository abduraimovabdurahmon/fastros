//! Small, strict codecs.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod base64 {
    use alloc::string::String;
    use alloc::vec::Vec;

    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    fn enc(data: &[u8], alpha: &[u8; 64], pad: bool) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            let chars = chunk.len() + 1;
            for i in 0..4 {
                if i < chars {
                    out.push(alpha[(n >> (18 - 6 * i)) as usize & 63] as char);
                } else if pad {
                    out.push('=');
                }
            }
        }
        out
    }

    fn dec(s: &str, alpha: &[u8; 64]) -> Option<Vec<u8>> {
        let s = s.trim_end_matches('=');
        let mut map = [255u8; 256];
        for (i, &c) in alpha.iter().enumerate() {
            map[c as usize] = i as u8;
        }
        let mut out = Vec::with_capacity(s.len() * 3 / 4);
        let mut acc = 0u32;
        let mut bits = 0;
        for c in s.bytes() {
            if c == b'\n' || c == b'\r' || c == b' ' {
                continue;
            }
            let v = map[c as usize];
            if v == 255 {
                return None;
            }
            acc = acc << 6 | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        // Leftover bits must be zero padding (strict decoding).
        if bits >= 6 || acc != 0 {
            return None;
        }
        Some(out)
    }

    pub fn encode(data: &[u8]) -> String {
        enc(data, STD, true)
    }
    pub fn encode_nopad(data: &[u8]) -> String {
        enc(data, STD, false)
    }
    pub fn encode_url(data: &[u8]) -> String {
        enc(data, URL, false)
    }
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        dec(s, STD)
    }
    pub fn decode_url(s: &str) -> Option<Vec<u8>> {
        dec(s, URL)
    }
}

pub mod hex {
    use alloc::string::String;
    use alloc::vec::Vec;

    pub fn encode(data: &[u8]) -> String {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(data.len() * 2);
        for &b in data {
            s.push(H[(b >> 4) as usize] as char);
            s.push(H[(b & 15) as usize] as char);
        }
        s
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 {
            return None;
        }
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        let v = [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")];
        for (plain, enc) in v {
            assert_eq!(base64::encode(plain.as_bytes()), enc);
            assert_eq!(base64::decode(enc).unwrap(), plain.as_bytes());
            assert_eq!(base64::decode(enc.trim_end_matches('=')).unwrap(), plain.as_bytes());
        }
        assert_eq!(base64::decode("Zm9v!"), None);
        assert_eq!(base64::decode("Zh=="), None, "non-zero padding bits");
        let bin: Vec<u8> = (0..=255).collect();
        assert_eq!(base64::decode_url(&base64::encode_url(&bin)).unwrap(), bin);
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex::encode(&[0, 15, 255]), "000fff");
        assert_eq!(hex::decode("000fff").unwrap(), vec![0, 15, 255]);
        assert_eq!(hex::decode("0g"), None);
        assert_eq!(hex::decode("abc"), None);
    }
}
