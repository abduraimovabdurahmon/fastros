//! SSH binary encodings (RFC 4251 §5).

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated;

pub struct Reader<'a> {
    b: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, pos: 0 }
    }
    pub fn u8(&mut self) -> Result<u8, Truncated> {
        let v = *self.b.get(self.pos).ok_or(Truncated)?;
        self.pos += 1;
        Ok(v)
    }
    pub fn bool(&mut self) -> Result<bool, Truncated> {
        Ok(self.u8()? != 0)
    }
    pub fn u32(&mut self) -> Result<u32, Truncated> {
        let s = self.b.get(self.pos..self.pos + 4).ok_or(Truncated)?;
        self.pos += 4;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        let s = self.b.get(self.pos..self.pos.checked_add(n).ok_or(Truncated)?).ok_or(Truncated)?;
        self.pos += n;
        Ok(s)
    }
    pub fn string(&mut self) -> Result<&'a [u8], Truncated> {
        let n = self.u32()? as usize;
        self.bytes(n)
    }
    pub fn utf8(&mut self) -> Result<String, Truncated> {
        Ok(String::from_utf8_lossy(self.string()?).into_owned())
    }
    pub fn name_list(&mut self) -> Result<Vec<String>, Truncated> {
        let s = self.utf8()?;
        Ok(if s.is_empty() { Vec::new() } else { s.split(',').map(String::from).collect() })
    }
    pub fn rest(&self) -> &'a [u8] {
        &self.b[self.pos.min(self.b.len())..]
    }
}

#[derive(Default)]
pub struct Writer {
    pub b: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer { b: Vec::new() }
    }
    pub fn msg(t: u8) -> Writer {
        Writer { b: alloc::vec![t] }
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.b.push(v);
        self
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.b.push(v as u8);
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.b.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.b.extend_from_slice(v);
        self
    }
    pub fn string(&mut self, v: &[u8]) -> &mut Self {
        self.u32(v.len() as u32);
        self.b.extend_from_slice(v);
        self
    }
    pub fn str(&mut self, v: &str) -> &mut Self {
        self.string(v.as_bytes())
    }
    /// Unsigned big-endian integer as an SSH `mpint`.
    pub fn mpint(&mut self, v: &[u8]) -> &mut Self {
        let mut i = 0;
        while i < v.len() && v[i] == 0 {
            i += 1;
        }
        let v = &v[i..];
        if v.first().is_some_and(|&b| b & 0x80 != 0) {
            self.u32(v.len() as u32 + 1);
            self.b.push(0);
        } else {
            self.u32(v.len() as u32);
        }
        self.b.extend_from_slice(v);
        self
    }
    pub fn done(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.b)
    }
}

pub mod msg {
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const UNIMPLEMENTED: u8 = 3;
    pub const DEBUG: u8 = 4;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const EXT_INFO: u8 = 7;
    pub const KEXINIT: u8 = 20;
    pub const NEWKEYS: u8 = 21;
    pub const KEX_ECDH_INIT: u8 = 30;
    pub const KEX_ECDH_REPLY: u8 = 31;
    pub const USERAUTH_REQUEST: u8 = 50;
    pub const USERAUTH_FAILURE: u8 = 51;
    pub const USERAUTH_SUCCESS: u8 = 52;
    pub const USERAUTH_BANNER: u8 = 53;
    pub const USERAUTH_PK_OK: u8 = 60;
    pub const GLOBAL_REQUEST: u8 = 80;
    pub const REQUEST_SUCCESS: u8 = 81;
    pub const REQUEST_FAILURE: u8 = 82;
    pub const CHANNEL_OPEN: u8 = 90;
    pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const CHANNEL_DATA: u8 = 94;
    pub const CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const CHANNEL_EOF: u8 = 96;
    pub const CHANNEL_CLOSE: u8 = 97;
    pub const CHANNEL_REQUEST: u8 = 98;
    pub const CHANNEL_SUCCESS: u8 = 99;
    pub const CHANNEL_FAILURE: u8 = 100;
}

pub mod disconnect {
    pub const PROTOCOL_ERROR: u32 = 2;
    pub const KEY_EXCHANGE_FAILED: u32 = 3;
    pub const MAC_ERROR: u32 = 5;
    pub const SERVICE_NOT_AVAILABLE: u32 = 7;
    pub const BY_APPLICATION: u32 = 11;
    pub const TOO_MANY_CONNECTIONS: u32 = 12;
    pub const AUTH_CANCELLED_BY_USER: u32 = 13;
    pub const NO_MORE_AUTH_METHODS: u32 = 14;
}
