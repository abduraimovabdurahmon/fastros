//! gzip (RFC 1952): streaming encoder and a streaming, multi-member decoder
//! that checks every member's CRC-32 and length.

use crate::crc32::Crc32;
use crate::deflate::Deflater;
use crate::inflate::Inflater;
use crate::{Error, Read, Result, Write};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub const MAGIC: [u8; 2] = [0x1F, 0x8B];
const CM_DEFLATE: u8 = 8;
const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;
const FRESERVED: u8 = 0xE0;
/// OS byte for Unix.
pub const OS_UNIX: u8 = 3;
/// Longest NUL-terminated header string accepted.
const MAX_HEADER_STRING: usize = 64 * 1024;

/// Does `data` start like a gzip stream?
pub fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 2 && data[..2] == MAGIC
}

/// Member header fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// Original file name (FNAME).
    pub name: Option<String>,
    /// Modification time of the original (0 = unknown).
    pub mtime: u32,
    pub comment: Option<String>,
    pub os: u8,
    pub xfl: u8,
}

/// What followed the last member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trailing {
    Nothing,
    /// Only NUL bytes (tape padding) — harmless.
    Zeros,
    /// Anything else; ignored like GNU gzip does, but reported.
    Garbage,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Header,
    Body,
    Trailer,
    Done,
}

/// Streaming decoder: `read` yields the concatenated contents of all members.
pub struct GzDecoder<R: Read> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    eof: bool,
    inflater: Inflater,
    state: State,
    crc: Crc32,
    size: u32,
    first: Option<Header>,
    header_len: u64,
    members: u32,
    total_in: u64,
    total_out: u64,
    trailing: Trailing,
}

impl<R: Read> GzDecoder<R> {
    pub fn new(inner: R) -> GzDecoder<R> {
        GzDecoder {
            inner,
            buf: vec![0; 32 * 1024],
            pos: 0,
            len: 0,
            eof: false,
            inflater: Inflater::new(),
            state: State::Header,
            crc: Crc32::new(),
            size: 0,
            first: None,
            header_len: 0,
            members: 0,
            total_in: 0,
            total_out: 0,
            trailing: Trailing::Nothing,
        }
    }

    /// Parse the first member header now (it is otherwise parsed on the
    /// first `read`).
    pub fn read_header(&mut self) -> Result<&Header> {
        if self.state == State::Header && self.first.is_none() {
            self.start_member()?;
        }
        self.first.as_ref().ok_or(Error::UnexpectedEof)
    }

    /// Header of the first member, once parsed.
    pub fn header(&self) -> Option<&Header> {
        self.first.as_ref()
    }

    /// Size of the first member's header plus its 8-byte trailer (what
    /// `gzip -l` counts as overhead).
    pub fn overhead(&self) -> u64 {
        self.header_len + 8
    }

    pub fn members(&self) -> u32 {
        self.members
    }

    /// Compressed bytes taken from the source so far.
    pub fn total_in(&self) -> u64 {
        self.total_in - (self.len - self.pos) as u64
    }

    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// Valid only after `read` returned 0.
    pub fn trailing(&self) -> Trailing {
        self.trailing
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    fn fill(&mut self) -> Result<bool> {
        if self.pos < self.len {
            return Ok(true);
        }
        if self.eof {
            return Ok(false);
        }
        let n = self.inner.read(&mut self.buf)?;
        self.pos = 0;
        self.len = n;
        self.total_in += n as u64;
        if n == 0 {
            self.eof = true;
        }
        Ok(n > 0)
    }

    fn byte(&mut self) -> Result<u8> {
        if !self.fill()? {
            return Err(Error::UnexpectedEof);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Make at least `n` (≤ buffer size) bytes available if the source has them.
    fn peek(&mut self, n: usize) -> Result<&[u8]> {
        while self.len - self.pos < n && !self.eof {
            self.buf.copy_within(self.pos..self.len, 0);
            self.len -= self.pos;
            self.pos = 0;
            let got = self.inner.read(&mut self.buf[self.len..])?;
            self.total_in += got as u64;
            if got == 0 {
                self.eof = true;
            }
            self.len += got;
        }
        Ok(&self.buf[self.pos..self.len])
    }

    fn start_member(&mut self) -> Result<()> {
        let first = self.members == 0;
        let mut hcrc = Crc32::new();
        let mut count = 0u64;
        let mut hb = |s: &mut Self| -> Result<u8> {
            let b = s.byte()?;
            hcrc.update(&[b]);
            count += 1;
            Ok(b)
        };
        let id1 = hb(self)?;
        let id2 = match hb(self) {
            Ok(b) => b,
            Err(Error::UnexpectedEof) if id1 != MAGIC[0] => return Err(Error::BadMagic),
            Err(e) => return Err(e),
        };
        if [id1, id2] != MAGIC {
            return Err(Error::BadMagic);
        }
        let cm = hb(self)?;
        if cm != CM_DEFLATE {
            return Err(Error::Unsupported("unknown compression method"));
        }
        let flg = hb(self)?;
        if flg & FRESERVED != 0 {
            return Err(Error::Unsupported("reserved header flags set"));
        }
        let mut t = [0u8; 4];
        for b in t.iter_mut() {
            *b = hb(self)?;
        }
        let mtime = u32::from_le_bytes(t);
        let xfl = hb(self)?;
        let os = hb(self)?;
        if flg & FEXTRA != 0 {
            let xlen = hb(self)? as usize | (hb(self)? as usize) << 8;
            for _ in 0..xlen {
                hb(self)?;
            }
        }
        let mut cstring = |s: &mut Self| -> Result<String> {
            let mut v = Vec::new();
            loop {
                let b = hb(s)?;
                if b == 0 {
                    break;
                }
                if v.len() >= MAX_HEADER_STRING {
                    return Err(Error::Corrupt("header string too long"));
                }
                v.push(b);
            }
            Ok(String::from_utf8_lossy(&v).into_owned())
        };
        let name = if flg & FNAME != 0 { Some(cstring(self)?) } else { None };
        let comment = if flg & FCOMMENT != 0 { Some(cstring(self)?) } else { None };
        if flg & FHCRC != 0 {
            let want = hcrc.value() as u16;
            let lo = self.byte()?;
            let hi = self.byte()?;
            count += 2;
            if u16::from_le_bytes([lo, hi]) != want {
                return Err(Error::Corrupt("header checksum mismatch"));
            }
        }
        if first {
            self.first = Some(Header { name, mtime, comment, os, xfl });
            self.header_len = count;
        }
        self.inflater.reset();
        self.crc = Crc32::new();
        self.size = 0;
        self.state = State::Body;
        Ok(())
    }

    fn end_member(&mut self) -> Result<()> {
        let mut t = [0u8; 8];
        for b in t.iter_mut() {
            *b = self.byte()?;
        }
        let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
        let size = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
        if crc != self.crc.value() {
            return Err(Error::Checksum { expected: crc, actual: self.crc.value() });
        }
        if size != self.size {
            return Err(Error::Length);
        }
        self.members += 1;
        let next = self.peek(2)?;
        if next.is_empty() {
            self.state = State::Done;
        } else if next.len() >= 2 && next[..2] == MAGIC {
            self.state = State::Header;
        } else {
            // Scan what is left: NUL padding is fine, anything else is garbage.
            self.trailing = Trailing::Zeros;
            loop {
                if self.buf[self.pos..self.len].iter().any(|&b| b != 0) {
                    self.trailing = Trailing::Garbage;
                    break;
                }
                self.pos = self.len;
                if !self.fill()? {
                    break;
                }
            }
            self.state = State::Done;
        }
        Ok(())
    }
}

impl<R: Read> Read for GzDecoder<R> {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            match self.state {
                State::Header => self.start_member()?,
                State::Body => {
                    let (c, w) = self.inflater.inflate(&self.buf[self.pos..self.len], out, true)?;
                    self.pos += c;
                    self.crc.update(&out[..w]);
                    self.size = self.size.wrapping_add(w as u32);
                    self.total_out += w as u64;
                    if self.inflater.is_finished() {
                        self.state = State::Trailer;
                    }
                    if w > 0 {
                        return Ok(w);
                    }
                    if !self.inflater.is_finished() {
                        if self.pos < self.len && c == 0 {
                            return Err(Error::Corrupt("decoder made no progress"));
                        }
                        if !self.fill()? {
                            return Err(Error::UnexpectedEof);
                        }
                    }
                }
                State::Trailer => self.end_member()?,
                State::Done => return Ok(0),
            }
        }
    }
}

/// Streaming encoder. Also a [`Write`] sink, so a tar writer can sit on top.
pub struct GzEncoder<W: Write> {
    inner: W,
    d: Deflater,
    crc: Crc32,
    size: u32,
    out: Vec<u8>,
    total_in: u64,
    total_out: u64,
    header_len: u64,
}

impl<W: Write> GzEncoder<W> {
    /// Start a member; the header is written with the first output.
    pub fn new(inner: W, level: u8, header: &Header) -> GzEncoder<W> {
        let level = level.min(9);
        let mut out = Vec::with_capacity(64 * 1024);
        out.extend_from_slice(&MAGIC);
        out.push(CM_DEFLATE);
        let mut flg = 0;
        if header.name.is_some() {
            flg |= FNAME;
        }
        if header.comment.is_some() {
            flg |= FCOMMENT;
        }
        out.push(flg);
        out.extend_from_slice(&header.mtime.to_le_bytes());
        out.push(match level {
            9 => 2,
            1 => 4,
            _ => 0,
        });
        out.push(OS_UNIX);
        for s in [&header.name, &header.comment].into_iter().flatten() {
            // A NUL inside the name would end it early: drop such bytes.
            out.extend(s.bytes().filter(|&b| b != 0));
            out.push(0);
        }
        let header_len = out.len() as u64;
        GzEncoder { inner, d: Deflater::new(level), crc: Crc32::new(), size: 0, out, total_in: 0, total_out: 0, header_len }
    }

    fn drain(&mut self, force: bool) -> Result<()> {
        if !self.out.is_empty() && (force || self.out.len() >= 32 * 1024) {
            self.inner.write_all(&self.out)?;
            self.total_out += self.out.len() as u64;
            self.out.clear();
        }
        Ok(())
    }

    /// Header plus trailer bytes (for ratio reporting).
    pub fn overhead(&self) -> u64 {
        self.header_len + 8
    }

    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Write the final block and trailer; returns the sink and
    /// (uncompressed, compressed) byte counts.
    pub fn finish(mut self) -> Result<(W, u64, u64)> {
        self.d.finish(&mut self.out);
        self.out.extend_from_slice(&self.crc.value().to_le_bytes());
        self.out.extend_from_slice(&self.size.to_le_bytes());
        self.drain(true)?;
        Ok((self.inner, self.total_in, self.total_out))
    }
}

impl<W: Write> Write for GzEncoder<W> {
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        // Feed in slices so the pending output stays bounded.
        for chunk in data.chunks(64 * 1024) {
            self.crc.update(chunk);
            self.size = self.size.wrapping_add(chunk.len() as u32);
            self.total_in += chunk.len() as u64;
            self.d.write(chunk, &mut self.out);
            self.drain(false)?;
        }
        Ok(())
    }
}

/// Compress a whole buffer into one member.
pub fn compress(data: &[u8], level: u8, header: &Header) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), level, header);
    e.write_all(data).expect("Vec sink cannot fail");
    e.finish().expect("Vec sink cannot fail").0
}

/// Decompress a whole buffer (all members), producing at most `limit` bytes.
pub fn decompress(data: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut d = GzDecoder::new(data);
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = d.read(&mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > limit {
            return Err(Error::TooLarge("decompressed data exceeds the limit"));
        }
        out.extend_from_slice(&buf[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `printf 'hello\n' | gzip -n -9` from GNU gzip 1.12.
    const HELLO_GZ: [u8; 26] = [
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0xe7, 0x02, 0x00, 0x20, 0x30, 0x3a, 0x36, 0x06, 0x00,
        0x00, 0x00,
    ];

    #[test]
    fn decodes_gnu_gzip_output() {
        assert_eq!(decompress(&HELLO_GZ, 100).unwrap(), b"hello\n");
        let mut d = GzDecoder::new(&HELLO_GZ[..]);
        let h = d.read_header().unwrap().clone();
        assert_eq!(h.name, None);
        assert_eq!(h.os, 3);
        assert_eq!(h.xfl, 2);
        assert_eq!(d.overhead(), 18);
    }

    #[test]
    fn roundtrip_with_name_and_multi_member() {
        let h = Header { name: Some("notes.txt".into()), mtime: 1_789_000_000, ..Default::default() };
        let a = compress(b"first member\n", 6, &h);
        let b = compress(b"second\n", 1, &Header::default());
        let mut both = a.clone();
        both.extend_from_slice(&b);
        assert_eq!(decompress(&both, 1000).unwrap(), b"first member\nsecond\n");
        let mut d = GzDecoder::new(&both[..]);
        assert_eq!(d.read_header().unwrap().name.as_deref(), Some("notes.txt"));
        assert_eq!(d.read_header().unwrap().mtime, 1_789_000_000);
        let mut sink = crate::Discard::default();
        crate::copy(&mut d, &mut sink).unwrap();
        assert_eq!(d.members(), 2);
        assert_eq!(d.trailing(), Trailing::Nothing);
        assert_eq!(d.total_in(), both.len() as u64);
    }

    #[test]
    fn detects_corruption() {
        let good = compress(b"some data that is long enough to matter", 6, &Header::default());
        let mut bad_crc = good.clone();
        let n = bad_crc.len();
        bad_crc[n - 8] ^= 1;
        assert!(matches!(decompress(&bad_crc, 1000), Err(Error::Checksum { .. })));
        let mut bad_len = good.clone();
        bad_len[n - 1] ^= 1;
        assert_eq!(decompress(&bad_len, 1000), Err(Error::Length));
        assert_eq!(decompress(b"not gzip at all", 1000), Err(Error::BadMagic));
        assert_eq!(decompress(b"", 1000), Err(Error::UnexpectedEof));
        for cut in 0..good.len() {
            assert!(decompress(&good[..cut], 1000).is_err(), "cut {cut}");
        }
    }

    #[test]
    fn trailing_data_is_classified() {
        let mut z = compress(b"x", 6, &Header::default());
        z.extend_from_slice(&[0; 100]);
        let mut d = GzDecoder::new(&z[..]);
        crate::copy(&mut d, &mut crate::Discard::default()).unwrap();
        assert_eq!(d.trailing(), Trailing::Zeros);
        let mut g = compress(b"x", 6, &Header::default());
        g.extend_from_slice(b"junk");
        let mut d = GzDecoder::new(&g[..]);
        crate::copy(&mut d, &mut crate::Discard::default()).unwrap();
        assert_eq!(d.trailing(), Trailing::Garbage);
    }

    #[test]
    fn header_crc_and_extra_fields() {
        // Build a header with FEXTRA + FCOMMENT + FHCRC by hand.
        let body = crate::deflate::compress(b"abc", 6);
        let mut v = vec![0x1f, 0x8b, 8, FEXTRA | FCOMMENT | FHCRC, 0, 0, 0, 0, 0, 3, 4, 0, b'A', b'B', 0, 0];
        v.extend_from_slice(b"comment\0");
        let hc = crate::crc32::checksum(&v) as u16;
        v.extend_from_slice(&hc.to_le_bytes());
        v.extend_from_slice(&body);
        v.extend_from_slice(&crate::crc32::checksum(b"abc").to_le_bytes());
        v.extend_from_slice(&3u32.to_le_bytes());
        assert_eq!(decompress(&v, 10).unwrap(), b"abc");
        v[16] ^= 0x20; // corrupt the comment: header CRC must catch it
        assert!(matches!(decompress(&v, 10), Err(Error::Corrupt(_))));
    }

    #[test]
    fn one_byte_reads() {
        struct Trickle<'a>(&'a [u8]);
        impl Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
                if self.0.is_empty() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }
        let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let z = compress(&data, 6, &Header { name: Some("n".into()), ..Default::default() });
        let mut d = GzDecoder::new(Trickle(&z));
        let mut out = Vec::new();
        crate::copy(&mut d, &mut out).unwrap();
        assert!(out == data);
    }
}
