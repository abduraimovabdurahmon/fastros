//! tar: POSIX ustar with pax extended headers, GNU long names
//! (`././@LongLink` 'L'/'K'), base-256 numbers, and v7 archives.
//!
//! The reader is a pull parser over any [`Read`]: `next_entry` yields
//! headers, `read_data` the member's contents. The writer emits ustar and
//! adds a pax header only when a field does not fit.

use crate::{read_exact, read_full, Error, Read, Result, Write};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

pub const BLOCK: usize = 512;
/// GNU tar's default record size (blocking factor 20).
pub const RECORD: usize = 20 * BLOCK;
/// Largest pax/long-name payload accepted (memory bound for hostile input).
const MAX_META: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    HardLink,
    Symlink,
    CharDevice,
    BlockDevice,
    Directory,
    Fifo,
    /// Anything else (GNU sparse 'S', vendor types); data is skipped.
    Other(u8),
}

impl Kind {
    fn from_flag(f: u8) -> Kind {
        match f {
            b'0' | 0 | b'7' => Kind::File,
            b'1' => Kind::HardLink,
            b'2' => Kind::Symlink,
            b'3' => Kind::CharDevice,
            b'4' => Kind::BlockDevice,
            b'5' | b'D' => Kind::Directory,
            b'6' => Kind::Fifo,
            other => Kind::Other(other),
        }
    }

    fn flag(self) -> u8 {
        match self {
            Kind::File => b'0',
            Kind::HardLink => b'1',
            Kind::Symlink => b'2',
            Kind::CharDevice => b'3',
            Kind::BlockDevice => b'4',
            Kind::Directory => b'5',
            Kind::Fifo => b'6',
            Kind::Other(f) => f,
        }
    }

    /// `ls`-style type letter as GNU `tar -tv` prints it.
    pub fn letter(self) -> char {
        match self {
            Kind::File => '-',
            Kind::HardLink => 'h',
            Kind::Symlink => 'l',
            Kind::CharDevice => 'c',
            Kind::BlockDevice => 'b',
            Kind::Directory => 'd',
            Kind::Fifo => 'p',
            Kind::Other(b'S') => '-',
            Kind::Other(b'V') => 'V',
            Kind::Other(_) => '?',
        }
    }
}

/// One archive member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    /// Symlink target or hard-link target.
    pub link: String,
    pub kind: Kind,
    /// Permission bits (0o7777).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub uname: String,
    pub gname: String,
    /// Bytes of data that follow the header.
    pub size: u64,
    pub mtime: i64,
    pub dev_major: u32,
    pub dev_minor: u32,
}

impl Entry {
    pub fn new(path: &str, kind: Kind) -> Entry {
        Entry {
            path: path.to_string(),
            link: String::new(),
            kind,
            mode: if kind == Kind::Directory { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            uname: String::new(),
            gname: String::new(),
            size: 0,
            mtime: 0,
            dev_major: 0,
            dev_minor: 0,
        }
    }
}

// ── field codecs ────────────────────────────────────────────────────────────

fn cstr(f: &[u8]) -> String {
    let end = f.iter().position(|&b| b == 0).unwrap_or(f.len());
    String::from_utf8_lossy(&f[..end]).into_owned()
}

/// Octal (space/NUL padded) or GNU base-256 unsigned field.
fn parse_num(f: &[u8]) -> Result<u64> {
    if f[0] & 0x80 != 0 {
        if f[0] == 0xFF {
            return Err(Error::Corrupt("negative number in header"));
        }
        let mut v = (f[0] & 0x7F) as u64;
        for &b in &f[1..] {
            if v >> 56 != 0 {
                return Err(Error::TooLarge("numeric header field"));
            }
            v = v << 8 | b as u64;
        }
        return Ok(v);
    }
    let mut i = 0;
    while i < f.len() && (f[i] == b' ' || f[i] == 0) {
        i += 1;
    }
    let mut v = 0u64;
    while i < f.len() && (b'0'..=b'7').contains(&f[i]) {
        v = v.checked_mul(8).and_then(|v| v.checked_add((f[i] - b'0') as u64)).ok_or(Error::TooLarge("numeric header field"))?;
        i += 1;
    }
    if f[i..].iter().any(|&b| b != b' ' && b != 0) {
        return Err(Error::Corrupt("bad numeric header field"));
    }
    Ok(v)
}

/// Signed field (mtime): octal or base-256 two's complement.
fn parse_signed(f: &[u8]) -> Result<i64> {
    if f[0] == 0xFF {
        let mut v: i128 = -1;
        for &b in f {
            v = (v << 8) | b as i128;
        }
        return i64::try_from(v).map_err(|_| Error::TooLarge("time field"));
    }
    let v = parse_num(f)?;
    i64::try_from(v).map_err(|_| Error::TooLarge("time field"))
}

fn parse_u32(f: &[u8]) -> Result<u32> {
    u32::try_from(parse_num(f)?).map_err(|_| Error::Unsupported("id or device number above 2^32"))
}

/// Write `v` as zero-padded octal filling `f` minus a trailing NUL;
/// false if it does not fit.
fn put_octal(f: &mut [u8], v: u64) -> bool {
    let digits = f.len() - 1;
    let s = format!("{v:0digits$o}");
    if s.len() > digits {
        return false;
    }
    f[..digits].copy_from_slice(s.as_bytes());
    f[digits] = 0;
    true
}

/// GNU base-256 encoding for values too large for octal.
fn put_base256(f: &mut [u8], v: u64) {
    for b in f.iter_mut() {
        *b = 0;
    }
    let n = f.len();
    let bytes = v.to_be_bytes();
    let k = bytes.len().min(n - 1);
    f[n - k..].copy_from_slice(&bytes[bytes.len() - k..]);
    f[0] |= 0x80;
}

fn put_num(f: &mut [u8], v: u64) {
    if !put_octal(f, v) {
        put_base256(f, v);
    }
}

fn put_str(f: &mut [u8], s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(f.len());
    f[..n].copy_from_slice(&b[..n]);
}

fn checksums(h: &[u8; BLOCK]) -> (u64, i64) {
    let mut u = 0u64;
    let mut s = 0i64;
    for (i, &b) in h.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        u += b as u64;
        s += b as i8 as i64;
    }
    (u, s)
}

fn verify_checksum(h: &[u8; BLOCK]) -> Result<()> {
    let stored = parse_num(&h[148..156]).map_err(|_| Error::Corrupt("header checksum field"))?;
    let (u, s) = checksums(h);
    if stored == u || stored as i64 == s {
        Ok(())
    } else {
        Err(Error::Corrupt("header checksum mismatch"))
    }
}

fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

// ── pax ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Default, Debug)]
struct Pax {
    path: Option<String>,
    linkpath: Option<String>,
    size: Option<u64>,
    uid: Option<u32>,
    gid: Option<u32>,
    uname: Option<String>,
    gname: Option<String>,
    mtime: Option<i64>,
}

impl Pax {
    fn merge(&mut self, o: Pax) {
        macro_rules! take {
            ($($f:ident),*) => { $( if o.$f.is_some() { self.$f = o.$f; } )* };
        }
        take!(path, linkpath, size, uid, gid, uname, gname, mtime);
    }
}

fn parse_decimal(s: &[u8]) -> Result<u64> {
    if s.is_empty() || s.len() > 20 || !s.iter().all(u8::is_ascii_digit) {
        return Err(Error::Corrupt("pax number"));
    }
    s.iter().try_fold(0u64, |v, &d| v.checked_mul(10).and_then(|v| v.checked_add((d - b'0') as u64))).ok_or(Error::Corrupt("pax number"))
}

/// `[-]SECONDS[.FRACTION]` → whole seconds, rounded toward −∞.
fn parse_pax_time(s: &[u8]) -> Result<i64> {
    let (neg, s) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    let (int, frac) = match s.iter().position(|&b| b == b'.') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, &b""[..]),
    };
    if !frac.iter().all(u8::is_ascii_digit) {
        return Err(Error::Corrupt("pax time"));
    }
    let v = i64::try_from(parse_decimal(int)?).map_err(|_| Error::Corrupt("pax time"))?;
    Ok(if neg { -v - (frac.iter().any(|&d| d != b'0') as i64) } else { v })
}

fn parse_pax(data: &[u8]) -> Result<Pax> {
    let mut p = Pax::default();
    let mut rest = data;
    while !rest.is_empty() {
        if rest.iter().all(|&b| b == 0) {
            break;
        }
        let sp = rest.iter().position(|&b| b == b' ').ok_or(Error::Corrupt("pax record"))?;
        let len = parse_decimal(&rest[..sp])? as usize;
        if len <= sp + 1 || len > rest.len() || rest[len - 1] != b'\n' {
            return Err(Error::Corrupt("pax record length"));
        }
        let rec = &rest[sp + 1..len - 1];
        let eq = rec.iter().position(|&b| b == b'=').ok_or(Error::Corrupt("pax record"))?;
        let (key, val) = (&rec[..eq], &rec[eq + 1..]);
        let text = || String::from_utf8_lossy(val).into_owned();
        if !val.is_empty() {
            match key {
                b"path" => p.path = Some(text()),
                b"linkpath" => p.linkpath = Some(text()),
                b"size" => p.size = Some(parse_decimal(val)?),
                b"uid" => p.uid = Some(u32::try_from(parse_decimal(val)?).map_err(|_| Error::Unsupported("uid above 2^32"))?),
                b"gid" => p.gid = Some(u32::try_from(parse_decimal(val)?).map_err(|_| Error::Unsupported("gid above 2^32"))?),
                b"uname" => p.uname = Some(text()),
                b"gname" => p.gname = Some(text()),
                b"mtime" => p.mtime = Some(parse_pax_time(val)?),
                k if k.starts_with(b"GNU.sparse") => return Err(Error::Unsupported("sparse files")),
                _ => {}
            }
        }
        rest = &rest[len..];
    }
    Ok(p)
}

fn pax_record(out: &mut Vec<u8>, key: &str, value: &str) {
    let base = key.len() + value.len() + 3;
    let mut len = base + 1;
    while len != base + len.to_string().len() {
        len = base + len.to_string().len();
    }
    out.extend_from_slice(format!("{len} {key}={value}\n").as_bytes());
}

// ── reader ──────────────────────────────────────────────────────────────────

pub struct TarReader<R: Read> {
    inner: R,
    remaining: u64,
    pad: u64,
    global: Pax,
    done: bool,
    offset: u64,
    scratch: Vec<u8>,
}

impl<R: Read> TarReader<R> {
    pub fn new(inner: R) -> TarReader<R> {
        TarReader { inner, remaining: 0, pad: 0, global: Pax::default(), done: false, offset: 0, scratch: vec![0; 8192] }
    }

    /// Bytes of the archive consumed so far.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    fn discard(&mut self, mut n: u64) -> Result<()> {
        while n > 0 {
            let k = n.min(self.scratch.len() as u64) as usize;
            let got = self.inner.read(&mut self.scratch[..k])?;
            if got == 0 {
                return Err(Error::UnexpectedEof);
            }
            n -= got as u64;
            self.offset += got as u64;
        }
        Ok(())
    }

    /// Skip what is left of the current member's data.
    pub fn skip_data(&mut self) -> Result<()> {
        let n = self.remaining + self.pad;
        self.remaining = 0;
        self.pad = 0;
        self.discard(n)
    }

    fn read_meta(&mut self, size: u64) -> Result<Vec<u8>> {
        if size > MAX_META {
            return Err(Error::TooLarge("extended header"));
        }
        let mut v = vec![0u8; size as usize];
        read_exact(&mut self.inner, &mut v)?;
        self.offset += size;
        self.discard(padding(size))?;
        Ok(v)
    }

    /// The next member, or `None` at the end of the archive.
    pub fn next_entry(&mut self) -> Result<Option<Entry>> {
        if self.done {
            return Ok(None);
        }
        self.skip_data()?;
        let mut local = Pax::default();
        let mut long_name: Option<String> = None;
        let mut long_link: Option<String> = None;
        loop {
            let mut h = [0u8; BLOCK];
            if !read_full(&mut self.inner, &mut h)? {
                self.done = true;
                return Ok(None);
            }
            self.offset += BLOCK as u64;
            if h.iter().all(|&b| b == 0) {
                // End of archive; the second zero block is optional in practice.
                let mut h2 = [0u8; BLOCK];
                match read_full(&mut self.inner, &mut h2) {
                    Ok(true) => self.offset += BLOCK as u64,
                    Ok(false) | Err(Error::UnexpectedEof) => {}
                    Err(e) => return Err(e),
                }
                self.done = true;
                return Ok(None);
            }
            verify_checksum(&h)?;
            let flag = h[156];
            let size = parse_num(&h[124..136])?;
            match flag {
                b'x' => {
                    let d = self.read_meta(size)?;
                    local.merge(parse_pax(&d)?);
                    continue;
                }
                b'g' => {
                    let d = self.read_meta(size)?;
                    let g = parse_pax(&d)?;
                    self.global.merge(g);
                    continue;
                }
                b'L' => {
                    long_name = Some(cstr(&self.read_meta(size)?));
                    continue;
                }
                b'K' => {
                    long_link = Some(cstr(&self.read_meta(size)?));
                    continue;
                }
                b'V' => {
                    self.discard(size + padding(size))?;
                    continue;
                }
                _ => {}
            }
            let ustar = &h[257..263] == b"ustar\0";
            let gnu = &h[257..265] == b"ustar  \0";
            let mut name = cstr(&h[0..100]);
            if ustar && h[345] != 0 {
                name = format!("{}/{}", cstr(&h[345..500]), name);
            }
            let mut kind = Kind::from_flag(flag);
            if kind == Kind::File && flag != b'7' && name.ends_with('/') && long_name.is_none() && local.path.is_none() {
                kind = Kind::Directory; // v7-style directory
            }
            let g = &self.global;
            let mut size_field = size;
            if let Some(s) = local.size.or(g.size) {
                size_field = s;
            }
            let e = Entry {
                path: local.path.clone().or_else(|| long_name.take()).or_else(|| g.path.clone()).unwrap_or(name),
                link: local.linkpath.clone().or_else(|| long_link.take()).or_else(|| g.linkpath.clone()).unwrap_or_else(|| cstr(&h[157..257])),
                kind,
                mode: (parse_num(&h[100..108])? & 0o7777) as u32,
                uid: match local.uid.or(g.uid) {
                    Some(u) => u,
                    None => parse_u32(&h[108..116])?,
                },
                gid: match local.gid.or(g.gid) {
                    Some(u) => u,
                    None => parse_u32(&h[116..124])?,
                },
                uname: local.uname.clone().or_else(|| g.uname.clone()).unwrap_or_else(|| if ustar || gnu { cstr(&h[265..297]) } else { String::new() }),
                gname: local.gname.clone().or_else(|| g.gname.clone()).unwrap_or_else(|| if ustar || gnu { cstr(&h[297..329]) } else { String::new() }),
                size: size_field,
                mtime: match local.mtime.or(g.mtime) {
                    Some(t) => t,
                    None => parse_signed(&h[136..148])?,
                },
                dev_major: if ustar || gnu { parse_u32(&h[329..337])? } else { 0 },
                dev_minor: if ustar || gnu { parse_u32(&h[337..345])? } else { 0 },
            };
            if e.path.is_empty() {
                return Err(Error::Corrupt("member with an empty name"));
            }
            self.remaining = size_field;
            self.pad = padding(size_field);
            return Ok(Some(e));
        }
    }

    /// Read the current member's data; `Ok(0)` at its end.
    pub fn read_data(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.remaining) as usize;
        let got = self.inner.read(&mut buf[..n])?;
        if got == 0 {
            return Err(Error::UnexpectedEof);
        }
        self.remaining -= got as u64;
        self.offset += got as u64;
        Ok(got)
    }
}

impl<R: Read> Read for TarReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.read_data(buf)
    }
}

// ── writer ──────────────────────────────────────────────────────────────────

pub struct TarWriter<W: Write> {
    inner: W,
    remaining: u64,
    pad: usize,
    written: u64,
}

/// Split a path into ustar (name, prefix) fields, if it fits.
fn split_ustar(path: &str) -> Option<(&str, &str)> {
    if path.len() <= 100 {
        return Some((path, ""));
    }
    let b = path.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c == b'/' && i > 0 && b.len() - i - 1 <= 100 && b.len() - i - 1 > 0 {
            return if i <= 155 { Some((&path[i + 1..], &path[..i])) } else { None };
        }
    }
    None
}

fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

impl<W: Write> TarWriter<W> {
    pub fn new(inner: W) -> TarWriter<W> {
        TarWriter { inner, remaining: 0, pad: 0, written: 0 }
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    fn emit(&mut self, b: &[u8]) -> Result<()> {
        self.inner.write_all(b)?;
        self.written += b.len() as u64;
        Ok(())
    }

    fn header_block(e: &Entry, path: &str, prefix: &str, flag: u8, size: u64) -> [u8; BLOCK] {
        let mut h = [0u8; BLOCK];
        put_str(&mut h[0..100], truncate_str(path, 100));
        put_num(&mut h[100..108], e.mode as u64 & 0o7777);
        put_num(&mut h[108..116], e.uid as u64);
        put_num(&mut h[116..124], e.gid as u64);
        put_num(&mut h[124..136], size);
        if e.mtime >= 0 {
            put_num(&mut h[136..148], e.mtime as u64);
        } else {
            put_octal(&mut h[136..148], 0);
        }
        h[156] = flag;
        put_str(&mut h[157..257], truncate_str(&e.link, 100));
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        put_str(&mut h[265..297], truncate_str(&e.uname, 32));
        put_str(&mut h[297..329], truncate_str(&e.gname, 32));
        if matches!(e.kind, Kind::CharDevice | Kind::BlockDevice) {
            put_num(&mut h[329..337], e.dev_major as u64);
            put_num(&mut h[337..345], e.dev_minor as u64);
        } else {
            put_octal(&mut h[329..337], 0);
            put_octal(&mut h[337..345], 0);
        }
        put_str(&mut h[345..500], truncate_str(prefix, 155));
        let (sum, _) = checksums(&h);
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        h
    }

    /// Write a member's header. For [`Kind::File`] exactly `e.size` bytes of
    /// data must follow via [`write_data`](Self::write_data), then
    /// [`finish_entry`](Self::finish_entry).
    pub fn append_header(&mut self, e: &Entry) -> Result<()> {
        if self.remaining != 0 || self.pad != 0 {
            return Err(Error::Length);
        }
        let mut path = e.path.clone();
        if e.kind == Kind::Directory && !path.ends_with('/') {
            path.push('/');
        }
        let size = if e.kind == Kind::File { e.size } else { 0 };
        let mut pax = Vec::new();
        let (name, prefix) = match split_ustar(&path) {
            Some(np) => np,
            None => {
                pax_record(&mut pax, "path", &path);
                (truncate_str(&path, 100), "")
            }
        };
        if e.link.len() > 100 {
            pax_record(&mut pax, "linkpath", &e.link);
        }
        if size > 0o777_7777_7777 {
            pax_record(&mut pax, "size", &size.to_string());
        }
        if e.uid > 0o7777777 {
            pax_record(&mut pax, "uid", &e.uid.to_string());
        }
        if e.gid > 0o7777777 {
            pax_record(&mut pax, "gid", &e.gid.to_string());
        }
        if e.mtime < 0 || e.mtime > 0o777_7777_7777 {
            pax_record(&mut pax, "mtime", &e.mtime.to_string());
        }
        if e.uname.len() > 32 {
            pax_record(&mut pax, "uname", &e.uname);
        }
        if e.gname.len() > 32 {
            pax_record(&mut pax, "gname", &e.gname);
        }
        if !pax.is_empty() {
            let base = path.trim_end_matches('/').rsplit('/').next().unwrap_or("x");
            let pname = format!("PaxHeaders/{}", truncate_str(base, 88));
            let mut pe = Entry::new(&pname, Kind::Other(b'x'));
            pe.mtime = e.mtime.max(0);
            pe.uid = e.uid;
            pe.gid = e.gid;
            let h = Self::header_block(&pe, &pname, "", b'x', pax.len() as u64);
            self.emit(&h)?;
            self.emit(&pax)?;
            let z = [0u8; BLOCK];
            self.emit(&z[..padding(pax.len() as u64) as usize])?;
        }
        let h = Self::header_block(e, name, prefix, e.kind.flag(), size);
        self.emit(&h)?;
        self.remaining = size;
        self.pad = padding(size) as usize;
        Ok(())
    }

    pub fn write_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() as u64 > self.remaining {
            return Err(Error::Length);
        }
        self.emit(data)?;
        self.remaining -= data.len() as u64;
        Ok(())
    }

    /// Pad the member to a block boundary; all its data must be written.
    pub fn finish_entry(&mut self) -> Result<()> {
        if self.remaining != 0 {
            return Err(Error::Length);
        }
        let z = [0u8; BLOCK];
        let pad = self.pad;
        self.emit(&z[..pad])?;
        self.pad = 0;
        Ok(())
    }

    /// Header, data and padding in one call.
    pub fn append(&mut self, e: &Entry, data: &[u8]) -> Result<()> {
        self.append_header(e)?;
        self.write_data(data)?;
        self.finish_entry()
    }

    /// End-of-archive marker (two zero blocks), padded to a full record.
    pub fn finish(mut self) -> Result<W> {
        if self.remaining != 0 || self.pad != 0 {
            return Err(Error::Length);
        }
        let z = [0u8; BLOCK];
        self.emit(&z)?;
        self.emit(&z)?;
        while self.written % RECORD as u64 != 0 {
            self.emit(&z)?;
        }
        Ok(self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(data: &[u8]) -> Result<Vec<(Entry, Vec<u8>)>> {
        let mut r = TarReader::new(data);
        let mut v = Vec::new();
        while let Some(e) = r.next_entry()? {
            let mut d = Vec::new();
            crate::copy(&mut r, &mut d)?;
            v.push((e, d));
        }
        Ok(v)
    }

    #[test]
    fn roundtrip_all_kinds() {
        let mut w = TarWriter::new(Vec::new());
        let mut f = Entry::new("dir/file.txt", Kind::File);
        f.size = 11;
        f.mode = 0o640;
        f.uid = 1000;
        f.gid = 100;
        f.uname = "user".into();
        f.gname = "users".into();
        f.mtime = 1_789_000_000;
        w.append(&Entry::new("dir", Kind::Directory), b"").unwrap();
        w.append(&f, b"hello world").unwrap();
        let mut l = Entry::new("dir/link", Kind::Symlink);
        l.link = "file.txt".into();
        w.append(&l, b"").unwrap();
        let mut hl = Entry::new("dir/hard", Kind::HardLink);
        hl.link = "dir/file.txt".into();
        w.append(&hl, b"").unwrap();
        let mut c = Entry::new("dev/null", Kind::CharDevice);
        c.dev_major = 1;
        c.dev_minor = 3;
        w.append(&c, b"").unwrap();
        w.append(&Entry::new("fifo", Kind::Fifo), b"").unwrap();
        let out = w.finish().unwrap();
        assert_eq!(out.len() % RECORD, 0);
        let v = read_all(&out).unwrap();
        assert_eq!(v.len(), 6);
        assert_eq!(v[0].0.path, "dir/");
        assert_eq!(v[0].0.kind, Kind::Directory);
        assert_eq!(v[1].0, f);
        assert_eq!(v[1].1, b"hello world");
        assert_eq!(v[2].0.link, "file.txt");
        assert_eq!(v[3].0.kind, Kind::HardLink);
        assert_eq!((v[4].0.dev_major, v[4].0.dev_minor), (1, 3));
        assert_eq!(v[5].0.kind, Kind::Fifo);
    }

    #[test]
    fn long_names_use_prefix_then_pax() {
        let mid = format!("{}/{}", "a".repeat(120), "b".repeat(90)); // fits prefix+name
        let long = format!("{}/{}", "c".repeat(200), "d".repeat(150)); // needs pax
        let link = "t".repeat(300);
        let mut w = TarWriter::new(Vec::new());
        let mut e = Entry::new(&mid, Kind::File);
        e.size = 3;
        w.append(&e, b"abc").unwrap();
        let mut e2 = Entry::new(&long, Kind::File);
        e2.size = 1;
        w.append(&e2, b"z").unwrap();
        let mut s = Entry::new("s", Kind::Symlink);
        s.link = link.clone();
        w.append(&s, b"").unwrap();
        let mut big = Entry::new("big-ids", Kind::File);
        big.uid = 4_000_000_000;
        big.mtime = -86_400;
        w.append(&big, b"").unwrap();
        let out = w.finish().unwrap();
        let v = read_all(&out).unwrap();
        assert_eq!(v[0].0.path, mid);
        assert_eq!(v[0].1, b"abc");
        assert_eq!(v[1].0.path, long);
        assert_eq!(v[1].1, b"z");
        assert_eq!(v[2].0.link, link);
        assert_eq!(v[3].0.uid, 4_000_000_000);
        assert_eq!(v[3].0.mtime, -86_400);
    }

    #[test]
    fn reads_gnu_longlink_and_base256() {
        // Hand-built GNU archive: ././@LongLink 'L' record then a file.
        let name = "x".repeat(150);
        let mut out = Vec::new();
        let mut h = [0u8; BLOCK];
        put_str(&mut h[0..100], "././@LongLink");
        put_octal(&mut h[100..108], 0o644);
        put_octal(&mut h[108..116], 0);
        put_octal(&mut h[116..124], 0);
        put_octal(&mut h[124..136], name.len() as u64 + 1);
        put_octal(&mut h[136..148], 0);
        h[156] = b'L';
        h[257..265].copy_from_slice(b"ustar  \0");
        let s = format!("{:06o}\0 ", checksums(&h).0);
        h[148..156].copy_from_slice(s.as_bytes());
        out.extend_from_slice(&h);
        let mut body = name.clone().into_bytes();
        body.push(0);
        body.resize(512, 0);
        out.extend_from_slice(&body);
        let mut h = [0u8; BLOCK];
        put_str(&mut h[0..100], &name[..100]);
        put_octal(&mut h[100..108], 0o600);
        put_base256(&mut h[108..116], 70_000);
        put_octal(&mut h[116..124], 0);
        put_octal(&mut h[124..136], 2);
        put_octal(&mut h[136..148], 5);
        h[156] = b'0';
        h[257..265].copy_from_slice(b"ustar  \0");
        let s = format!("{:06o}\0 ", checksums(&h).0);
        h[148..156].copy_from_slice(s.as_bytes());
        out.extend_from_slice(&h);
        let mut d = b"ok".to_vec();
        d.resize(512, 0);
        out.extend_from_slice(&d);
        out.extend_from_slice(&[0u8; 1024]);
        let v = read_all(&out).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0.path, name);
        assert_eq!(v[0].0.uid, 70_000);
        assert_eq!(v[0].1, b"ok");
    }

    #[test]
    fn corruption_is_reported_never_panics() {
        let mut w = TarWriter::new(Vec::new());
        let mut e = Entry::new("f", Kind::File);
        e.size = 1000;
        w.append(&e, &[7u8; 1000]).unwrap();
        let good = w.finish().unwrap();
        let mut bad = good.clone();
        bad[10] ^= 0x40;
        assert_eq!(read_all(&bad).unwrap_err(), Error::Corrupt("header checksum mismatch"));
        for cut in (1..1536).step_by(13) {
            let r = read_all(&good[..cut]);
            assert!(r.is_err(), "cut {cut}");
        }
        // Clean end without zero blocks is accepted.
        assert_eq!(read_all(&good[..1536]).unwrap().len(), 1);
        // Pseudo-random headers.
        let mut x = 7u64;
        for _ in 0..500 {
            let mut blk = vec![0u8; 2048];
            for b in blk.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = x as u8;
            }
            // Give some of them a valid checksum so parsing goes deeper.
            let mut h = [0u8; BLOCK];
            h.copy_from_slice(&blk[..BLOCK]);
            let s = format!("{:06o}\0 ", checksums(&h).0);
            blk[148..156].copy_from_slice(s.as_bytes());
            let _ = read_all(&blk);
        }
    }

    #[test]
    fn pax_parsing_edge_cases() {
        let mut rec = Vec::new();
        pax_record(&mut rec, "path", "p");
        assert_eq!(rec, b"9 path=p\n");
        let mut rec = Vec::new();
        pax_record(&mut rec, "comment", &"c".repeat(90));
        assert!(rec.starts_with(b"103 comment="));
        assert_eq!(rec.len(), 103);
        // Lengths straddling the 2→3 digit boundary stay self-consistent.
        for n in 80..100 {
            let mut rec = Vec::new();
            pax_record(&mut rec, "comment", &"c".repeat(n));
            let sp = rec.iter().position(|&b| b == b' ').unwrap();
            assert_eq!(parse_decimal(&rec[..sp]).unwrap() as usize, rec.len());
        }
        assert!(parse_pax(b"5 a=b\n").is_err());
        assert!(parse_pax(b"99 path=x\n").is_err());
        assert!(parse_pax(b"x path=x\n").is_err());
        assert_eq!(parse_pax(b"15 mtime=-1.25\n").unwrap().mtime, Some(-2));
        assert_eq!(parse_pax(b"13 mtime=7.9\n").unwrap().mtime, Some(7));
        assert!(matches!(parse_pax(b"22 GNU.sparse.size=10\n"), Err(Error::Unsupported(_))));
    }

    #[test]
    fn meta_size_is_bounded() {
        let mut h = [0u8; BLOCK];
        put_str(&mut h[0..100], "pax");
        put_octal(&mut h[124..136], 1 << 30);
        h[156] = b'x';
        h[257..263].copy_from_slice(b"ustar\0");
        let s = format!("{:06o}\0 ", checksums(&h).0);
        h[148..156].copy_from_slice(s.as_bytes());
        assert_eq!(read_all(&h).unwrap_err(), Error::TooLarge("extended header"));
    }
}
