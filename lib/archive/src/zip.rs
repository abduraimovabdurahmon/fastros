//! zip (PKWARE APPNOTE 6.3): reader over [`ReadAt`] with the zip64 read
//! path, a streaming per-entry decoder that checks CRC-32 and never yields
//! more than the declared size, and a writer for stored/deflated entries
//! with Info-ZIP's Unix extra fields (`UT` timestamps, `ux` owner).

use crate::crc32::{self, Crc32};
use crate::deflate::{self, Deflater};
use crate::inflate::Inflater;
use crate::time::{dos_to_unix, unix_to_dos};
use crate::{read_exact_at, Error, Read, ReadAt, Result, Write};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

const LOCAL_SIG: u32 = 0x0403_4B50;
const CENTRAL_SIG: u32 = 0x0201_4B50;
const EOCD_SIG: u32 = 0x0605_4B50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4B50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4B50;
const DESCRIPTOR_SIG: u32 = 0x0807_4B50;
const EOCD_LEN: usize = 22;
const CENTRAL_LEN: usize = 46;
const LOCAL_LEN: usize = 30;
/// Central directories larger than this are refused (memory bound).
const MAX_CENTRAL: u64 = 256 << 20;

const FLAG_ENCRYPTED: u16 = 1 << 0;
const FLAG_DESCRIPTOR: u16 = 1 << 3;
const FLAG_UTF8: u16 = 1 << 11;
/// "Version made by": Unix, spec 3.0 (what Info-ZIP zip 3.0 writes).
const MADE_BY_UNIX: u16 = 3 << 8 | 30;
const EXTRA_ZIP64: u16 = 0x0001;
const EXTRA_UT: u16 = 0x5455;
const EXTRA_UX: u16 = 0x7875;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Stored,
    Deflated,
    Other(u16),
}

impl Method {
    fn from_u16(v: u16) -> Method {
        match v {
            0 => Method::Stored,
            8 => Method::Deflated,
            o => Method::Other(o),
        }
    }
    fn code(self) -> u16 {
        match self {
            Method::Stored => 0,
            Method::Deflated => 8,
            Method::Other(o) => o,
        }
    }
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn u64le(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// A central-directory record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZipEntry {
    pub name: String,
    pub method: Method,
    pub flags: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub size: u64,
    /// Offset of the local header (already corrected for prepended data).
    pub header_offset: u64,
    /// Unix time: the `UT` extra field if present, else the DOS timestamp.
    pub mtime: i64,
    pub made_by: u16,
    pub external_attr: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl ZipEntry {
    /// Unix `st_mode` if the entry was made on a Unix-like host.
    pub fn unix_mode(&self) -> Option<u32> {
        let host = self.made_by >> 8;
        let m = self.external_attr >> 16;
        ((host == 3 || host == 19) && m != 0).then_some(m)
    }

    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/') || self.unix_mode().is_some_and(|m| m & S_IFMT == S_IFDIR) || (self.unix_mode().is_none() && self.external_attr & 0x10 != 0)
    }

    pub fn is_symlink(&self) -> bool {
        self.unix_mode().is_some_and(|m| m & S_IFMT == S_IFLNK)
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }
}

/// Parse the extra-field area, filling the zip64 sizes and Unix metadata.
fn parse_extra(extra: &[u8], e: &mut ZipEntry, need64: [bool; 3]) -> Result<()> {
    let mut p = 0;
    while p + 4 <= extra.len() {
        let id = u16le(extra, p);
        let len = u16le(extra, p + 2) as usize;
        let d = extra.get(p + 4..p + 4 + len).ok_or(Error::Corrupt("extra field overruns"))?;
        match id {
            EXTRA_ZIP64 => {
                let mut q = 0;
                let mut take = |want: bool| -> Result<Option<u64>> {
                    if !want {
                        return Ok(None);
                    }
                    let v = d.get(q..q + 8).ok_or(Error::Corrupt("short zip64 extra field"))?;
                    q += 8;
                    Ok(Some(u64le(v, 0)))
                };
                if let Some(v) = take(need64[0])? {
                    e.size = v;
                }
                if let Some(v) = take(need64[1])? {
                    e.compressed_size = v;
                }
                if let Some(v) = take(need64[2])? {
                    e.header_offset = v;
                }
            }
            EXTRA_UT if !d.is_empty() && d[0] & 1 != 0 && d.len() >= 5 => {
                e.mtime = u32le(d, 1) as i64;
            }
            EXTRA_UX if d.len() >= 3 && d[0] == 1 => {
                let us = d[1] as usize;
                if let Some(u) = d.get(2..2 + us) {
                    if us <= 4 {
                        e.uid = Some(u.iter().rev().fold(0u32, |a, &b| a << 8 | b as u32));
                    }
                    let gs_at = 2 + us;
                    if let Some(&gs) = d.get(gs_at) {
                        let gs = gs as usize;
                        if let Some(g) = d.get(gs_at + 1..gs_at + 1 + gs) {
                            if gs <= 4 {
                                e.gid = Some(g.iter().rev().fold(0u32, |a, &b| a << 8 | b as u32));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        p += 4 + len;
    }
    Ok(())
}

pub struct ZipArchive<R: ReadAt> {
    src: R,
    entries: Vec<ZipEntry>,
    comment: Vec<u8>,
    /// Bytes found before the archive proper (self-extractor stubs).
    prepended: u64,
}

impl<R: ReadAt> ZipArchive<R> {
    pub fn open(src: R) -> Result<ZipArchive<R>> {
        let size = src.size();
        if size < EOCD_LEN as u64 {
            return Err(Error::BadMagic);
        }
        let tail_len = size.min((EOCD_LEN + 0xFFFF) as u64) as usize;
        let tail_start = size - tail_len as u64;
        let mut tail = vec![0u8; tail_len];
        read_exact_at(&src, tail_start, &mut tail)?;
        let mut found = None;
        for i in (0..=tail_len - EOCD_LEN).rev() {
            if u32le(&tail, i) == EOCD_SIG && i + EOCD_LEN + u16le(&tail, i + 20) as usize <= tail_len {
                found = Some(i);
                break;
            }
        }
        let i = found.ok_or(Error::BadMagic)?;
        let eocd_pos = tail_start + i as u64;
        let e = &tail[i..];
        if u16le(e, 4) != 0 || u16le(e, 6) != 0 {
            return Err(Error::Unsupported("multi-disk archives"));
        }
        let mut count = u16le(e, 10) as u64;
        let mut cd_size = u32le(e, 12) as u64;
        let mut cd_off = u32le(e, 16) as u64;
        let comment = e[EOCD_LEN..EOCD_LEN + u16le(e, 20) as usize].to_vec();
        let mut cd_end = eocd_pos;
        if (count == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_off == 0xFFFF_FFFF) && eocd_pos >= 20 {
            let mut loc = [0u8; 20];
            read_exact_at(&src, eocd_pos - 20, &mut loc)?;
            if u32le(&loc, 0) == ZIP64_LOCATOR_SIG {
                let z = u64le(&loc, 8);
                let mut r = [0u8; 56];
                read_exact_at(&src, z, &mut r)?;
                if u32le(&r, 0) != ZIP64_EOCD_SIG {
                    return Err(Error::Corrupt("zip64 end record missing"));
                }
                count = u64le(&r, 32);
                cd_size = u64le(&r, 40);
                cd_off = u64le(&r, 48);
                cd_end = z;
            }
        }
        let cd_span = cd_off.checked_add(cd_size).ok_or(Error::Corrupt("central directory out of range"))?;
        let prepended = cd_end.checked_sub(cd_span).ok_or(Error::Corrupt("central directory out of range"))?;
        if cd_size > MAX_CENTRAL {
            return Err(Error::TooLarge("central directory"));
        }
        if count > cd_size / CENTRAL_LEN as u64 {
            return Err(Error::Corrupt("entry count exceeds central directory"));
        }
        let mut cd = vec![0u8; cd_size as usize];
        read_exact_at(&src, cd_off + prepended, &mut cd)?;
        let mut entries = Vec::with_capacity(count as usize);
        let mut p = 0usize;
        for _ in 0..count {
            let h = cd.get(p..p + CENTRAL_LEN).ok_or(Error::Corrupt("truncated central directory"))?;
            if u32le(h, 0) != CENTRAL_SIG {
                return Err(Error::Corrupt("bad central directory signature"));
            }
            let (nlen, xlen, clen) = (u16le(h, 28) as usize, u16le(h, 30) as usize, u16le(h, 32) as usize);
            let rec_end = p + CENTRAL_LEN + nlen + xlen + clen;
            if rec_end > cd.len() {
                return Err(Error::Corrupt("truncated central directory"));
            }
            let name_b = &cd[p + CENTRAL_LEN..p + CENTRAL_LEN + nlen];
            let extra = &cd[p + CENTRAL_LEN + nlen..p + CENTRAL_LEN + nlen + xlen];
            let (csize, usize_, off) = (u32le(h, 20), u32le(h, 24), u32le(h, 42));
            let mut ent = ZipEntry {
                name: String::from_utf8_lossy(name_b).into_owned(),
                method: Method::from_u16(u16le(h, 10)),
                flags: u16le(h, 8),
                crc32: u32le(h, 16),
                compressed_size: csize as u64,
                size: usize_ as u64,
                header_offset: off as u64,
                mtime: dos_to_unix(u16le(h, 14), u16le(h, 12)),
                made_by: u16le(h, 4),
                external_attr: u32le(h, 38),
                uid: None,
                gid: None,
            };
            parse_extra(extra, &mut ent, [usize_ == 0xFFFF_FFFF, csize == 0xFFFF_FFFF, off == 0xFFFF_FFFF])?;
            ent.header_offset = ent.header_offset.checked_add(prepended).ok_or(Error::Corrupt("entry offset"))?;
            entries.push(ent);
            p = rec_end;
        }
        Ok(ZipArchive { src, entries, comment, prepended })
    }

    pub fn entries(&self) -> &[ZipEntry] {
        self.entries.as_slice()
    }

    pub fn comment(&self) -> &[u8] {
        &self.comment
    }

    /// Bytes before the archive (Info-ZIP warns about these).
    pub fn prepended(&self) -> u64 {
        self.prepended
    }

    pub fn source(&self) -> &R {
        &self.src
    }

    /// (offset, length) of entry `i`'s compressed data.
    pub fn data_range(&self, i: usize) -> Result<(u64, u64)> {
        let e = &self.entries[i];
        let mut h = [0u8; LOCAL_LEN];
        read_exact_at(&self.src, e.header_offset, &mut h)?;
        if u32le(&h, 0) != LOCAL_SIG {
            return Err(Error::Corrupt("bad local header signature"));
        }
        let start = e.header_offset + LOCAL_LEN as u64 + u16le(&h, 26) as u64 + u16le(&h, 28) as u64;
        let end = start.checked_add(e.compressed_size).ok_or(Error::Corrupt("entry size"))?;
        if end > self.src.size() {
            return Err(Error::Corrupt("entry data extends past the end of the archive"));
        }
        Ok((start, e.compressed_size))
    }

    /// Streaming reader for entry `i`'s contents.
    pub fn reader(&self, i: usize) -> Result<EntryReader<'_, R>> {
        let e = &self.entries[i];
        if e.is_encrypted() {
            return Err(Error::Unsupported("encrypted entries"));
        }
        let inflater = match e.method {
            Method::Stored => {
                if e.compressed_size != e.size {
                    return Err(Error::Corrupt("stored entry with differing sizes"));
                }
                None
            }
            Method::Deflated => Some(Box::new(Inflater::new())),
            Method::Other(_) => return Err(Error::Unsupported("compression method")),
        };
        let (start, len) = self.data_range(i)?;
        Ok(EntryReader {
            src: &self.src,
            pos: start,
            end: start + len,
            inflater,
            inbuf: vec![0; if e.method == Method::Deflated { 32 * 1024 } else { 0 }],
            in_pos: 0,
            in_len: 0,
            crc: Crc32::new(),
            produced: 0,
            expected: e.size,
            expected_crc: e.crc32,
            verified: false,
        })
    }
}

pub struct EntryReader<'a, R: ReadAt> {
    src: &'a R,
    pos: u64,
    end: u64,
    inflater: Option<Box<Inflater>>,
    inbuf: Vec<u8>,
    in_pos: usize,
    in_len: usize,
    crc: Crc32,
    produced: u64,
    expected: u64,
    expected_crc: u32,
    verified: bool,
}

impl<R: ReadAt> EntryReader<'_, R> {
    fn verify(&mut self) -> Result<()> {
        if !self.verified {
            if self.produced != self.expected {
                return Err(Error::Length);
            }
            if self.crc.value() != self.expected_crc {
                return Err(Error::Checksum { expected: self.expected_crc, actual: self.crc.value() });
            }
            self.verified = true;
        }
        Ok(())
    }

    fn account(&mut self, out: &[u8]) -> Result<()> {
        self.produced += out.len() as u64;
        if self.produced > self.expected {
            return Err(Error::Length);
        }
        self.crc.update(out);
        Ok(())
    }
}

impl<R: ReadAt> Read for EntryReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.inflater.is_none() {
            let n = (buf.len() as u64).min(self.end - self.pos) as usize;
            if n == 0 {
                self.verify()?;
                return Ok(0);
            }
            let got = self.src.read_at(self.pos, &mut buf[..n])?;
            if got == 0 {
                return Err(Error::UnexpectedEof);
            }
            self.pos += got as u64;
            self.account(&buf[..got])?;
            return Ok(got);
        }
        loop {
            if self.inflater.as_ref().is_some_and(|i| i.is_finished()) {
                self.verify()?;
                return Ok(0);
            }
            if self.in_pos == self.in_len && self.pos < self.end {
                let k = (self.inbuf.len() as u64).min(self.end - self.pos) as usize;
                let got = self.src.read_at(self.pos, &mut self.inbuf[..k])?;
                if got == 0 {
                    return Err(Error::UnexpectedEof);
                }
                self.pos += got as u64;
                self.in_pos = 0;
                self.in_len = got;
            }
            let more = self.pos < self.end;
            let inf = self.inflater.as_mut().expect("deflated entry has an inflater");
            let (c, w) = inf.inflate(&self.inbuf[self.in_pos..self.in_len], buf, more)?;
            let finished = inf.is_finished();
            self.in_pos += c;
            if w > 0 {
                self.account(&buf[..w])?;
                return Ok(w);
            }
            if c == 0 && !finished && (self.in_pos < self.in_len || !more) {
                return Err(Error::Corrupt("invalid compressed data"));
            }
        }
    }
}

// ── writer ──────────────────────────────────────────────────────────────────

/// Metadata of an entry to add.
#[derive(Clone, Debug)]
pub struct FileMeta {
    pub name: String,
    /// Full `st_mode` (type and permission bits).
    pub mode: u32,
    pub mtime: i64,
    pub uid: u32,
    pub gid: u32,
}

/// What was written for an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Added {
    pub method: Method,
    pub size: u64,
    pub compressed: u64,
    pub crc32: u32,
}

struct Central {
    name: Vec<u8>,
    method: Method,
    flags: u16,
    crc: u32,
    csize: u32,
    usize: u32,
    offset: u32,
    date: u16,
    time: u16,
    mtime: u32,
    uid: u32,
    gid: u32,
    ext_attr: u32,
    needed: u16,
}

struct Stream {
    c: Central,
    d: Deflater,
    crc: Crc32,
    size: u64,
    csize: u64,
    out: Vec<u8>,
}

pub struct ZipWriter<W: Write> {
    w: W,
    offset: u64,
    central: Vec<Central>,
    stream: Option<Box<Stream>>,
}

fn fits32(v: u64) -> Result<u32> {
    if v >= 0xFFFF_FFFF {
        return Err(Error::TooLarge("entry or archive above 4 GiB (zip64 output is not supported)"));
    }
    Ok(v as u32)
}

fn local_extra(c: &Central) -> Vec<u8> {
    let mut x = Vec::with_capacity(28);
    x.extend_from_slice(&EXTRA_UT.to_le_bytes());
    x.extend_from_slice(&9u16.to_le_bytes());
    x.push(3);
    x.extend_from_slice(&c.mtime.to_le_bytes());
    x.extend_from_slice(&c.mtime.to_le_bytes());
    x.extend_from_slice(&EXTRA_UX.to_le_bytes());
    x.extend_from_slice(&11u16.to_le_bytes());
    x.extend_from_slice(&[1, 4]);
    x.extend_from_slice(&c.uid.to_le_bytes());
    x.push(4);
    x.extend_from_slice(&c.gid.to_le_bytes());
    x
}

fn central_extra(c: &Central) -> Vec<u8> {
    let mut x = Vec::with_capacity(24);
    x.extend_from_slice(&EXTRA_UT.to_le_bytes());
    x.extend_from_slice(&5u16.to_le_bytes());
    x.push(3);
    x.extend_from_slice(&c.mtime.to_le_bytes());
    x.extend_from_slice(&EXTRA_UX.to_le_bytes());
    x.extend_from_slice(&11u16.to_le_bytes());
    x.extend_from_slice(&[1, 4]);
    x.extend_from_slice(&c.uid.to_le_bytes());
    x.push(4);
    x.extend_from_slice(&c.gid.to_le_bytes());
    x
}

impl<W: Write> ZipWriter<W> {
    pub fn new(w: W) -> ZipWriter<W> {
        ZipWriter { w, offset: 0, central: Vec::new(), stream: None }
    }

    fn emit(&mut self, b: &[u8]) -> Result<()> {
        self.w.write_all(b)?;
        self.offset += b.len() as u64;
        Ok(())
    }

    fn central_for(&self, meta: &FileMeta, method: Method, flags: u16) -> Result<Central> {
        if self.central.len() >= 0xFFFF {
            return Err(Error::TooLarge("more than 65534 entries (zip64 output is not supported)"));
        }
        if meta.name.len() > 0xFFFF {
            return Err(Error::TooLarge("entry name"));
        }
        let (date, time) = unix_to_dos(meta.mtime);
        let dir = meta.mode & S_IFMT == S_IFDIR;
        let flags = flags | if meta.name.is_ascii() { 0 } else { FLAG_UTF8 };
        Ok(Central {
            name: meta.name.as_bytes().to_vec(),
            method,
            flags,
            crc: 0,
            csize: 0,
            usize: 0,
            offset: fits32(self.offset)?,
            date,
            time,
            mtime: meta.mtime.clamp(0, u32::MAX as i64) as u32,
            uid: meta.uid,
            gid: meta.gid,
            ext_attr: (meta.mode << 16) | if dir { 0x10 } else { 0 },
            needed: if method == Method::Deflated || dir { 20 } else { 10 },
        })
    }

    fn local_header(&mut self, c: &Central) -> Result<()> {
        let extra = local_extra(c);
        let mut h = Vec::with_capacity(LOCAL_LEN + c.name.len() + extra.len());
        h.extend_from_slice(&LOCAL_SIG.to_le_bytes());
        h.extend_from_slice(&c.needed.to_le_bytes());
        h.extend_from_slice(&c.flags.to_le_bytes());
        h.extend_from_slice(&c.method.code().to_le_bytes());
        h.extend_from_slice(&c.time.to_le_bytes());
        h.extend_from_slice(&c.date.to_le_bytes());
        h.extend_from_slice(&c.crc.to_le_bytes());
        h.extend_from_slice(&c.csize.to_le_bytes());
        h.extend_from_slice(&c.usize.to_le_bytes());
        h.extend_from_slice(&(c.name.len() as u16).to_le_bytes());
        h.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        h.extend_from_slice(&c.name);
        h.extend_from_slice(&extra);
        self.emit(&h)
    }

    fn check_idle(&self) -> Result<()> {
        if self.stream.is_some() {
            return Err(Error::Length);
        }
        Ok(())
    }

    /// Add a regular file from memory. Deflates at `level` (0 = store) and
    /// falls back to storing when deflate does not shrink the data.
    pub fn add_file(&mut self, meta: &FileMeta, data: &[u8], level: u8) -> Result<Added> {
        self.check_idle()?;
        let size = fits32(data.len() as u64)?;
        let packed = if level > 0 && !data.is_empty() { deflate::compress(data, level) } else { Vec::new() };
        let deflated = level > 0 && !data.is_empty() && packed.len() < data.len();
        let method = if deflated { Method::Deflated } else { Method::Stored };
        let body: &[u8] = if deflated { &packed } else { data };
        let mut c = self.central_for(meta, method, level_flags(level, method))?;
        c.crc = crc32::checksum(data);
        c.usize = size;
        c.csize = fits32(body.len() as u64)?;
        self.local_header(&c)?;
        self.emit(body)?;
        let a = Added { method, size: data.len() as u64, compressed: body.len() as u64, crc32: c.crc };
        self.central.push(c);
        Ok(a)
    }

    /// Add a directory entry (the name gets a trailing `/`).
    pub fn add_directory(&mut self, meta: &FileMeta) -> Result<()> {
        let mut m = meta.clone();
        if !m.name.ends_with('/') {
            m.name.push('/');
        }
        m.mode = (m.mode & !S_IFMT) | S_IFDIR;
        self.add_file(&m, &[], 0).map(|_| ())
    }

    /// Add a symbolic link (stored; the data is the target, as Info-ZIP does).
    pub fn add_symlink(&mut self, meta: &FileMeta, target: &str) -> Result<()> {
        let mut m = meta.clone();
        m.mode = (m.mode & !S_IFMT) | S_IFLNK;
        self.add_file(&m, target.as_bytes(), 0).map(|_| ())
    }

    /// Begin a streamed (deflated, data-descriptor) entry of unknown size.
    pub fn start_file(&mut self, meta: &FileMeta, level: u8) -> Result<()> {
        self.check_idle()?;
        let c = self.central_for(meta, Method::Deflated, FLAG_DESCRIPTOR | level_flags(level, Method::Deflated))?;
        self.local_header(&c)?;
        self.stream = Some(Box::new(Stream { c, d: Deflater::new(level.max(1)), crc: Crc32::new(), size: 0, csize: 0, out: Vec::new() }));
        Ok(())
    }

    pub fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        let mut s = self.stream.take().ok_or(Error::Length)?;
        s.crc.update(data);
        s.size += data.len() as u64;
        s.d.write(data, &mut s.out);
        let r = if s.out.len() >= 32 * 1024 {
            s.csize += s.out.len() as u64;
            let out = core::mem::take(&mut s.out);
            self.emit(&out)
        } else {
            Ok(())
        };
        self.stream = Some(s);
        r
    }

    pub fn finish_file(&mut self) -> Result<Added> {
        let mut s = self.stream.take().ok_or(Error::Length)?;
        s.d.finish(&mut s.out);
        s.csize += s.out.len() as u64;
        let out = core::mem::take(&mut s.out);
        self.emit(&out)?;
        s.c.crc = s.crc.value();
        s.c.usize = fits32(s.size)?;
        s.c.csize = fits32(s.csize)?;
        let mut dd = Vec::with_capacity(16);
        dd.extend_from_slice(&DESCRIPTOR_SIG.to_le_bytes());
        dd.extend_from_slice(&s.c.crc.to_le_bytes());
        dd.extend_from_slice(&s.c.csize.to_le_bytes());
        dd.extend_from_slice(&s.c.usize.to_le_bytes());
        self.emit(&dd)?;
        let a = Added { method: Method::Deflated, size: s.size, compressed: s.csize, crc32: s.c.crc };
        self.central.push(s.c);
        Ok(a)
    }

    /// Copy entry `i` of another archive without recompressing it.
    pub fn copy_entry<R: ReadAt>(&mut self, a: &ZipArchive<R>, i: usize) -> Result<()> {
        self.check_idle()?;
        let e = &a.entries()[i];
        let (start, len) = a.data_range(i)?;
        let mode = e.unix_mode().unwrap_or(if e.is_dir() { S_IFDIR | 0o755 } else { S_IFREG | 0o644 });
        let meta = FileMeta { name: e.name.clone(), mode, mtime: e.mtime, uid: e.uid.unwrap_or(0), gid: e.gid.unwrap_or(0) };
        let mut c = self.central_for(&meta, e.method, e.flags & !FLAG_DESCRIPTOR & !FLAG_UTF8)?;
        c.ext_attr = if e.unix_mode().is_some() { e.external_attr } else { c.ext_attr };
        c.crc = e.crc32;
        c.csize = fits32(len)?;
        c.usize = fits32(e.size)?;
        self.local_header(&c)?;
        let mut buf = vec![0u8; 32 * 1024];
        let mut off = start;
        while off < start + len {
            let k = ((start + len - off) as usize).min(buf.len());
            read_exact_at(a.source(), off, &mut buf[..k])?;
            self.emit(&buf[..k])?;
            off += k as u64;
        }
        self.central.push(c);
        Ok(())
    }

    /// Write the central directory and end record; returns the sink.
    pub fn finish(mut self, comment: &[u8]) -> Result<W> {
        self.check_idle()?;
        let cd_start = fits32(self.offset)?;
        let central = core::mem::take(&mut self.central);
        for c in &central {
            let extra = central_extra(c);
            let mut h = Vec::with_capacity(CENTRAL_LEN + c.name.len() + extra.len());
            h.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
            h.extend_from_slice(&MADE_BY_UNIX.to_le_bytes());
            h.extend_from_slice(&c.needed.to_le_bytes());
            h.extend_from_slice(&c.flags.to_le_bytes());
            h.extend_from_slice(&c.method.code().to_le_bytes());
            h.extend_from_slice(&c.time.to_le_bytes());
            h.extend_from_slice(&c.date.to_le_bytes());
            h.extend_from_slice(&c.crc.to_le_bytes());
            h.extend_from_slice(&c.csize.to_le_bytes());
            h.extend_from_slice(&c.usize.to_le_bytes());
            h.extend_from_slice(&(c.name.len() as u16).to_le_bytes());
            h.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // comment length
            h.extend_from_slice(&0u16.to_le_bytes()); // disk
            h.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
            h.extend_from_slice(&c.ext_attr.to_le_bytes());
            h.extend_from_slice(&c.offset.to_le_bytes());
            h.extend_from_slice(&c.name);
            h.extend_from_slice(&extra);
            self.emit(&h)?;
        }
        let cd_size = fits32(self.offset - cd_start as u64)?;
        let n = central.len() as u16;
        let clen = comment.len().min(0xFFFF);
        let mut e = Vec::with_capacity(EOCD_LEN + clen);
        e.extend_from_slice(&EOCD_SIG.to_le_bytes());
        e.extend_from_slice(&[0, 0, 0, 0]);
        e.extend_from_slice(&n.to_le_bytes());
        e.extend_from_slice(&n.to_le_bytes());
        e.extend_from_slice(&cd_size.to_le_bytes());
        e.extend_from_slice(&cd_start.to_le_bytes());
        e.extend_from_slice(&(clen as u16).to_le_bytes());
        e.extend_from_slice(&comment[..clen]);
        self.emit(&e)?;
        Ok(self.w)
    }
}

/// General-purpose flag bits 1-2 for deflate: 2 = maximum, 4 = fast.
fn level_flags(level: u8, m: Method) -> u16 {
    match (m, level) {
        (Method::Deflated, 8..) => 2,
        (Method::Deflated, 1..=2) => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str, mode: u32) -> FileMeta {
        FileMeta { name: name.into(), mode, mtime: 1_789_000_000, uid: 1000, gid: 100 }
    }

    fn extract(a: &ZipArchive<Vec<u8>>, i: usize) -> Result<Vec<u8>> {
        let mut r = a.reader(i)?;
        let mut v = Vec::new();
        crate::copy(&mut r, &mut v)?;
        Ok(v)
    }

    fn sample() -> Vec<u8> {
        let mut w = ZipWriter::new(Vec::new());
        w.add_directory(&meta("dir", S_IFDIR | 0o755)).unwrap();
        let text = "hello zip ".repeat(500);
        let a = w.add_file(&meta("dir/text.txt", S_IFREG | 0o640), text.as_bytes(), 6).unwrap();
        assert_eq!(a.method, Method::Deflated);
        let b = w.add_file(&meta("tiny", S_IFREG | 0o600), b"x", 6).unwrap();
        assert_eq!(b.method, Method::Stored);
        w.add_symlink(&meta("dir/link", S_IFLNK | 0o777), "text.txt").unwrap();
        w.start_file(&meta("streamed.bin", S_IFREG | 0o644), 9).unwrap();
        for i in 0..100u32 {
            w.write_chunk(&[(i % 7) as u8; 1000]).unwrap();
        }
        let s = w.finish_file().unwrap();
        assert_eq!(s.size, 100_000);
        w.finish(b"a comment").unwrap()
    }

    #[test]
    fn roundtrip() {
        let z = sample();
        let a = ZipArchive::open(z).unwrap();
        let e = a.entries();
        assert_eq!(e.len(), 5);
        assert_eq!(e[0].name, "dir/");
        assert!(e[0].is_dir());
        assert_eq!(e[1].unix_mode(), Some(S_IFREG | 0o640));
        assert_eq!(e[1].mtime, 1_789_000_000);
        assert_eq!((e[1].uid, e[1].gid), (Some(1000), Some(100)));
        assert_eq!(extract(&a, 1).unwrap(), "hello zip ".repeat(500).as_bytes());
        assert_eq!(extract(&a, 2).unwrap(), b"x");
        assert!(e[3].is_symlink());
        assert_eq!(extract(&a, 3).unwrap(), b"text.txt");
        let s = extract(&a, 4).unwrap();
        assert_eq!(s.len(), 100_000);
        assert_eq!(a.comment(), b"a comment");
    }

    #[test]
    fn copy_entries_between_archives() {
        let src = ZipArchive::open(sample()).unwrap();
        let mut w = ZipWriter::new(Vec::new());
        for i in 0..src.entries().len() {
            w.copy_entry(&src, i).unwrap();
        }
        let a = ZipArchive::open(w.finish(b"").unwrap()).unwrap();
        for i in 0..a.entries().len() {
            assert_eq!(extract(&a, i).unwrap(), extract(&src, i).unwrap());
            assert_eq!(a.entries()[i].flags & FLAG_DESCRIPTOR, 0);
        }
    }

    #[test]
    fn prepended_stub_is_tolerated() {
        let mut z = b"#!/bin/sh\nexit 0\n".to_vec();
        z.extend(sample());
        let a = ZipArchive::open(z).unwrap();
        assert_eq!(a.prepended(), 17);
        assert_eq!(extract(&a, 2).unwrap(), b"x");
    }

    #[test]
    fn zip64_end_records_are_read() {
        // Rewrite a plain archive's EOCD into zip64 form.
        let z = sample();
        let eocd = z.len() - 22 - 9;
        let count = u16le(&z, eocd + 10) as u64;
        let cd_size = u32le(&z, eocd + 12) as u64;
        let cd_off = u32le(&z, eocd + 16) as u64;
        let mut out = z[..eocd].to_vec();
        let z64_at = out.len() as u64;
        out.extend_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&44u64.to_le_bytes());
        out.extend_from_slice(&[30, 3, 45, 0]);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&z64_at.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
        out.extend_from_slice(&[0xFF; 8]);
        out.extend_from_slice(&[0, 0]);
        let a = ZipArchive::open(out).unwrap();
        assert_eq!(a.entries().len(), 5);
        assert_eq!(extract(&a, 4).unwrap().len(), 100_000);
    }

    #[test]
    fn zip64_extra_in_central_record() {
        let mut e = ZipEntry {
            name: "x".into(),
            method: Method::Stored,
            flags: 0,
            crc32: 0,
            compressed_size: 0xFFFF_FFFF,
            size: 0xFFFF_FFFF,
            header_offset: 0,
            mtime: 0,
            made_by: 0,
            external_attr: 0,
            uid: None,
            gid: None,
        };
        let mut x = Vec::new();
        x.extend_from_slice(&EXTRA_ZIP64.to_le_bytes());
        x.extend_from_slice(&16u16.to_le_bytes());
        x.extend_from_slice(&(5u64 << 32).to_le_bytes());
        x.extend_from_slice(&(6u64 << 32).to_le_bytes());
        parse_extra(&x, &mut e, [true, true, false]).unwrap();
        assert_eq!((e.size, e.compressed_size), (5 << 32, 6 << 32));
        assert!(parse_extra(&x[..10], &mut e, [true, true, false]).is_err());
    }

    #[test]
    fn crc_and_size_violations_are_caught() {
        let z = sample();
        let a = ZipArchive::open(z.clone()).unwrap();
        // Flip a byte inside the stored "tiny" entry's data.
        let (start, _) = a.data_range(2).unwrap();
        let mut bad = z.clone();
        bad[start as usize] ^= 1;
        let b = ZipArchive::open(bad).unwrap();
        assert!(matches!(extract(&b, 2), Err(Error::Checksum { .. })));
        // A lying central directory (declared size too small) must stop early.
        let mut lie = z.clone();
        let cd_off = u32le(&z, z.len() - 22 - 9 + 16) as usize;
        let mut p = cd_off;
        let mut target = None;
        while u32le(&lie, p) == CENTRAL_SIG {
            let name_len = u16le(&lie, p + 28) as usize;
            if &lie[p + 46..p + 46 + name_len] == b"dir/text.txt" {
                target = Some(p);
            }
            p += 46 + name_len + u16le(&lie, p + 30) as usize + u16le(&lie, p + 32) as usize;
        }
        let t = target.unwrap();
        lie[t + 24..t + 28].copy_from_slice(&10u32.to_le_bytes());
        let l = ZipArchive::open(lie).unwrap();
        assert_eq!(extract(&l, 1), Err(Error::Length));
    }

    #[test]
    fn hostile_input_never_panics() {
        let z = sample();
        for cut in 0..z.len() {
            if let Ok(a) = ZipArchive::open(z[..cut].to_vec()) {
                for i in 0..a.entries().len() {
                    let _ = extract(&a, i);
                }
            }
        }
        let mut x = 3u64;
        for round in 0..300 {
            let mut v = z.clone();
            for _ in 0..(1 + round % 8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let at = (x as usize) % v.len();
                v[at] = (x >> 32) as u8;
            }
            if let Ok(a) = ZipArchive::open(v) {
                for i in 0..a.entries().len() {
                    let _ = extract(&a, i);
                }
            }
        }
        assert_eq!(ZipArchive::open(b"PK\x05\x06".to_vec()).err(), Some(Error::BadMagic));
    }
}
