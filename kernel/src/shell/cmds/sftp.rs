//! `sftp-server` — the SFTP subsystem (protocol version 3) that our sshd runs
//! for `subsystem sftp`. Modern `scp` and `sftp` both speak SFTP, so this is
//! what makes file transfer to/from FastROS work out of the box. It speaks the
//! binary protocol over stdin/stdout (wired to the ssh channel) and serves the
//! filesystem via `fs::ops`.

use crate::fs::file::{flags, File};
use crate::fs::ops::{self, Ctx as FsCtx};
use crate::fs::{FileType, Metadata, SetAttr};
use crate::shell::ctx::Ctx;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

// Client → server.
const INIT: u8 = 1;
const OPEN: u8 = 3;
const CLOSE: u8 = 4;
const READ: u8 = 5;
const WRITE: u8 = 6;
const LSTAT: u8 = 7;
const FSTAT: u8 = 8;
const SETSTAT: u8 = 9;
const FSETSTAT: u8 = 10;
const OPENDIR: u8 = 11;
const READDIR: u8 = 12;
const REMOVE: u8 = 13;
const MKDIR: u8 = 14;
const RMDIR: u8 = 15;
const REALPATH: u8 = 16;
const STAT: u8 = 17;
const RENAME: u8 = 18;
// Server → client.
const VERSION: u8 = 2;
const STATUS: u8 = 101;
const HANDLE: u8 = 102;
const DATA: u8 = 103;
const NAME: u8 = 104;
const ATTRS: u8 = 105;
// Status codes.
const FX_OK: u32 = 0;
const FX_EOF: u32 = 1;
const FX_NO_SUCH_FILE: u32 = 2;
const FX_FAILURE: u32 = 4;
// OPEN pflags.
const PF_READ: u32 = 0x1;
const PF_WRITE: u32 = 0x2;
const PF_APPEND: u32 = 0x4;
const PF_CREAT: u32 = 0x8;
const PF_TRUNC: u32 = 0x10;
const PF_EXCL: u32 = 0x20;
// ATTR flags.
const A_SIZE: u32 = 0x1;
const A_PERM: u32 = 0x4;
const A_TIME: u32 = 0x8;

struct DirState {
    entries: Vec<String>,
    idx: usize,
    path: String,
}

pub fn sftp_server(ctx: &mut Ctx) -> i32 {
    let inp = ctx.stdin();
    let out = ctx.stdout();
    let fsx = ops::Ctx::of(&ctx.proc);
    let mut files: BTreeMap<String, Arc<dyn File>> = BTreeMap::new();
    let mut dirs: BTreeMap<String, DirState> = BTreeMap::new();
    let mut hc: u64 = 0;

    loop {
        let Some((typ, body)) = read_packet(&inp) else { break };
        let mut c = Cur::new(&body);
        if typ == INIT {
            let _ver = c.u32();
            let mut w = Buf::new(VERSION);
            w.u32(3); // we speak version 3
            send(&out, w);
            continue;
        }
        let Some(id) = c.u32() else { continue };
        match typ {
            REALPATH => {
                let p = c.string().unwrap_or_default();
                let canon = normalize(&p);
                let mut w = Buf::new(NAME);
                w.u32(id);
                w.u32(1);
                w.string(&canon);
                w.string(&canon); // longname
                w.u32(0); // empty attrs
                send(&out, w);
            }
            STAT | LSTAT => {
                let p = c.string().unwrap_or_default();
                match ops::stat(&fsx, &normalize(&p), typ == STAT) {
                    Ok(m) => send_attrs(&out, id, &m),
                    Err(_) => status(&out, id, FX_NO_SUCH_FILE, "no such file"),
                }
            }
            FSTAT => {
                let h = c.string().unwrap_or_default();
                match files.get(&h).and_then(|f| f.stat().ok()) {
                    Some(m) => send_attrs(&out, id, &m),
                    None => status(&out, id, FX_FAILURE, "bad handle"),
                }
            }
            OPEN => {
                let p = normalize(&c.string().unwrap_or_default());
                let pf = c.u32().unwrap_or(0);
                let mut fl = 0u32;
                if pf & PF_READ != 0 && pf & PF_WRITE != 0 {
                    fl |= flags::O_RDWR;
                } else if pf & PF_WRITE != 0 {
                    fl |= flags::O_WRONLY;
                } else {
                    fl |= flags::O_RDONLY;
                }
                if pf & PF_APPEND != 0 {
                    fl |= flags::O_APPEND;
                }
                if pf & PF_CREAT != 0 {
                    fl |= flags::O_CREAT;
                }
                if pf & PF_TRUNC != 0 {
                    fl |= flags::O_TRUNC;
                }
                if pf & PF_EXCL != 0 {
                    fl |= flags::O_EXCL;
                }
                match ops::open(&fsx, &p, fl, 0o644) {
                    Ok(f) => {
                        hc += 1;
                        let h = alloc::format!("f{hc}");
                        files.insert(h.clone(), f);
                        handle(&out, id, &h);
                    }
                    Err(e) => status(&out, id, err_code(e), e.desc()),
                }
            }
            READ => {
                let h = c.string().unwrap_or_default();
                let off = c.u64().unwrap_or(0);
                let len = c.u32().unwrap_or(0).min(64 * 1024) as usize;
                match files.get(&h) {
                    Some(f) => {
                        let mut b = alloc::vec![0u8; len];
                        match f.pread(off, &mut b) {
                            Ok(0) => status(&out, id, FX_EOF, "eof"),
                            Ok(n) => {
                                let mut w = Buf::new(DATA);
                                w.u32(id);
                                w.bytes(&b[..n]);
                                send(&out, w);
                            }
                            Err(e) => status(&out, id, err_code(e), e.desc()),
                        }
                    }
                    None => status(&out, id, FX_FAILURE, "bad handle"),
                }
            }
            WRITE => {
                let h = c.string().unwrap_or_default();
                let off = c.u64().unwrap_or(0);
                let data = c.bytes().unwrap_or_default();
                match files.get(&h) {
                    Some(f) => match write_all_at(f, off, data) {
                        Ok(()) => status(&out, id, FX_OK, "ok"),
                        Err(e) => status(&out, id, err_code(e), e.desc()),
                    },
                    None => status(&out, id, FX_FAILURE, "bad handle"),
                }
            }
            CLOSE => {
                let h = c.string().unwrap_or_default();
                files.remove(&h);
                dirs.remove(&h);
                status(&out, id, FX_OK, "closed");
            }
            OPENDIR => {
                let p = normalize(&c.string().unwrap_or_default());
                match ops::list_dir(&fsx, &p) {
                    Ok(es) => {
                        hc += 1;
                        let h = alloc::format!("d{hc}");
                        let mut names: Vec<String> = alloc::vec![".".to_string(), "..".to_string()];
                        names.extend(es.into_iter().map(|e| e.name).filter(|n| n != "." && n != ".."));
                        dirs.insert(h.clone(), DirState { entries: names, idx: 0, path: p });
                        handle(&out, id, &h);
                    }
                    Err(e) => status(&out, id, err_code(e), e.desc()),
                }
            }
            READDIR => {
                let h = c.string().unwrap_or_default();
                match dirs.get_mut(&h) {
                    Some(d) => {
                        if d.idx >= d.entries.len() {
                            status(&out, id, FX_EOF, "eof");
                        } else {
                            let end = (d.idx + 64).min(d.entries.len());
                            let batch = d.entries[d.idx..end].to_vec();
                            let dpath = d.path.clone();
                            d.idx = end;
                            let mut w = Buf::new(NAME);
                            w.u32(id);
                            w.u32(batch.len() as u32);
                            for name in &batch {
                                let full = join(&dpath, name);
                                let m = ops::stat(&fsx, &full, false).ok();
                                w.string(name);
                                w.string(&long_name(name, m.as_ref()));
                                push_attrs(&mut w, m.as_ref());
                            }
                            send(&out, w);
                        }
                    }
                    None => status(&out, id, FX_FAILURE, "bad handle"),
                }
            }
            REMOVE => {
                let p = normalize(&c.string().unwrap_or_default());
                reply(&out, id, ops::unlink(&fsx, &p));
            }
            MKDIR => {
                let p = normalize(&c.string().unwrap_or_default());
                reply(&out, id, ops::mkdir(&fsx, &p, 0o755));
            }
            RMDIR => {
                let p = normalize(&c.string().unwrap_or_default());
                reply(&out, id, ops::rmdir(&fsx, &p));
            }
            RENAME => {
                let from = normalize(&c.string().unwrap_or_default());
                let to = normalize(&c.string().unwrap_or_default());
                reply(&out, id, ops::rename(&fsx, &from, &to));
            }
            SETSTAT => {
                let p = normalize(&c.string().unwrap_or_default());
                let sa = parse_setattr(&mut c);
                reply(&out, id, apply_setattr(&fsx, &p, &sa));
            }
            FSETSTAT => {
                let h = c.string().unwrap_or_default();
                let sa = parse_setattr(&mut c);
                match files.get(&h) {
                    Some(f) => {
                        let r = sa.size.map(|s| f.truncate(s)).unwrap_or(Ok(()));
                        reply(&out, id, r);
                    }
                    None => status(&out, id, FX_FAILURE, "bad handle"),
                }
            }
            _ => status(&out, id, FX_FAILURE, "unsupported"),
        }
    }
    0
}

fn write_all_at(f: &Arc<dyn File>, mut off: u64, mut data: &[u8]) -> crate::errno::KResult<()> {
    while !data.is_empty() {
        let n = f.pwrite(off, data)?;
        if n == 0 {
            return Err(crate::errno::Errno::EIO);
        }
        off += n as u64;
        data = &data[n..];
    }
    Ok(())
}

struct SAttr {
    size: Option<u64>,
    perm: Option<u16>,
}

fn parse_setattr(c: &mut Cur) -> SAttr {
    let flags = c.u32().unwrap_or(0);
    let mut sa = SAttr { size: None, perm: None };
    if flags & A_SIZE != 0 {
        sa.size = c.u64();
    }
    if flags & 0x2 != 0 {
        // uid, gid
        c.u32();
        c.u32();
    }
    if flags & A_PERM != 0 {
        sa.perm = c.u32().map(|p| (p & 0o7777) as u16);
    }
    if flags & A_TIME != 0 {
        c.u32();
        c.u32();
    }
    sa
}

fn apply_setattr(fsx: &FsCtx, path: &str, sa: &SAttr) -> crate::errno::KResult<()> {
    if sa.size.is_none() && sa.perm.is_none() {
        return Ok(());
    }
    let node = fsx.resolve(path, true)?;
    node.inode.set_attr(&SetAttr { size: sa.size, perm: sa.perm, ..Default::default() })
}

fn err_code(e: crate::errno::Errno) -> u32 {
    match e {
        crate::errno::Errno::ENOENT => FX_NO_SUCH_FILE,
        _ => FX_FAILURE,
    }
}

fn reply(out: &Arc<dyn File>, id: u32, r: crate::errno::KResult<()>) {
    match r {
        Ok(()) => status(out, id, FX_OK, "ok"),
        Err(e) => status(out, id, err_code(e), e.desc()),
    }
}

// ── response helpers ────────────────────────────────────────────────────────

fn status(out: &Arc<dyn File>, id: u32, code: u32, msg: &str) {
    let mut w = Buf::new(STATUS);
    w.u32(id);
    w.u32(code);
    w.string(msg);
    w.string(""); // language tag
    send(out, w);
}

fn handle(out: &Arc<dyn File>, id: u32, h: &str) {
    let mut w = Buf::new(HANDLE);
    w.u32(id);
    w.string(h);
    send(out, w);
}

fn send_attrs(out: &Arc<dyn File>, id: u32, m: &Metadata) {
    let mut w = Buf::new(ATTRS);
    w.u32(id);
    push_attrs(&mut w, Some(m));
    send(out, w);
}

fn push_attrs(w: &mut Buf, m: Option<&Metadata>) {
    match m {
        Some(m) => {
            w.u32(A_SIZE | A_PERM | A_TIME);
            w.u64(m.size);
            w.u32(m.kind.mode_bits() | (m.perm as u32 & 0o7777));
            w.u32(m.mtime.sec as u32); // atime
            w.u32(m.mtime.sec as u32); // mtime
        }
        None => w.u32(0),
    }
}

/// `ls -l`-style long name (no CRLF).
fn long_name(name: &str, m: Option<&Metadata>) -> String {
    let (kind, perm, size, nlink, uid, gid) = match m {
        Some(m) => (m.kind, m.perm, m.size, m.nlink, m.uid, m.gid),
        None => (FileType::Regular, 0o644, 0, 1, 0, 0),
    };
    let t = match kind {
        FileType::Directory => 'd',
        FileType::Symlink => 'l',
        FileType::CharDevice => 'c',
        FileType::BlockDevice => 'b',
        FileType::Fifo => 'p',
        FileType::Socket => 's',
        _ => '-',
    };
    let rwx = |b: u16| -> String {
        alloc::format!(
            "{}{}{}",
            if b & 4 != 0 { 'r' } else { '-' },
            if b & 2 != 0 { 'w' } else { '-' },
            if b & 1 != 0 { 'x' } else { '-' }
        )
    };
    alloc::format!(
        "{}{}{}{} {:>3} {:<8} {:<8} {:>10} Jan  1 00:00 {}",
        t, rwx(perm >> 6), rwx(perm >> 3), rwx(perm), nlink, uid, gid, size, name
    )
}

// ── path helpers ────────────────────────────────────────────────────────────

fn normalize(p: &str) -> String {
    let base = if p.starts_with('/') { p.to_string() } else { alloc::format!("/{p}") };
    let mut out: Vec<&str> = Vec::new();
    for c in base.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        let mut s = String::new();
        for c in out {
            s.push('/');
            s.push_str(c);
        }
        s
    }
}

fn join(dir: &str, name: &str) -> String {
    if name == "." {
        return dir.to_string();
    }
    if name == ".." {
        return normalize(&alloc::format!("{dir}/.."));
    }
    if dir == "/" {
        alloc::format!("/{name}")
    } else {
        alloc::format!("{}/{name}", dir.trim_end_matches('/'))
    }
}

// ── wire format ─────────────────────────────────────────────────────────────

/// Read one packet: u32 length, then that many bytes (type + payload).
fn read_packet(inp: &Arc<dyn File>) -> Option<(u8, Vec<u8>)> {
    let mut len = [0u8; 4];
    if !read_exact(inp, &mut len) {
        return None;
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > 512 * 1024 {
        return None;
    }
    let mut body = alloc::vec![0u8; n];
    if !read_exact(inp, &mut body) {
        return None;
    }
    let typ = body[0];
    Some((typ, body[1..].to_vec()))
}

fn read_exact(inp: &Arc<dyn File>, buf: &mut [u8]) -> bool {
    let mut off = 0;
    while off < buf.len() {
        match inp.read(&mut buf[off..]) {
            Ok(0) | Err(_) => return false,
            Ok(k) => off += k,
        }
    }
    true
}

fn send(out: &Arc<dyn File>, b: Buf) {
    let _ = out.write_all(&b.finish());
}

/// A cursor over a received payload.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Cur<'a> {
        Cur { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.p + n > self.b.len() {
            return None;
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        let s = self.take(8)?;
        Some(u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn string(&mut self) -> Option<String> {
        self.bytes().map(|b| String::from_utf8_lossy(b).into_owned())
    }
}

/// A response builder (type byte + payload, length-prefixed on finish).
struct Buf {
    v: Vec<u8>,
}
impl Buf {
    fn new(typ: u8) -> Buf {
        Buf { v: alloc::vec![typ] }
    }
    fn u32(&mut self, x: u32) {
        self.v.extend_from_slice(&x.to_be_bytes());
    }
    fn u64(&mut self, x: u64) {
        self.v.extend_from_slice(&x.to_be_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.v.extend_from_slice(b);
    }
    fn string(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    fn finish(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.v.len() + 4);
        out.extend_from_slice(&(self.v.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.v);
        out
    }
}
