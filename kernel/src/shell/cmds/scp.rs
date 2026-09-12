//! `scp` — secure copy over SSH.
//!
//! Client (user-typed): `scp [-r] [-P port] SRC DEST`, where one side is
//! `[user@]host:path`. Uploads run the remote `scp -t`, downloads the remote
//! `scp -f`, over an SSH channel.
//!
//! Remote side (run by our sshd for an incoming scp): `scp -t PATH` (sink) or
//! `scp -f PATH` (source), speaking the scp protocol over stdin/stdout.
//!
//! Both directions share one protocol engine over a `Chan` (a byte channel that
//! is either the process stdio or an SSH session).

use crate::fs::file::{flags, File};
use crate::fs::ops::{self, Ctx as FsCtx};
use crate::fs::FileType;
use crate::shell::ctx::Ctx;
use crate::ssh::client::Session;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// A bidirectional byte channel the scp protocol runs over.
trait Chan {
    fn rd(&self, buf: &mut [u8]) -> usize; // 0 = EOF
    fn wr(&self, data: &[u8]) -> bool; // true = ok
}

/// Server side: the process's stdin (read) and stdout (write).
struct FileChan {
    inp: Arc<dyn File>,
    out: Arc<dyn File>,
}
impl Chan for FileChan {
    fn rd(&self, buf: &mut [u8]) -> usize {
        self.inp.read(buf).unwrap_or(0)
    }
    fn wr(&self, data: &[u8]) -> bool {
        self.out.write_all(data).is_ok()
    }
}

/// Client side: an SSH session channel.
struct SessChan {
    sess: Arc<Session>,
}
impl Chan for SessChan {
    fn rd(&self, buf: &mut [u8]) -> usize {
        self.sess.read(buf)
    }
    fn wr(&self, data: &[u8]) -> bool {
        self.sess.write(data).is_ok()
    }
}

pub fn scp(ctx: &mut Ctx) -> i32 {
    let (mut sink, mut source, mut recursive) = (false, false, false);
    let mut port = 22u16;
    let mut operands: Vec<String> = Vec::new();
    let args = ctx.args[1..].to_vec();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-t" => sink = true,
            "-f" => source = true,
            "-r" => recursive = true,
            "-P" => {
                i += 1;
                port = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(22);
            }
            "--" | "-d" | "-p" | "-v" | "-q" | "-e" | "-B" | "-C" => {}
            s if s.starts_with('-') => {}
            s => operands.push(s.to_string()),
        }
        i += 1;
    }

    // Remote side (invoked by sshd).
    if sink || source {
        let chan = FileChan { inp: ctx.stdin(), out: ctx.stdout() };
        let path = operands.first().cloned().unwrap_or_else(|| ".".to_string());
        return if sink {
            sink_mode(ctx, &path, recursive, &chan)
        } else {
            source_mode(ctx, &path, recursive, &chan)
        };
    }

    // Client side: scp SRC DEST.
    if operands.len() != 2 {
        return ctx.fail("usage: scp [-r] [-P PORT] SRC DEST  (one side is [user@]host:path)");
    }
    let (src, dst) = (operands[0].clone(), operands[1].clone());
    let src_r = parse_remote(&src);
    let dst_r = parse_remote(&dst);
    match (src_r, dst_r) {
        (None, Some((user, host, rpath))) => client_upload(ctx, &src, &user, &host, port, &rpath, recursive),
        (Some((user, host, rpath)), None) => client_download(ctx, &user, &host, port, &rpath, &dst, recursive),
        (Some(_), Some(_)) => ctx.fail("scp: remote-to-remote copy is not supported"),
        (None, None) => ctx.fail("scp: neither SRC nor DEST is remote — use cp for local copies"),
    }
}

/// `[user@]host:path` → (user, host, path); None if the operand is local.
fn parse_remote(s: &str) -> Option<(String, String, String)> {
    let colon = s.find(':')?;
    // A ':' after a '/' is part of a local path, not a host separator.
    if s[..colon].contains('/') {
        return None;
    }
    let (authority, path) = (&s[..colon], &s[colon + 1..]);
    let (user, host) = match authority.split_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string()),
        None => ("root".to_string(), authority.to_string()),
    };
    if host.is_empty() {
        return None;
    }
    let path = if path.is_empty() { ".".to_string() } else { path.to_string() };
    Some((user, host, path))
}

fn open_session(ctx: &mut Ctx, user: &str, host: &str, port: u16) -> Result<Arc<Session>, i32> {
    let Some(pass) = super::ssh::resolve_password(ctx) else {
        return Err(ctx.fail("scp: no password"));
    };
    match Session::open(host, port, user, &pass, 20_000) {
        Ok(s) => Ok(s),
        Err(e) => Err(ctx.fail(alloc::format!("scp: {}", super::ssh::errmsg(&e)))),
    }
}

fn client_upload(ctx: &mut Ctx, local: &str, user: &str, host: &str, port: u16, rpath: &str, recursive: bool) -> i32 {
    let sess = match open_session(ctx, user, host, port) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let cmd = alloc::format!("scp {}-t {}", if recursive { "-r " } else { "" }, sh_quote(rpath));
    if let Err(e) = sess.exec(&cmd) {
        return ctx.fail(alloc::format!("scp: {}", super::ssh::errmsg(&e)));
    }
    let chan = SessChan { sess: sess.clone() };
    let code = source_mode(ctx, local, recursive, &chan);
    sess.eof();
    let ecode = sess.wait_exit();
    let err = sess.stderr();
    if !err.is_empty() {
        ctx.eprint(&String::from_utf8_lossy(&err));
    }
    sess.close();
    if code != 0 {
        code
    } else {
        ecode
    }
}

fn client_download(ctx: &mut Ctx, user: &str, host: &str, port: u16, rpath: &str, local: &str, recursive: bool) -> i32 {
    let sess = match open_session(ctx, user, host, port) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let cmd = alloc::format!("scp {}-f {}", if recursive { "-r " } else { "" }, sh_quote(rpath));
    if let Err(e) = sess.exec(&cmd) {
        return ctx.fail(alloc::format!("scp: {}", super::ssh::errmsg(&e)));
    }
    let chan = SessChan { sess: sess.clone() };
    let code = sink_mode(ctx, local, recursive, &chan);
    let ecode = sess.wait_exit();
    let err = sess.stderr();
    if !err.is_empty() {
        ctx.eprint(&String::from_utf8_lossy(&err));
    }
    sess.close();
    if code != 0 {
        code
    } else {
        ecode
    }
}

/// Minimal shell quoting for the remote command.
fn sh_quote(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)) {
        s.to_string()
    } else {
        alloc::format!("'{}'", s.replace('\'', "'\\''"))
    }
}

// ── protocol I/O over a Chan ────────────────────────────────────────────────

fn ack(c: &dyn Chan) {
    c.wr(&[0u8]);
}

fn err_reply(c: &dyn Chan, msg: &str) {
    let mut b = Vec::with_capacity(msg.len() + 2);
    b.push(1u8);
    b.extend_from_slice(msg.as_bytes());
    b.push(b'\n');
    c.wr(&b);
}

fn read_exact(c: &dyn Chan, buf: &mut [u8]) -> bool {
    let mut off = 0;
    while off < buf.len() {
        let n = c.rd(&mut buf[off..]);
        if n == 0 {
            return false;
        }
        off += n;
    }
    true
}

fn read_byte(c: &dyn Chan) -> Option<u8> {
    let mut b = [0u8; 1];
    read_exact(c, &mut b).then_some(b[0])
}

fn read_line(c: &dyn Chan) -> Option<String> {
    let mut line = Vec::new();
    loop {
        let b = read_byte(c)?;
        if b == b'\n' {
            return Some(String::from_utf8_lossy(&line).into_owned());
        }
        line.push(b);
    }
}

fn read_ack(c: &dyn Chan) -> bool {
    match read_byte(c) {
        Some(0) => true,
        Some(_) => {
            let _ = read_line(c);
            false
        }
        None => false,
    }
}

// ── sink: receive into `dest` ───────────────────────────────────────────────

fn sink_mode(ctx: &mut Ctx, dest: &str, _recursive: bool, c: &dyn Chan) -> i32 {
    let fsx = ops::Ctx::of(&ctx.proc);
    let dest_is_dir = ops::stat(&fsx, dest, true).map(|m| m.kind == FileType::Directory).unwrap_or(false);
    let mut dir = if dest_is_dir { dest.to_string() } else { parent_of(dest) };
    let mut first = true;
    ack(c);
    loop {
        let Some(line) = read_line(c) else { break };
        if line.is_empty() {
            continue;
        }
        let tag = line.as_bytes()[0] as char;
        let body = &line[1..];
        match tag {
            'C' => {
                let Some((mode, size, name)) = parse_cd(body) else {
                    err_reply(c, "bad C header");
                    return 1;
                };
                let target = if first && !dest_is_dir { dest.to_string() } else { join(&dir, &name) };
                first = false;
                ack(c);
                if let Err(e) = recv_file(c, &fsx, &target, size, mode) {
                    err_reply(c, &alloc::format!("{target}: {}", e.desc()));
                    return 1;
                }
                let _ = read_byte(c);
                ack(c);
            }
            'D' => {
                let Some((mode, _sz, name)) = parse_cd(body) else {
                    err_reply(c, "bad D header");
                    return 1;
                };
                let sub = if first && !dest_is_dir { dest.to_string() } else { join(&dir, &name) };
                first = false;
                if ops::stat(&fsx, &sub, true).is_err() {
                    let _ = ops::mkdir(&fsx, &sub, (mode & 0o7777) as u16);
                }
                dir = sub;
                ack(c);
            }
            'E' => {
                dir = parent_of(&dir);
                ack(c);
            }
            'T' => ack(c),
            _ => {
                err_reply(c, "unexpected scp command");
                return 1;
            }
        }
    }
    0
}

fn recv_file(c: &dyn Chan, fsx: &FsCtx, path: &str, size: u64, mode: u32) -> crate::errno::KResult<()> {
    let f = ops::open(fsx, path, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC, (mode & 0o7777) as u16)?;
    let mut left = size;
    let mut buf = [0u8; 8192];
    while left > 0 {
        let want = core::cmp::min(left as usize, buf.len());
        if !read_exact(c, &mut buf[..want]) {
            return Err(crate::errno::Errno::EIO);
        }
        f.write_all(&buf[..want])?;
        left -= want as u64;
    }
    Ok(())
}

// ── source: send `path` ─────────────────────────────────────────────────────

fn source_mode(ctx: &mut Ctx, path: &str, recursive: bool, c: &dyn Chan) -> i32 {
    let fsx = ops::Ctx::of(&ctx.proc);
    if !read_ack(c) {
        return 1;
    }
    match send_path(c, &fsx, path, recursive) {
        Ok(()) => 0,
        Err(msg) => {
            err_reply(c, &msg);
            1
        }
    }
}

fn send_path(c: &dyn Chan, fsx: &FsCtx, path: &str, recursive: bool) -> Result<(), String> {
    let meta = ops::stat(fsx, path, true).map_err(|e| alloc::format!("{path}: {}", e.desc()))?;
    let name = basename(path);
    if meta.kind == FileType::Directory {
        if !recursive {
            return Err(alloc::format!("{path}: not a regular file"));
        }
        let hdr = alloc::format!("D{:04o} 0 {}\n", meta.perm & 0o7777, name);
        if !c.wr(hdr.as_bytes()) || !read_ack(c) {
            return Err("peer".to_string());
        }
        let entries = ops::list_dir(fsx, path).map_err(|e| e.desc().to_string())?;
        for e in entries {
            if e.name == "." || e.name == ".." {
                continue;
            }
            send_path(c, fsx, &join(path, &e.name), recursive)?;
        }
        if !c.wr(b"E\n") || !read_ack(c) {
            return Err("peer".to_string());
        }
        return Ok(());
    }
    let f = ops::open(fsx, path, flags::O_RDONLY, 0).map_err(|e| alloc::format!("{path}: {}", e.desc()))?;
    let hdr = alloc::format!("C{:04o} {} {}\n", meta.perm & 0o7777, meta.size, name);
    if !c.wr(hdr.as_bytes()) || !read_ack(c) {
        return Err("peer".to_string());
    }
    let mut buf = [0u8; 8192];
    let mut left = meta.size;
    while left > 0 {
        let want = core::cmp::min(left as usize, buf.len());
        match f.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => {
                if !c.wr(&buf[..n]) {
                    return Err("write".to_string());
                }
                left -= n as u64;
            }
            Err(_) => return Err("read".to_string()),
        }
    }
    ack(c);
    if !read_ack(c) {
        return Err("peer".to_string());
    }
    Ok(())
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn parse_cd(body: &str) -> Option<(u32, u64, String)> {
    let mode_end = body.find(' ')?;
    let mode = u32::from_str_radix(&body[..mode_end], 8).ok()?;
    let rest = &body[mode_end + 1..];
    let size_end = rest.find(' ')?;
    let size: u64 = rest[..size_end].parse().ok()?;
    let name = rest[size_end + 1..].to_string();
    Some((mode, size, name))
}

fn basename(p: &str) -> String {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or(p).to_string()
}

fn parent_of(p: &str) -> String {
    match p.trim_end_matches('/').rsplit_once('/') {
        Some(("", _)) | None => "/".to_string(),
        Some((head, _)) => head.to_string(),
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" {
        alloc::format!("/{name}")
    } else {
        alloc::format!("{}/{name}", dir.trim_end_matches('/'))
    }
}

