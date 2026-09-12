//! `scp` — secure copy, remote (server) side of the protocol.
//!
//! When a client runs `scp file user@fastros:/dest`, our sshd executes
//! `scp -t /dest` here and the client speaks the scp binary protocol to it;
//! `scp user@fastros:/file local` runs `scp -f /file`. We implement both the
//! sink (`-t`) and source (`-f`) roles, single files and (`-r`) directory trees,
//! over stdin/stdout. Outbound copies from FastROS to another host would need an
//! SSH client, which does not exist yet — that form reports a clear error.

use crate::fs::file::{flags, File};
use crate::fs::ops::{self, Ctx as FsCtx};
use crate::fs::FileType;
use crate::shell::ctx::Ctx;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

pub fn scp(ctx: &mut Ctx) -> i32 {
    let (mut sink, mut source, mut recursive) = (false, false, false);
    let mut path: Option<String> = None;
    for a in ctx.args[1..].iter() {
        match a.as_str() {
            "-t" => sink = true,
            "-f" => source = true,
            "-r" => recursive = true,
            "--" | "-d" | "-p" | "-v" | "-q" | "-e" | "-B" | "-C" => {}
            s if s.starts_with('-') => {}
            s => path = Some(s.to_string()),
        }
    }
    let Some(path) = path else {
        // No -t/-f: this is a user-typed scp. Only local<->local or a helpful note.
        if ctx.args[1..].iter().any(|a| a.contains(':') && !a.starts_with('-')) {
            return ctx.fail("scp: outbound copy needs an SSH client (not yet implemented); use `ftp` or run scp from the remote side");
        }
        return ctx.fail("scp: usage: scp [-r] SRC DEST (remote side is driven by sshd)");
    };
    if sink {
        sink_mode(ctx, &path, recursive)
    } else if source {
        source_mode(ctx, &path, recursive)
    } else {
        ctx.fail("scp: outbound copy needs an SSH client (not yet implemented)")
    }
}

// ── low-level protocol I/O over the ssh channel (stdin/stdout) ──────────────

fn ack(out: &Arc<dyn File>) {
    let _ = out.write_all(&[0u8]);
}

fn err_reply(out: &Arc<dyn File>, msg: &str) {
    let mut b = Vec::with_capacity(msg.len() + 2);
    b.push(1u8); // warning
    b.extend_from_slice(msg.as_bytes());
    b.push(b'\n');
    let _ = out.write_all(&b);
}

/// Read exactly `n` bytes; false on early EOF.
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

fn read_byte(inp: &Arc<dyn File>) -> Option<u8> {
    let mut b = [0u8; 1];
    read_exact(inp, &mut b).then_some(b[0])
}

/// A control line up to and excluding '\n'; None on EOF.
fn read_line(inp: &Arc<dyn File>) -> Option<String> {
    let mut line = Vec::new();
    loop {
        let b = read_byte(inp)?;
        if b == b'\n' {
            return Some(String::from_utf8_lossy(&line).into_owned());
        }
        line.push(b);
    }
}

/// Wait for the peer's status byte (0 ok). Returns false on error/EOF.
fn read_ack(inp: &Arc<dyn File>) -> bool {
    match read_byte(inp) {
        Some(0) => true,
        Some(_) => {
            let _ = read_line(inp); // consume the message
            false
        }
        None => false,
    }
}

// ── sink: receive into `dest` ───────────────────────────────────────────────

fn sink_mode(ctx: &mut Ctx, dest: &str, _recursive: bool) -> i32 {
    let inp = ctx.stdin();
    let out = ctx.stdout();
    let fsx = ops::Ctx::of(&ctx.proc);
    let dest_is_dir = ops::stat(&fsx, dest, true).map(|m| m.kind == FileType::Directory).unwrap_or(false);
    // Directory stack for -r; starts at dest (if a dir) else its parent.
    let mut dir = if dest_is_dir { dest.to_string() } else { parent_of(dest) };
    let mut first = true;
    ack(&out);
    loop {
        let Some(line) = read_line(&inp) else { break };
        if line.is_empty() {
            continue;
        }
        let tag = line.as_bytes()[0] as char;
        let body = &line[1..];
        match tag {
            'C' => {
                let Some((mode, size, name)) = parse_cd(body) else {
                    err_reply(&out, "bad C header");
                    return 1;
                };
                let target = if first && !dest_is_dir { dest.to_string() } else { join(&dir, &name) };
                first = false;
                ack(&out);
                if let Err(e) = recv_file(&inp, &fsx, &target, size, mode) {
                    err_reply(&out, &alloc::format!("{target}: {}", e.desc()));
                    return 1;
                }
                // peer's post-data status byte, then our ack
                let _ = read_byte(&inp);
                ack(&out);
            }
            'D' => {
                let Some((mode, _sz, name)) = parse_cd(body) else {
                    err_reply(&out, "bad D header");
                    return 1;
                };
                let sub = if first && !dest_is_dir { dest.to_string() } else { join(&dir, &name) };
                first = false;
                if ops::stat(&fsx, &sub, true).is_err() {
                    let _ = ops::mkdir(&fsx, &sub, (mode & 0o7777) as u16);
                }
                dir = sub;
                ack(&out);
            }
            'E' => {
                dir = parent_of(&dir);
                ack(&out);
            }
            'T' => {
                ack(&out); // times: accepted, not applied
            }
            _ => {
                err_reply(&out, "unexpected scp command");
                return 1;
            }
        }
    }
    0
}

fn recv_file(inp: &Arc<dyn File>, fsx: &FsCtx, path: &str, size: u64, mode: u32) -> crate::errno::KResult<()> {
    let f = ops::open(fsx, path, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC, (mode & 0o7777) as u16)?;
    let mut left = size;
    let mut buf = [0u8; 8192];
    while left > 0 {
        let want = core::cmp::min(left as usize, buf.len());
        if !read_exact(inp, &mut buf[..want]) {
            return Err(crate::errno::Errno::EIO);
        }
        f.write_all(&buf[..want])?;
        left -= want as u64;
    }
    Ok(())
}

// ── source: send `path` ─────────────────────────────────────────────────────

fn source_mode(ctx: &mut Ctx, path: &str, recursive: bool) -> i32 {
    let inp = ctx.stdin();
    let out = ctx.stdout();
    let fsx = ops::Ctx::of(&ctx.proc);
    if !read_ack(&inp) {
        return 1;
    }
    match send_path(&inp, &out, &fsx, path, recursive) {
        Ok(()) => 0,
        Err(msg) => {
            err_reply(&out, &msg);
            1
        }
    }
}

fn send_path(inp: &Arc<dyn File>, out: &Arc<dyn File>, fsx: &FsCtx, path: &str, recursive: bool) -> Result<(), String> {
    let meta = ops::stat(fsx, path, true).map_err(|e| alloc::format!("{path}: {}", e.desc()))?;
    let name = basename(path);
    if meta.kind == FileType::Directory {
        if !recursive {
            return Err(alloc::format!("{path}: not a regular file"));
        }
        let hdr = alloc::format!("D{:04o} 0 {}\n", meta.perm & 0o7777, name);
        out.write_all(hdr.as_bytes()).map_err(|_| "write".to_string())?;
        if !read_ack(inp) {
            return Err("peer".to_string());
        }
        let entries = ops::list_dir(fsx, path).map_err(|e| e.desc().to_string())?;
        for e in entries {
            if e.name == "." || e.name == ".." {
                continue;
            }
            send_path(inp, out, fsx, &join(path, &e.name), recursive)?;
        }
        out.write_all(b"E\n").map_err(|_| "write".to_string())?;
        if !read_ack(inp) {
            return Err("peer".to_string());
        }
        return Ok(());
    }
    // Regular file.
    let f = ops::open(fsx, path, flags::O_RDONLY, 0).map_err(|e| alloc::format!("{path}: {}", e.desc()))?;
    let hdr = alloc::format!("C{:04o} {} {}\n", meta.perm & 0o7777, meta.size, name);
    out.write_all(hdr.as_bytes()).map_err(|_| "write".to_string())?;
    if !read_ack(inp) {
        return Err("peer".to_string());
    }
    let mut buf = [0u8; 8192];
    let mut left = meta.size;
    while left > 0 {
        let want = core::cmp::min(left as usize, buf.len());
        match f.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => {
                out.write_all(&buf[..n]).map_err(|_| "write".to_string())?;
                left -= n as u64;
            }
            Err(_) => return Err("read".to_string()),
        }
    }
    ack(out); // end-of-file status
    if !read_ack(inp) {
        return Err("peer".to_string());
    }
    Ok(())
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Parse "0644 12345 name" from a C/D header body.
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
