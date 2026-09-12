//! `ftp` — a small FTP client over [`crate::net::ftp`].
//!
//! One-shot forms (scriptable):
//!   ftp ls  ftp://[user[:pass]@]host[:port]/dir
//!   ftp get ftp://.../file [localfile]
//!   ftp put localfile ftp://.../destfile
//! Interactive form:
//!   ftp host [port]        then: ls [dir] | cd DIR | pwd | get F | put F | bye

use crate::outln;
use crate::fs::file::flags;
use crate::fs::ops;
use crate::net::ftp::{Ftp, FtpError, Url};
use crate::shell::ctx::Ctx;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const TIMEOUT_MS: u64 = 30_000;

fn open_url(ctx: &mut Ctx, url_s: &str) -> Result<(Ftp, Url), i32> {
    let url = Url::parse(url_s).map_err(|e| ctx.fail(alloc::format!("ftp: {}", e.message())))?;
    let mut f = Ftp::connect(&url.host, url.port, TIMEOUT_MS).map_err(|e| ctx.fail(alloc::format!("ftp: {}", e.message())))?;
    f.login(&url.user, &url.pass).map_err(|e| ctx.fail(alloc::format!("ftp: login: {}", e.message())))?;
    Ok((f, url))
}

fn read_local(ctx: &mut Ctx, path: &str) -> Result<Vec<u8>, i32> {
    let fs = ops::Ctx::of(&ctx.proc);
    let f = ops::open(&fs, path, flags::O_RDONLY, 0).map_err(|e| ctx.fail_errno(path, e))?;
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match f.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(ctx.fail_errno(path, e)),
        }
    }
    Ok(out)
}

fn write_local(ctx: &mut Ctx, path: &str, data: &[u8]) -> Result<(), i32> {
    let fs = ops::Ctx::of(&ctx.proc);
    let f = ops::open(&fs, path, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC, 0o644).map_err(|e| ctx.fail_errno(path, e))?;
    f.write_all(data).map_err(|e| ctx.fail_errno(path, e))
}

/// Trailing path component, or "index".
fn basename(path: &str) -> String {
    let n = path.rsplit('/').next().unwrap_or("");
    if n.is_empty() { "download".to_string() } else { n.to_string() }
}

pub fn ftp(ctx: &mut Ctx) -> i32 {
    let args: Vec<String> = ctx.args[1..].to_vec();
    match args.first().map(|s| s.as_str()) {
        Some("ls") | Some("dir") => {
            let Some(url) = args.get(1) else { return ctx.fail("ftp ls: need an ftp:// URL") };
            let (mut f, u) = match open_url(ctx, url) {
                Ok(v) => v,
                Err(c) => return c,
            };
            let r = f.list(&u.path);
            f.quit();
            match r {
                Ok(bytes) => {
                    ctx.write(&bytes);
                    0
                }
                Err(e) => ctx.fail(alloc::format!("ftp: {}", e.message())),
            }
        }
        Some("get") => {
            let Some(url) = args.get(1) else { return ctx.fail("ftp get: need an ftp:// URL") };
            let (mut f, u) = match open_url(ctx, url) {
                Ok(v) => v,
                Err(c) => return c,
            };
            let r = f.retr(&u.path);
            f.quit();
            match r {
                Ok(bytes) => {
                    let out = args.get(2).cloned().unwrap_or_else(|| basename(&u.path));
                    if let Err(c) = write_local(ctx, &out, &bytes) {
                        return c;
                    }
                    outln!(ctx, "ftp: wrote {} ({} bytes)", out, bytes.len());
                    0
                }
                Err(e) => ctx.fail(alloc::format!("ftp: {}", e.message())),
            }
        }
        Some("put") => {
            let (Some(local), Some(url)) = (args.get(1), args.get(2)) else {
                return ctx.fail("ftp put: usage: ftp put LOCALFILE ftp://.../dest");
            };
            let data = match read_local(ctx, local) {
                Ok(d) => d,
                Err(c) => return c,
            };
            let (mut f, u) = match open_url(ctx, url) {
                Ok(v) => v,
                Err(c) => return c,
            };
            let r = f.stor(&u.path, &data);
            f.quit();
            match r {
                Ok(()) => {
                    outln!(ctx, "ftp: stored {} bytes to {}", data.len(), u.path);
                    0
                }
                Err(e) => ctx.fail(alloc::format!("ftp: {}", e.message())),
            }
        }
        Some(host) if !host.starts_with('-') => {
            let port = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(21);
            interactive(ctx, host, port)
        }
        _ => ctx.fail("usage: ftp ls|get|put <ftp://URL>  |  ftp <host> [port]"),
    }
}

/// A tiny REPL over stdin, for hand use.
fn interactive(ctx: &mut Ctx, host: &str, port: u16) -> i32 {
    let mut f = match Ftp::connect(host, port, TIMEOUT_MS) {
        Ok(f) => f,
        Err(e) => return ctx.fail(alloc::format!("ftp: {}", e.message())),
    };
    // Anonymous by default; a real login can be redone via the `user` command.
    if let Err(e) = f.login("anonymous", "anonymous@fastros") {
        ctx.eprint(&alloc::format!("ftp: login: {}\n", e.message()));
    } else {
        outln!(ctx, "Connected to {host}. Anonymous login ok.");
    }
    let report = |ctx: &mut Ctx, r: Result<(), FtpError>| {
        if let Err(e) = r {
            ctx.eprint(&alloc::format!("ftp: {}\n", e.message()));
        }
    };
    let mut line = String::new();
    loop {
        ctx.print("ftp> ");
        ctx.flush();
        if !read_line(ctx, &mut line) {
            break;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            [] => {}
            ["bye"] | ["quit"] | ["exit"] => break,
            ["pwd"] => match f.pwd() {
                Ok(p) => outln!(ctx, "{p}"),
                Err(e) => ctx.eprint(&alloc::format!("ftp: {}\n", e.message())),
            },
            ["cd", d] => report(ctx, f.cwd(d)),
            ["ls"] | ["dir"] => match f.list("") {
                Ok(b) => ctx.write(&b),
                Err(e) => ctx.eprint(&alloc::format!("ftp: {}\n", e.message())),
            },
            ["ls", d] | ["dir", d] => match f.list(d) {
                Ok(b) => ctx.write(&b),
                Err(e) => ctx.eprint(&alloc::format!("ftp: {}\n", e.message())),
            },
            ["get", p] => {
                let out = basename(p);
                match f.retr(p) {
                    Ok(b) => {
                        if write_local(ctx, &out, &b).is_ok() {
                            outln!(ctx, "wrote {out} ({} bytes)", b.len());
                        }
                    }
                    Err(e) => ctx.eprint(&alloc::format!("ftp: {}\n", e.message())),
                }
            }
            ["put", p] => match read_local(ctx, p) {
                Ok(data) => report(ctx, f.stor(&basename(p), &data)),
                Err(_) => {}
            },
            _ => ctx.eprint("commands: ls [dir], cd DIR, pwd, get F, put F, bye\n"),
        }
    }
    f.quit();
    0
}

/// Read one line from stdin into `line` (cleared first); false on EOF.
fn read_line(ctx: &mut Ctx, line: &mut String) -> bool {
    line.clear();
    let mut byte = [0u8; 1];
    loop {
        match ctx.read_stdin(&mut byte) {
            Ok(0) => return !line.is_empty(),
            Ok(_) => {
                if byte[0] == b'\n' {
                    return true;
                }
                line.push(byte[0] as char);
            }
            Err(_) => return false,
        }
    }
}
