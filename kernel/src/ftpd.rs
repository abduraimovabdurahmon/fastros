//! FTP server (`ftpd`) — RFC 959, passive mode.
//!
//! Serves the guest filesystem so a standard FTP client (from a laptop, another
//! container, or FastROS' own `ftp` command) can list, download and upload
//! files. It parallels the SSH server: one accept loop, a task per connection.
//! Auth is intentionally permissive (any USER/PASS logs in as root) — the same
//! trust model as the console; tighten via a config later if needed.

use crate::fs::file::flags;
use crate::fs::ops::{self, Ctx};
use crate::fs::FileType;
use crate::net::socket::{TcpListener, TcpStream};
use crate::net::{IpAddress, IpEndpoint};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};

const PORT: u16 = 21;
const IDLE_MS: u64 = 300_000;
/// Passive data ports are handed out from this range, round-robin.
const PASV_LO: u16 = 50_000;
const PASV_HI: u16 = 50_199;
static PASV_NEXT: AtomicU16 = AtomicU16::new(PASV_LO);

pub fn start() {
    crate::sched::spawn("ftpd", listen);
}

fn listen() {
    let listener = loop {
        match TcpListener::bind(PORT, 8) {
            Ok(l) => break l,
            Err(e) => {
                crate::kerr!("ftpd", "cannot listen on port {}: {}", PORT, e);
                crate::sched::sleep_ms(5000);
            }
        }
    };
    crate::kinfo!("ftpd", "listening on port {}", PORT);
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(x) => x,
            Err(_) => continue,
        };
        crate::sched::spawn("ftpd-conn", move || {
            let mut s = Session::new(Arc::new(stream), peer);
            s.run();
        });
    }
}

/// Root-privileged filesystem context (the server runs as the kernel process).
fn fsctx() -> Ctx {
    Ctx::of(&crate::proc::kernel())
}

struct Session {
    ctrl: Arc<TcpStream>,
    peer: IpEndpoint,
    buf: Vec<u8>,
    cwd: String,
    /// Pending passive-mode data listener (created by PASV, consumed by the
    /// next transfer command).
    pasv: Option<TcpListener>,
    rnfr: Option<String>,
}

impl Session {
    fn new(ctrl: Arc<TcpStream>, peer: IpEndpoint) -> Session {
        Session { ctrl, peer, buf: Vec::new(), cwd: "/".to_string(), pasv: None, rnfr: None }
    }

    fn reply(&self, code: u16, text: &str) {
        let line = alloc::format!("{code} {text}\r\n");
        let _ = self.ctrl.write_all(line.as_bytes());
    }

    fn read_line(&mut self) -> Option<String> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Some(String::from_utf8_lossy(&line).into_owned());
            }
            let mut tmp = [0u8; 512];
            match self.ctrl.read_timeout(&mut tmp, Some(IDLE_MS)) {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
            }
        }
    }

    fn run(&mut self) {
        self.reply(220, "FastROS FTP server ready");
        loop {
            let Some(line) = self.read_line() else { break };
            let (cmd, arg) = match line.split_once(' ') {
                Some((c, a)) => (c.to_ascii_uppercase(), a.to_string()),
                None => (line.to_ascii_uppercase(), String::new()),
            };
            match cmd.as_str() {
                "USER" => self.reply(331, "please send PASS"),
                "PASS" => self.reply(230, "login ok"),
                "SYST" => self.reply(215, "UNIX Type: L8"),
                "FEAT" => {
                    let _ = self.ctrl.write_all(b"211-Features:\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End\r\n");
                }
                "OPTS" => self.reply(200, "ok"),
                "NOOP" => self.reply(200, "ok"),
                "TYPE" => self.reply(200, "type set to I"),
                "PWD" | "XPWD" => {
                    let cwd = self.cwd.clone();
                    self.reply(257, &alloc::format!("\"{cwd}\" is the current directory"));
                }
                "CWD" | "XCWD" => self.cwd_cmd(&arg),
                "CDUP" | "XCUP" => {
                    let up = parent_of(&self.cwd);
                    self.cwd_cmd(&up);
                }
                "PASV" => self.pasv_cmd(),
                "LIST" => self.list_cmd(&arg, true),
                "NLST" => self.list_cmd(&arg, false),
                "RETR" => self.retr_cmd(&arg),
                "STOR" => self.stor_cmd(&arg),
                "DELE" => self.simple(ops::unlink(&fsctx(), &self.abspath(&arg)), 250, "deleted"),
                "MKD" | "XMKD" => {
                    let p = self.abspath(&arg);
                    match ops::mkdir(&fsctx(), &p, 0o755) {
                        Ok(()) => self.reply(257, &alloc::format!("\"{p}\" created")),
                        Err(e) => self.reply(550, e.desc()),
                    }
                }
                "RMD" | "XRMD" => self.simple(ops::rmdir(&fsctx(), &self.abspath(&arg)), 250, "removed"),
                "SIZE" => match ops::stat(&fsctx(), &self.abspath(&arg), true) {
                    Ok(m) => self.reply(213, &m.size.to_string()),
                    Err(e) => self.reply(550, e.desc()),
                },
                "RNFR" => {
                    let p = self.abspath(&arg);
                    if ops::stat(&fsctx(), &p, false).is_ok() {
                        self.rnfr = Some(p);
                        self.reply(350, "ready for RNTO");
                    } else {
                        self.reply(550, "no such file");
                    }
                }
                "RNTO" => {
                    let to = self.abspath(&arg);
                    match self.rnfr.take() {
                        Some(from) => self.simple(ops::rename(&fsctx(), &from, &to), 250, "renamed"),
                        None => self.reply(503, "RNFR first"),
                    }
                }
                "QUIT" => {
                    self.reply(221, "goodbye");
                    break;
                }
                _ => self.reply(502, "command not implemented"),
            }
        }
        self.ctrl.shutdown();
    }

    /// Resolve a client path against the session CWD to an absolute path.
    fn abspath(&self, arg: &str) -> String {
        if arg.is_empty() {
            self.cwd.clone()
        } else if arg.starts_with('/') {
            arg.to_string()
        } else if self.cwd == "/" {
            alloc::format!("/{arg}")
        } else {
            alloc::format!("{}/{arg}", self.cwd)
        }
    }

    fn simple(&self, r: crate::errno::KResult<()>, ok: u16, msg: &str) {
        match r {
            Ok(()) => self.reply(ok, msg),
            Err(e) => self.reply(550, e.desc()),
        }
    }

    fn cwd_cmd(&mut self, arg: &str) {
        let p = self.abspath(arg);
        match ops::stat(&fsctx(), &p, true) {
            Ok(m) if m.kind == FileType::Directory => {
                // Normalize through resolve so ".." collapses.
                self.cwd = normalize(&p);
                self.reply(250, "directory changed");
            }
            Ok(_) => self.reply(550, "not a directory"),
            Err(e) => self.reply(550, e.desc()),
        }
    }

    fn pasv_cmd(&mut self) {
        // Pick a free port from the range.
        let mut listener = None;
        for _ in 0..(PASV_HI - PASV_LO + 1) {
            let mut p = PASV_NEXT.fetch_add(1, Ordering::Relaxed);
            if p > PASV_HI {
                PASV_NEXT.store(PASV_LO, Ordering::Relaxed);
                p = PASV_LO;
            }
            if let Ok(l) = TcpListener::bind(p, 1) {
                listener = Some((l, p));
                break;
            }
        }
        let Some((l, port)) = listener else {
            self.reply(425, "cannot open passive port");
            return;
        };
        // Report the IP the control connection arrived on (what the client can reach).
        let ip = match self.ctrl.local().map(|e| e.addr) {
            Some(IpAddress::Ipv4(a)) => a.octets(),
            _ => [127, 0, 0, 1],
        };
        self.pasv = Some(l);
        self.reply(
            227,
            &alloc::format!(
                "Entering Passive Mode ({},{},{},{},{},{})",
                ip[0], ip[1], ip[2], ip[3], port >> 8, port & 0xff
            ),
        );
    }

    /// Accept the pending passive data connection.
    fn accept_data(&mut self) -> Option<TcpStream> {
        let l = self.pasv.take()?;
        match l.accept() {
            Ok((s, _)) => Some(s),
            Err(_) => None,
        }
    }

    fn list_cmd(&mut self, arg: &str, long: bool) {
        let path = self.abspath(arg);
        let entries = match ops::list_dir(&fsctx(), &path) {
            Ok(e) => e,
            Err(e) => {
                self.reply(550, e.desc());
                return;
            }
        };
        if self.pasv.is_none() {
            self.reply(425, "use PASV first");
            return;
        }
        self.reply(150, "here comes the listing");
        let Some(data) = self.accept_data() else {
            self.reply(425, "cannot open data connection");
            return;
        };
        let mut out = String::new();
        for e in entries {
            if e.name == "." || e.name == ".." {
                continue;
            }
            if long {
                let child = if path == "/" { alloc::format!("/{}", e.name) } else { alloc::format!("{}/{}", path, e.name) };
                let m = ops::stat(&fsctx(), &child, false).ok();
                out.push_str(&format_long(&e.name, m.as_ref()));
            } else {
                out.push_str(&e.name);
                out.push_str("\r\n");
            }
        }
        let _ = data.write_all(out.as_bytes());
        data.shutdown();
        self.reply(226, "transfer complete");
    }

    fn retr_cmd(&mut self, arg: &str) {
        let path = self.abspath(arg);
        let file = match ops::open(&fsctx(), &path, flags::O_RDONLY, 0) {
            Ok(f) => f,
            Err(e) => {
                self.reply(550, e.desc());
                return;
            }
        };
        if self.pasv.is_none() {
            self.reply(425, "use PASV first");
            return;
        }
        self.reply(150, "opening data connection");
        let Some(data) = self.accept_data() else {
            self.reply(425, "cannot open data connection");
            return;
        };
        let mut tmp = [0u8; 8192];
        loop {
            match file.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    if data.write_all(&tmp[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        data.shutdown();
        self.reply(226, "transfer complete");
    }

    fn stor_cmd(&mut self, arg: &str) {
        let path = self.abspath(arg);
        let file = match ops::open(&fsctx(), &path, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC, 0o644) {
            Ok(f) => f,
            Err(e) => {
                self.reply(550, e.desc());
                return;
            }
        };
        if self.pasv.is_none() {
            self.reply(425, "use PASV first");
            return;
        }
        self.reply(150, "ready to receive");
        let Some(data) = self.accept_data() else {
            self.reply(425, "cannot open data connection");
            return;
        };
        let mut tmp = [0u8; 8192];
        let mut ok = true;
        loop {
            match data.read_timeout(&mut tmp, Some(IDLE_MS)) {
                Ok(0) => break,
                Ok(n) => {
                    if file.write_all(&tmp[..n]).is_err() {
                        ok = false;
                        break;
                    }
                }
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        data.shutdown();
        if ok {
            self.reply(226, "transfer complete");
        } else {
            self.reply(550, "write failed");
        }
    }
}

/// `/a/b/c` -> `/a/b`; `/` stays `/`.
fn parent_of(p: &str) -> String {
    match p.rsplit_once('/') {
        Some(("", _)) | None => "/".to_string(),
        Some((head, _)) => head.to_string(),
    }
}

/// Collapse `.`/`..` in an absolute path.
fn normalize(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for c in p.split('/') {
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

/// One `ls -l`-style line (what FTP clients parse), CRLF-terminated.
fn format_long(name: &str, m: Option<&crate::fs::Metadata>) -> String {
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
    let rwx = |bits: u16| -> String {
        let mut s = String::new();
        s.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        s.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        s.push(if bits & 0o1 != 0 { 'x' } else { '-' });
        s
    };
    alloc::format!(
        "{}{}{}{} {:>3} {:<8} {:<8} {:>10} Jan 01 00:00 {}\r\n",
        t,
        rwx(perm >> 6),
        rwx(perm >> 3),
        rwx(perm),
        nlink,
        uid,
        gid,
        size,
        name
    )
}
