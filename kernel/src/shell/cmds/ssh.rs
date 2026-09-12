//! `ssh` — connect to a remote host, authenticate, and run a command (or an
//! interactive shell). Password auth: `-P <pass>`, the `SSHPASS` environment
//! variable, or an interactive prompt.

use crate::outln;
use crate::shell::ctx::Ctx;
use crate::ssh::client::Session;
use crate::ssh::transport::SshError;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

pub fn errmsg(e: &SshError) -> String {
    match e {
        SshError::Io => "connection error".to_string(),
        SshError::Closed => "connection closed".to_string(),
        SshError::Mac => "message authentication failed".to_string(),
        SshError::Protocol(m) => m.clone(),
        SshError::Disconnected(m) => m.clone(),
    }
}

/// Parse `[user@]host` → (user, host). Default user: the current $USER or root.
pub fn split_target(ctx: &Ctx, s: &str) -> (String, String) {
    match s.split_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string()),
        None => (ctx.env("USER").unwrap_or_else(|| "root".to_string()), s.to_string()),
    }
}

/// Resolve the password: the SSHPASS environment variable, or a prompt.
pub fn resolve_password(ctx: &mut Ctx) -> Option<String> {
    if let Some(p) = ctx.env("SSHPASS") {
        return Some(p);
    }
    ctx.print("password: ");
    ctx.flush();
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match ctx.read_stdin(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if b[0] == b'\n' {
                    break;
                }
                line.push(b[0]);
            }
        }
    }
    ctx.print("\n");
    Some(String::from_utf8_lossy(&line).into_owned())
}

pub fn ssh(ctx: &mut Ctx) -> i32 {
    let mut port = 22u16;
    let mut target = None;
    let mut cmd: Vec<String> = Vec::new();
    let mut i = 0;
    let args = ctx.args[1..].to_vec();
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-p" => {
                i += 1;
                port = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(22);
            }
            _ if target.is_none() && !a.starts_with('-') => target = Some(a.clone()),
            _ if target.is_some() => cmd.push(a.clone()),
            _ => {}
        }
        i += 1;
    }
    let Some(target) = target else {
        return ctx.fail("usage: ssh [-p PORT] [user@]host [command...]  (password: SSHPASS env or prompt)");
    };
    let (user, host) = split_target(ctx, &target);
    let Some(pass) = resolve_password(ctx) else {
        return ctx.fail("no password");
    };

    let sess = match Session::open(&host, port, &user, &pass, 20_000) {
        Ok(s) => s,
        Err(e) => return ctx.fail(alloc::format!("ssh: {}", errmsg(&e))),
    };
    let fp = crate::ssh::client::fingerprint(&sess.host_key.lock());
    ctx.eprint(&alloc::format!("Warning: host key for {host} is {fp} (not verified)\n"));

    let command = cmd.join(" ");
    let r = if command.is_empty() { sess.shell() } else { sess.exec(&command) };
    if let Err(e) = r {
        return ctx.fail(alloc::format!("ssh: {}", errmsg(&e)));
    }

    // Forward local stdin to the remote in the background.
    let sin = ctx.stdin();
    let s_in = sess.clone();
    crate::sched::spawn("ssh-stdin", move || pump_stdin(sin, s_in));

    // Copy remote output to our stdout until the channel closes.
    let out = ctx.stdout();
    let mut buf = [0u8; 8192];
    loop {
        let n = sess.read(&mut buf);
        if n == 0 {
            break;
        }
        if out.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let err = sess.stderr();
    if !err.is_empty() {
        ctx.eprint(&String::from_utf8_lossy(&err));
    }
    let code = sess.wait_exit();
    sess.close();
    code
}

fn pump_stdin(sin: Arc<dyn crate::fs::file::File>, sess: Arc<Session>) {
    let mut b = [0u8; 4096];
    loop {
        match sin.read(&mut b) {
            Ok(0) | Err(_) => {
                sess.eof();
                break;
            }
            Ok(n) => {
                if sess.is_closed() || sess.write(&b[..n]).is_err() {
                    break;
                }
            }
        }
    }
}
