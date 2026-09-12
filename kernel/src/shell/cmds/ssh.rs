//! `ssh` — connect to a remote host, authenticate (public key then password),
//! and run a command (or an interactive shell). Host keys are verified against
//! `~/.ssh/known_hosts` (trust on first use); a changed key is refused.

use crate::fs::file::flags;
use crate::fs::ops;
use crate::shell::ctx::Ctx;
use crate::ssh::client::{Auth, Session};
use crate::ssh::keys;
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

pub fn split_target(ctx: &Ctx, s: &str) -> (String, String) {
    match s.split_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string()),
        None => (ctx.env("USER").unwrap_or_else(|| "root".to_string()), s.to_string()),
    }
}

fn home(ctx: &Ctx) -> String {
    ctx.env("HOME").filter(|h| h.starts_with('/')).unwrap_or_else(|| "/root".to_string())
}

/// Load the user's ed25519 identity (`~/.ssh/id_ed25519`), if present.
fn load_identity(ctx: &Ctx) -> Option<(ed25519_dalek::SigningKey, Vec<u8>)> {
    let path = alloc::format!("{}/.ssh/id_ed25519", home(ctx));
    let fsx = ops::Ctx::of(&ctx.proc);
    let data = ops::read_file(&fsx, &path).ok()?;
    keys::parse_openssh_ed25519(&String::from_utf8_lossy(&data))
}

fn read_password_prompt(ctx: &mut Ctx) -> String {
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
    String::from_utf8_lossy(&line).into_owned()
}

fn host_label(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        alloc::format!("[{host}]:{port}")
    }
}

/// The stored host key for `host`, if `known_hosts` has one.
fn load_known_host(ctx: &Ctx, host: &str, port: u16) -> Option<Vec<u8>> {
    let path = alloc::format!("{}/.ssh/known_hosts", home(ctx));
    let fsx = ops::Ctx::of(&ctx.proc);
    let data = ops::read_file(&fsx, &path).ok()?;
    let want = host_label(host, port);
    for line in String::from_utf8_lossy(&data).lines() {
        let mut it = line.split_whitespace();
        let (h, kind, b64) = (it.next(), it.next(), it.next());
        if let (Some(h), Some("ssh-ed25519"), Some(b64)) = (h, kind, b64) {
            if h == want {
                return fastros_codec::base64::decode(b64);
            }
        }
    }
    None
}

/// Record a host key on trust-on-first-use.
fn remember_host(ctx: &mut Ctx, host: &str, port: u16, blob: &[u8]) {
    let fsx = ops::Ctx::of(&ctx.proc);
    let dir = alloc::format!("{}/.ssh", home(ctx));
    let _ = ops::mkdir_all(&fsx, &dir, 0o700);
    let path = alloc::format!("{dir}/known_hosts");
    let line = alloc::format!("{} ssh-ed25519 {}\n", host_label(host, port), fastros_codec::base64::encode(blob));
    let mut content = ops::read_file(&fsx, &path).unwrap_or_default();
    content.extend_from_slice(line.as_bytes());
    let _ = ops::write_file(&fsx, &path, &content, 0o644);
}

/// Connect, verify the host key (TOFU), and authenticate. Shared by ssh + scp.
pub fn connect(ctx: &mut Ctx, user: &str, host: &str, port: u16) -> Result<Arc<Session>, i32> {
    let key = load_identity(ctx);
    let password = if let Some(p) = ctx.env("SSHPASS") {
        Some(p)
    } else if key.is_none() {
        Some(read_password_prompt(ctx))
    } else {
        None
    };
    let auth = Auth { key, password };
    let expected = load_known_host(ctx, host, port);
    let known = expected.is_some();
    let sess = Session::open(host, port, user, &auth, expected.as_deref(), 20_000).map_err(|e| ctx.fail(alloc::format!("ssh: {}", errmsg(&e))))?;
    if !known {
        let hk = sess.host_key.lock().clone();
        let fp = crate::ssh::fingerprint(&hk);
        remember_host(ctx, host, port, &hk);
        ctx.eprint(&alloc::format!("Warning: permanently added '{}' (ED25519) to known hosts.\nHost key fingerprint: {}\n", host, fp));
    }
    Ok(sess)
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
        return ctx.fail("usage: ssh [-p PORT] [user@]host [command...]  (auth: ~/.ssh/id_ed25519 or SSHPASS/prompt)");
    };
    let (user, host) = split_target(ctx, &target);

    let sess = match connect(ctx, &user, &host, port) {
        Ok(s) => s,
        Err(c) => return c,
    };

    let command = cmd.join(" ");
    let r = if command.is_empty() { sess.shell() } else { sess.exec(&command) };
    if let Err(e) = r {
        return ctx.fail(alloc::format!("ssh: {}", errmsg(&e)));
    }

    let sin = ctx.stdin();
    let s_in = sess.clone();
    crate::sched::spawn("ssh-stdin", move || pump_stdin(sin, s_in));

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

/// `ssh-keygen` — generate `~/.ssh/id_ed25519` + `id_ed25519.pub`.
pub fn ssh_keygen(ctx: &mut Ctx) -> i32 {
    let dir = alloc::format!("{}/.ssh", home(ctx));
    let priv_path = alloc::format!("{dir}/id_ed25519");
    let pub_path = alloc::format!("{priv_path}.pub");
    let fsx = ops::Ctx::of(&ctx.proc);
    if ops::stat(&fsx, &priv_path, true).is_ok() {
        return ctx.fail(alloc::format!("{priv_path} already exists"));
    }
    let sk = keys::generate();
    let comment = alloc::format!("{}@fastros", ctx.env("USER").unwrap_or_else(|| "root".to_string()));
    let _ = ops::mkdir_all(&fsx, &dir, 0o700);
    if let Err(e) = write_file(&fsx, &priv_path, keys::to_openssh_pem(&sk, &comment).as_bytes(), 0o600) {
        return ctx.fail_errno(&priv_path, e);
    }
    if let Err(e) = write_file(&fsx, &pub_path, keys::public_line(&sk, &comment).as_bytes(), 0o644) {
        return ctx.fail_errno(&pub_path, e);
    }
    ctx.println(&alloc::format!("Your identification has been saved in {priv_path}"));
    ctx.println(&alloc::format!("Your public key has been saved in {pub_path}"));
    ctx.println(&alloc::format!("The key fingerprint is: {}", crate::ssh::fingerprint(&keys::public_blob(&sk))));
    0
}

fn write_file(fsx: &ops::Ctx, path: &str, data: &[u8], mode: u16) -> crate::errno::KResult<()> {
    let f = ops::open(fsx, path, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC, mode)?;
    f.write_all(data)
}
