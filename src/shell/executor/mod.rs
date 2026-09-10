//! Command executor
//!
//! Looks up the command handler and calls it.
//! Special handling for `sudo` (authenticate + elevate euid inline).
//! If the ParsedCommand has a `redir_out`, output is captured into a
//! CaptureIo buffer and written to memfs with the resolved absolute path.

use crate::shell::command::CommandRegistry;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::shell::memfs;
use crate::shell::parser::{ParsedCommand, MAX_ARGS};
use crate::kernel::users;
use crate::kernel::users::permission;

pub fn execute(
    cmd:      &ParsedCommand<'_>,
    registry: &CommandRegistry,
    env:      &mut ShellEnv,
    io:       &mut dyn ShellIo,
) -> i32 {
    // ── sudo — handle inline so we have access to the registry ─────────────────
    if cmd.name == b"sudo" {
        return execute_sudo(cmd, registry, env, io);
    }

    let handler = match registry.find(cmd.name) {
        Some(h) => h,
        None => {
            io.write_bytes(cmd.name);
            io.write_bytes(b": command not found  (try 'help')\n");
            env.last_exit = 127;
            return 127;
        }
    };

    let args: &[&[u8]] = &cmd.args[..cmd.argc.min(MAX_ARGS - 1)];

    // ── Output redirection ────────────────────────────────────────────────────
    let code = if let Some(raw_path) = cmd.redir_out {
        let mut path_buf = [0u8; 256];
        let abs_path = resolve_abs(env.cwd(), raw_path, &mut path_buf);

        // Permission check on redirect target
        if let Some((fuid, fgid, fmode)) = memfs::get_meta(abs_path) {
            if !permission::check(fuid, fgid, fmode, env.euid(), env.egid(), permission::MAY_WRITE) {
                io.write_bytes(b"bash: ");
                io.write_bytes(raw_path);
                io.write_bytes(b": Permission denied\n");
                env.last_exit = 1;
                return 1;
            }
        }
        // If file doesn't exist yet, check write permission on parent dir
        else {
            let parent = parent_of(abs_path);
            let (puid, pgid, pmode) = crate::shell::command::virt_fs::get_stat(parent);
            if !permission::check(puid, pgid, pmode, env.euid(), env.egid(), permission::MAY_WRITE) {
                io.write_bytes(b"bash: ");
                io.write_bytes(raw_path);
                io.write_bytes(b": Permission denied\n");
                env.last_exit = 1;
                return 1;
            }
        }

        static mut CAPTURE_BUF: CaptureIo = CaptureIo::new();
        let cap = unsafe { &mut CAPTURE_BUF };
        cap.reset();

        let code = handler.execute(args, env, cap);

        let data = cap.as_slice();
        let uid  = env.euid();
        let gid  = env.egid();
        if cmd.redir_append {
            memfs::append(abs_path, data);
        } else {
            memfs::write_owned(abs_path, data, uid, gid, 0o644);
        }
        code
    } else {
        handler.execute(args, env, io)
    };

    env.last_exit = code;
    code
}

// ── sudo inline handler ────────────────────────────────────────────────────────

fn execute_sudo(
    cmd:      &ParsedCommand<'_>,
    registry: &CommandRegistry,
    env:      &mut ShellEnv,
    io:       &mut dyn ShellIo,
) -> i32 {
    // sudo with no sub-command
    if cmd.argc == 0 {
        io.write_bytes(b"usage: sudo <command> [args...]\n");
        env.last_exit = 1;
        return 1;
    }

    // Authenticate if not already root
    if env.euid() != 0 {
        let mut uname_copy = [0u8; 32];
        let un = {
            let u = env.username();
            let n = u.len().min(32);
            uname_copy[..n].copy_from_slice(&u[..n]);
            n
        };

        io.write_bytes(b"[sudo] password for ");
        io.write_bytes(&uname_copy[..un]);
        io.write_bytes(b": ");

        let mut pw = [0u8; 64];
        let pwlen = read_secret(io, &mut pw);

        if !users::verify(&uname_copy[..un], &pw[..pwlen]) {
            io.write_bytes(b"sudo: incorrect password\n");
            env.last_exit = 1;
            return 1;
        }
    }

    // Extract sub-command
    let sub_name = cmd.args[0];
    let sub_args_slice = &cmd.args[1..cmd.argc.min(MAX_ARGS - 1)];

    // sudo su → full root switch
    if sub_name == b"su" {
        env.set_session(0, 0, b"/root", b"root");
        return 0;
    }

    // Elevate, run sub-command, restore
    let old_euid = env.elevate_root();

    let code = match registry.find(sub_name) {
        Some(h) => h.execute(sub_args_slice, env, io),
        None => {
            io.write_bytes(sub_name);
            io.write_bytes(b": command not found\n");
            1
        }
    };

    env.restore_euid(old_euid);
    env.last_exit = code;
    code
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read a secret (password) without echoing. Returns length.
fn read_secret(io: &mut dyn ShellIo, buf: &mut [u8; 64]) -> usize {
    let mut n = 0;
    loop {
        let b = io.read_byte_blocking();
        match b {
            b'\n' | b'\r' => { io.newline(); break; }
            0x08 | 0x7F   => { if n > 0 { n -= 1; } }
            c if c >= 0x20 && n < 64 => { buf[n] = c; n += 1; }
            _ => {}
        }
    }
    n
}

fn resolve_abs<'a>(cwd: &[u8], path: &[u8], buf: &'a mut [u8; 256]) -> &'a [u8] {
    if path.first() == Some(&b'/') {
        let n = path.len().min(255);
        buf[..n].copy_from_slice(&path[..n]);
        return &buf[..n];
    }
    let mut n = 0;
    for &b in cwd { if n < 255 { buf[n] = b; n += 1; } }
    if cwd != b"/" && n < 255 { buf[n] = b'/'; n += 1; }
    for &b in path { if n < 255 { buf[n] = b; n += 1; } }
    &buf[..n]
}

fn parent_of(path: &[u8]) -> &[u8] {
    if path == b"/" { return b"/"; }
    match path.iter().rposition(|&b| b == b'/') {
        None | Some(0) => b"/",
        Some(i)        => &path[..i],
    }
}

// ── CaptureIo ─────────────────────────────────────────────────────────────────

pub struct CaptureIo {
    buf: [u8; 4096],
    len: usize,
}

impl CaptureIo {
    pub const fn new() -> Self { Self { buf: [0u8; 4096], len: 0 } }
    pub fn reset(&mut self) { self.len = 0; }
    pub fn as_slice(&self) -> &[u8] { &self.buf[..self.len] }
}

impl ShellIo for CaptureIo {
    fn write_byte(&mut self, b: u8) {
        if self.len < 4096 { self.buf[self.len] = b; self.len += 1; }
    }
    fn write_bytes(&mut self, s: &[u8]) {
        for &b in s { self.write_byte(b); }
    }
    fn read_byte(&mut self) -> Option<u8> { None }
    fn clear_screen(&mut self) {}
}
