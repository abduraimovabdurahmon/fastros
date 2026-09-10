//! Command executor
//!
//! Looks up the command handler and calls it.
//! If the ParsedCommand has a `redir_out`, output is captured into a
//! CaptureIo buffer and written to memfs with the resolved absolute path.

use crate::shell::command::CommandRegistry;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::shell::memfs;
use crate::shell::parser::{ParsedCommand, MAX_ARGS};

pub fn execute(
    cmd:      &ParsedCommand<'_>,
    registry: &CommandRegistry,
    env:      &mut ShellEnv,
    io:       &mut dyn ShellIo,
) -> i32 {
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
        // Resolve relative path against CWD so memfs key is always absolute
        let mut path_buf = [0u8; 256];
        let abs_path = resolve_abs(env.cwd(), raw_path, &mut path_buf);

        static mut CAPTURE_BUF: CaptureIo = CaptureIo::new();
        let cap = unsafe { &mut CAPTURE_BUF };
        cap.reset();

        let code = handler.execute(args, env, cap);

        let data = cap.as_slice();
        if cmd.redir_append {
            memfs::append(abs_path, data);
        } else {
            memfs::write(abs_path, data);
        }
        code
    } else {
        handler.execute(args, env, io)
    };

    env.last_exit = code;
    code
}

/// Resolve `path` against `cwd` to an absolute path, written into `buf`.
/// Returns a slice of `buf`.
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
