//! FastROS interactive shell
//!
//! Layer position: Layer 5 (userspace-equivalent, runs in kernel mode for now).

pub mod command;
pub mod completion;
pub mod env;
pub mod executor;
pub mod history;
pub mod io;
pub mod memdir;
pub mod memfs;
pub mod parser;
pub mod readline;

use command::CommandRegistry;
use env::ShellEnv;
use io::ShellIo;
use readline::LineEditor;

// ── Concrete I/O implementation ───────────────────────────────────────────────

struct VgaKeyboardIo;

impl ShellIo for VgaKeyboardIo {
    fn write_byte(&mut self, b: u8) { crate::drivers::display::vga::write(&[b]); }
    fn write_bytes(&mut self, s: &[u8]) { crate::drivers::display::vga::write(s); }
    fn read_byte(&mut self) -> Option<u8> { crate::drivers::char::keyboard::read_byte() }
    fn clear_screen(&mut self) { crate::drivers::display::vga::clear(); }
    fn put_char_at(&mut self, col: u16, row: u16, ch: u8, color: u8) {
        crate::drivers::display::vga::put_at(col as usize, row as usize, ch, color);
    }
    fn write_at(&mut self, col: u16, row: u16, s: &[u8], color: u8) {
        crate::drivers::display::vga::write_at(col as usize, row as usize, s, color);
    }
    fn fill_row(&mut self, row: u16, ch: u8, color: u8) {
        crate::drivers::display::vga::fill_row(row as usize, ch, color);
    }
    fn move_cursor(&mut self, col: u16, row: u16) {
        crate::drivers::display::vga::set_cursor(col as usize, row as usize);
    }
}

// ── Login ─────────────────────────────────────────────────────────────────────

/// Show login prompt and authenticate. Returns a populated ShellEnv on success.
fn do_login(io: &mut dyn ShellIo) -> ShellEnv {
    let mut env = ShellEnv::new();
    loop {
        io.write_bytes(b"fastros login: ");

        // Read username (echo ON)
        let mut uname_buf = [0u8; 32];
        let ulen = read_line_simple(io, &mut uname_buf);
        if ulen == 0 { continue; }
        let username = &uname_buf[..ulen];

        // root with empty line — ask password
        io.write_bytes(b"Password: ");
        let mut pw = [0u8; 64];
        let plen = read_secret(io, &mut pw);

        if crate::kernel::users::verify(username, &pw[..plen]) {
            match crate::kernel::users::lookup_user(username) {
                Some((uid, gid, home, hl)) => {
                    env.set_session(uid, gid, &home[..hl], username);
                    print_motd(io);
                    return env;
                }
                None => {}
            }
        }

        io.write_bytes(b"Login incorrect\n\n");
    }
}

fn print_motd(io: &mut dyn ShellIo) {
    io.write_bytes(b"\n");
    io.write_bytes(b"  FastROS Shell  v0.1.0\n");
    io.write_bytes(b"  Type 'help' for a list of commands.\n");
    io.write_bytes(b"\n");
}

// ── Prompt ────────────────────────────────────────────────────────────────────

/// Build "user@fastros:~# " or "user@fastros:~$ " into `buf`.
fn build_prompt(env: &ShellEnv, buf: &mut [u8; 256]) -> usize {
    let mut n = 0;
    macro_rules! push {
        ($s:expr) => { for &b in $s.iter() { if n < 255 { buf[n] = b; n += 1; } } }
    }

    // username@fastros:
    push!(env.username());
    push!(b"@fastros:");

    // cwd with ~ substitution for home
    let cwd  = env.cwd();
    let home = env.home();

    if cwd == home {
        push!(b"~");
    } else if cwd.len() > home.len() && cwd.starts_with(home) && cwd[home.len()] == b'/' {
        push!(b"~");
        push!(&cwd[home.len()..]);
    } else {
        push!(cwd);
    }

    // # for root, $ for normal users
    if env.is_root() { push!(b"# "); } else { push!(b"$ "); }
    n
}

// ── REPL entry point ──────────────────────────────────────────────────────────

pub fn run() -> ! {
    let mut io       = VgaKeyboardIo;
    let mut env      = do_login(&mut io);
    let mut editor   = LineEditor::new();
    let     registry = CommandRegistry::init();

    loop {
        let mut prompt_buf = [0u8; 256];
        let prompt_len = build_prompt(&env, &mut prompt_buf);
        let prompt = &prompt_buf[..prompt_len];
        io.write_bytes(prompt);

        let line = editor.read_line(&mut io, prompt, env.cwd());
        if line.is_empty() { continue; }

        history::push(line);

        match parser::parse(line) {
            Some(cmd) => { executor::execute(&cmd, &registry, &mut env, &mut io); }
            None      => {}
        }
    }
}

// ── I/O helpers ───────────────────────────────────────────────────────────────

/// Read a line with echo (for username). Returns length.
fn read_line_simple(io: &mut dyn ShellIo, buf: &mut [u8; 32]) -> usize {
    let mut n = 0;
    loop {
        let b = io.read_byte_blocking();
        match b {
            b'\n' | b'\r' => { io.newline(); break; }
            0x08 | 0x7F => {
                if n > 0 { n -= 1; io.write_bytes(b"\x08 \x08"); }
            }
            c if c >= 0x20 && n < 32 => {
                buf[n] = c; n += 1;
                io.write_byte(c); // echo
            }
            _ => {}
        }
    }
    n
}

/// Read a secret (password) without echoing. Returns length.
fn read_secret(io: &mut dyn ShellIo, buf: &mut [u8; 64]) -> usize {
    let mut n = 0;
    loop {
        let b = io.read_byte_blocking();
        match b {
            b'\n' | b'\r' => { io.newline(); break; }
            0x08 | 0x7F => { if n > 0 { n -= 1; } }
            c if c >= 0x20 && n < 64 => { buf[n] = c; n += 1; }
            _ => {}
        }
    }
    n
}
