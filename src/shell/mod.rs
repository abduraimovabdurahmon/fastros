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

// ── Concrete I/O implementations ──────────────────────────────────────────────

struct VgaKeyboardIo;

impl ShellIo for VgaKeyboardIo {
    fn write_byte(&mut self, b: u8) { crate::drivers::display::vga::write(&[b]); }
    fn write_bytes(&mut self, s: &[u8]) { crate::drivers::display::vga::write(s); }
    fn read_byte(&mut self) -> Option<u8> { crate::drivers::char::keyboard::read_byte() }
    // Override blocking read to also drive network polling while idle
    fn read_byte_blocking(&mut self) -> u8 {
        loop {
            crate::kernel::net::poll_drivers();
            if let Some(b) = self.read_byte() { return b; }
            core::hint::spin_loop();
        }
    }
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

/// SSH I/O backend — reads from SSH channel, writes back via SSH.
struct SshIo;

impl ShellIo for SshIo {
    fn write_byte(&mut self, b: u8) {
        crate::kernel::net::ssh::send_to_client(&[b]);
    }
    fn write_bytes(&mut self, s: &[u8]) {
        if !s.is_empty() {
            crate::kernel::net::ssh::send_to_client(s);
        }
    }
    fn read_byte(&mut self) -> Option<u8> {
        crate::kernel::net::poll_drivers();
        crate::kernel::net::ssh::poll_byte()
    }
    fn read_byte_blocking(&mut self) -> u8 {
        loop {
            if let Some(b) = self.read_byte() { return b; }
            core::hint::spin_loop();
        }
    }
    fn clear_screen(&mut self) {
        // ANSI escape: erase screen + move to top-left
        crate::kernel::net::ssh::send_to_client(b"\x1b[2J\x1b[H");
    }
    fn newline(&mut self) {
        // SSH/telnet: send CR+LF for proper line ending
        crate::kernel::net::ssh::send_to_client(b"\r\n");
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
    let registry = CommandRegistry::init();

    // Outer loop: alternate between SSH sessions and local session.
    // SSH sessions are ephemeral; once an SSH client disconnects we loop back.
    // The local VGA session never returns.
    loop {
        // ── Wait for SSH client or local keyboard ──────────────────────────
        // Poll the network stack until either an SSH shell becomes active or
        // the user presses a local key (whichever comes first).
        let use_ssh = wait_for_input();

        if use_ssh {
            run_ssh_session(&registry);
            // Client disconnected → loop back and wait for the next session
        } else {
            // Local session: never returns
            run_local_session(&registry);
        }
    }
}

/// Spin until either an SSH shell session becomes active (returns true)
/// or a local key is pressed (returns false).
fn wait_for_input() -> bool {
    loop {
        crate::kernel::net::poll_drivers();
        crate::kernel::net::ssh::poll(); // drive handshake

        if crate::kernel::net::ssh::has_client() {
            return true;
        }
        if crate::drivers::char::keyboard::read_byte().is_some() {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Run one SSH shell session. Returns when the client disconnects.
fn run_ssh_session(registry: &CommandRegistry) {
    let mut io  = SshIo;
    let mut env = ShellEnv::new();

    // SSH already authenticated the user — use root credentials
    let root_home = b"/root";
    let root_name = b"root";
    env.set_session(0, 0, root_home, root_name);

    io.write_bytes(b"\r\nFastROS SSH shell\r\nType 'help' for available commands.\r\n\r\n");

    let mut editor = LineEditor::new();

    loop {
        if !crate::kernel::net::ssh::has_client() { break; }

        let mut prompt_buf = [0u8; 256];
        let prompt_len = build_prompt(&env, &mut prompt_buf);
        let prompt = &prompt_buf[..prompt_len];
        io.write_bytes(prompt);

        let line = editor.read_line(&mut io, prompt, env.cwd());

        // Check disconnect during readline
        if !crate::kernel::net::ssh::has_client() { break; }
        if line.is_empty() { continue; }

        history::push(line);

        match parser::parse(line) {
            Some(cmd) => { executor::execute(&cmd, registry, &mut env, &mut io); }
            None      => {}
        }
    }
}

/// Run the local VGA/keyboard session. Never returns.
fn run_local_session(registry: &CommandRegistry) -> ! {
    let mut io  = VgaKeyboardIo;
    let mut env = do_login(&mut io);
    let mut editor = LineEditor::new();

    loop {
        let mut prompt_buf = [0u8; 256];
        let prompt_len = build_prompt(&env, &mut prompt_buf);
        let prompt = &prompt_buf[..prompt_len];
        io.write_bytes(prompt);

        let line = editor.read_line(&mut io, prompt, env.cwd());
        if line.is_empty() { continue; }

        history::push(line);

        match parser::parse(line) {
            Some(cmd) => { executor::execute(&cmd, registry, &mut env, &mut io); }
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
