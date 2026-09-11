//! FastROS interactive shell
//!
//! Layer position: Layer 5 (userspace-equivalent, runs in kernel mode for now).
//!
//! Session model:
//!   Thread 0 (main kthread) — network poll loop, accepts SSH connections,
//!             spawns one kthread per session, handles local VGA keyboard.
//!   Threads 1-4 (SSH kthreads) — each runs an independent run_ssh_session()
//!             loop with its own ShellEnv, LineEditor, and SshIo(idx).

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
    fn write_byte(&mut self, b: u8)      { crate::drivers::display::vga::write(&[b]); }
    fn write_bytes(&mut self, s: &[u8])  { crate::drivers::display::vga::write(s); }
    fn read_byte(&mut self) -> Option<u8> { crate::drivers::char::keyboard::read_byte() }
    fn read_byte_blocking(&mut self) -> u8 {
        loop {
            crate::kernel::net::poll_drivers();
            crate::kernel::net::ssh::poll();
            // Spawn SSH threads while waiting for local keyboard
            check_and_spawn_ssh();
            if let Some(b) = self.read_byte() { return b; }
            // Yield so SSH session threads get CPU time
            crate::kernel::kthread::yield_now();
        }
    }
    fn clear_screen(&mut self)            { crate::drivers::display::vga::clear(); }
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

// ── SSH output buffer (batches TUI redraws into a few large TCP writes) ──────
// Without batching, htop sends 300+ tiny SSH packets per redraw → tcp_write
// failures corrupt the AES-CTR stream → arrow keys/session breaks.

const SSH_OUT_BUF_SIZE: usize = 16384; // 16 KB per session (4 sessions = 64 KB BSS)
static mut SSH_OUT_BUF: [[u8; SSH_OUT_BUF_SIZE]; 4] = [[0; SSH_OUT_BUF_SIZE]; 4];
static mut SSH_OUT_LEN: [usize; 4] = [0; 4];

fn ssh_out_push(idx: usize, data: &[u8]) {
    unsafe {
        let len = &mut SSH_OUT_LEN[idx];
        let available = SSH_OUT_BUF_SIZE.saturating_sub(*len);
        let n = data.len().min(available);
        SSH_OUT_BUF[idx][*len..*len + n].copy_from_slice(&data[..n]);
        *len += n;
    }
}

/// Flush the per-session output buffer to TCP in ≤1400-byte SSH channel chunks.
fn ssh_out_flush(idx: usize) {
    unsafe {
        let len = SSH_OUT_LEN[idx];
        if len == 0 { return; }
        let mut off = 0;
        while off < len {
            let chunk = (len - off).min(1400);
            crate::kernel::net::ssh::send_to_session(idx, &SSH_OUT_BUF[idx][off..off + chunk]);
            off += chunk;
        }
        SSH_OUT_LEN[idx] = 0;
    }
}

// ── ANSI helpers for SSH full-screen rendering ────────────────────────────────

// VGA color order: 0=Black,1=Blue,2=Green,3=Cyan,4=Red,5=Magenta,6=Brown,7=LightGray
// Maps VGA nibble → ANSI color index (0-7)
const VGA_TO_ANSI: [u8; 8] = [0, 4, 2, 6, 1, 5, 3, 7];

/// Write a u16 in decimal into buf. Returns bytes written.
fn ansi_u16(buf: &mut [u8], mut n: u16) -> usize {
    if buf.is_empty() { return 0; }
    if n == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 5];
    let mut len = 0;
    while n > 0 { tmp[len] = b'0' + (n % 10) as u8; n /= 10; len += 1; }
    let out = len.min(buf.len());
    for i in 0..out { buf[i] = tmp[len - 1 - i]; }
    out
}

/// Build `ESC[row+1;col+1H ESC[fg;bgm` into a 24-byte buffer.
/// Returns number of bytes written.
fn build_ansi_hdr(buf: &mut [u8; 24], col: u16, row: u16, color: u8) -> usize {
    let mut n = 0usize;
    // Cursor position: ESC[row;colH
    buf[n] = 0x1b; n += 1;
    buf[n] = b'['; n += 1;
    n += ansi_u16(&mut buf[n..], row + 1);
    buf[n] = b';'; n += 1;
    n += ansi_u16(&mut buf[n..], col + 1);
    buf[n] = b'H'; n += 1;
    // Color: ESC[fg;bgm
    let fg_vga  = color & 0x0F;
    let bg_vga  = (color >> 4) & 0x0F;
    let fg_ansi = VGA_TO_ANSI[(fg_vga & 7) as usize];
    let bg_ansi = VGA_TO_ANSI[(bg_vga & 7) as usize];
    let fg_code = if fg_vga >= 8 { 90 + fg_ansi as u16 } else { 30 + fg_ansi as u16 };
    let bg_code = if bg_vga >= 8 { 100 + bg_ansi as u16 } else { 40 + bg_ansi as u16 };
    buf[n] = 0x1b; n += 1;
    buf[n] = b'['; n += 1;
    n += ansi_u16(&mut buf[n..], fg_code);
    buf[n] = b';'; n += 1;
    n += ansi_u16(&mut buf[n..], bg_code);
    buf[n] = b'm'; n += 1;
    n
}

/// SSH I/O backend — one per session index.
struct SshIo(usize);

impl ShellIo for SshIo {
    fn write_byte(&mut self, b: u8) {
        crate::kernel::net::ssh::send_to_session(self.0, &[b]);
    }
    fn write_bytes(&mut self, s: &[u8]) {
        if !s.is_empty() {
            crate::kernel::net::ssh::send_to_session(self.0, s);
        }
    }
    fn read_byte(&mut self) -> Option<u8> {
        use crate::drivers::char::keyboard::*;
        // Drive the network stack so data is received and buffered
        crate::kernel::net::poll_drivers();
        crate::kernel::net::ssh::poll();
        let b = crate::kernel::net::ssh::pop_input_from(self.0)?;
        if b != 0x1b { return Some(b); }

        // Translate ANSI/VT escape sequences → VGA KEY_* constants.
        // Use explicit idx capture (not closure) to avoid borrow issues.
        // After ESC, poll once more to ensure remaining bytes are buffered.
        crate::kernel::net::ssh::poll();
        let idx = self.0;
        macro_rules! pop {
            () => { crate::kernel::net::ssh::pop_input_from(idx) }
        }
        match pop!() {
            Some(b'[') => match pop!() {            // CSI sequences
                Some(b'A') => Some(KEY_UP),
                Some(b'B') => Some(KEY_DOWN),
                Some(b'C') => Some(KEY_RIGHT),
                Some(b'D') => Some(KEY_LEFT),
                Some(b'H') => Some(KEY_HOME),
                Some(b'F') => Some(KEY_END),
                Some(b'1') => match pop!() {
                    Some(b'~') => Some(KEY_HOME),
                    Some(b'7') => { let _ = pop!(); Some(KEY_F6)  }
                    Some(b'8') => { let _ = pop!(); Some(KEY_F7)  }
                    Some(b'9') => { let _ = pop!(); Some(KEY_F8)  }
                    _ => Some(0x1b),
                },
                Some(b'2') => match pop!() {
                    Some(b'~') => Some(KEY_INS),
                    Some(b'0') => { let _ = pop!(); Some(KEY_F9)  }
                    Some(b'1') => { let _ = pop!(); Some(KEY_F10) }
                    _ => Some(0x1b),
                },
                Some(b'3') => { let _ = pop!(); Some(KEY_DEL)  }
                Some(b'4') => { let _ = pop!(); Some(KEY_END)  }
                Some(b'5') => { let _ = pop!(); Some(KEY_PGUP) }
                Some(b'6') => { let _ = pop!(); Some(KEY_PGDN) }
                _ => Some(0x1b),
            },
            Some(b'O') => match pop!() {            // SS3: arrows (app mode) + F1-F4
                Some(b'A') => Some(KEY_UP),          // \x1bOA = up   (DECCKM)
                Some(b'B') => Some(KEY_DOWN),        // \x1bOB = down
                Some(b'C') => Some(KEY_RIGHT),       // \x1bOC = right
                Some(b'D') => Some(KEY_LEFT),        // \x1bOD = left
                Some(b'H') => Some(KEY_HOME),
                Some(b'F') => Some(KEY_END),
                Some(b'P') => Some(KEY_F1),
                Some(b'Q') => Some(KEY_F2),
                Some(b'R') => Some(KEY_F3),
                Some(b'S') => Some(KEY_F4),
                _ => Some(0x1b),
            },
            _ => Some(0x1b),                        // lone ESC
        }
    }
    fn read_byte_blocking(&mut self) -> u8 {
        loop {
            if let Some(b) = self.read_byte() { return b; }
            if !crate::kernel::net::ssh::session_is_active(self.0) {
                return 0; // sentinel: session closed
            }
            // While waiting for input, check if new SSH sessions arrived and
            // spawn their kthreads — otherwise they never get served while
            // this thread holds the CPU between yields.
            check_and_spawn_ssh();
            // Yield to other threads (main thread, other SSH sessions)
            crate::kernel::kthread::yield_now();
        }
    }
    fn clear_screen(&mut self) {
        crate::kernel::net::ssh::send_to_session(self.0, b"\x1b[2J\x1b[H");
    }
    fn newline(&mut self) {
        crate::kernel::net::ssh::send_to_session(self.0, b"\r\n");
    }

    fn put_char_at(&mut self, col: u16, row: u16, ch: u8, color: u8) {
        let mut hdr = [0u8; 24];
        let hn = build_ansi_hdr(&mut hdr, col, row, color);
        ssh_out_push(self.0, &hdr[..hn]);
        ssh_out_push(self.0, &[ch]);
        ssh_out_push(self.0, b"\x1b[0m");
    }

    fn write_at(&mut self, col: u16, row: u16, s: &[u8], color: u8) {
        if s.is_empty() { return; }
        let mut hdr = [0u8; 24];
        let hn = build_ansi_hdr(&mut hdr, col, row, color);
        ssh_out_push(self.0, &hdr[..hn]);
        ssh_out_push(self.0, s);
        ssh_out_push(self.0, b"\x1b[0m");
    }

    fn fill_row(&mut self, row: u16, ch: u8, color: u8) {
        let cols = self.screen_cols() as usize;
        let mut hdr = [0u8; 24];
        let hn = build_ansi_hdr(&mut hdr, 0, row, color);
        ssh_out_push(self.0, &hdr[..hn]);
        let chunk = [ch; 64];
        let mut sent = 0;
        while sent < cols {
            let n = (cols - sent).min(64);
            ssh_out_push(self.0, &chunk[..n]);
            sent += n;
        }
        ssh_out_push(self.0, b"\x1b[0m");
    }

    fn move_cursor(&mut self, col: u16, row: u16) {
        let mut buf = [0u8; 16];
        let mut n = 0usize;
        buf[n] = 0x1b; n += 1;
        buf[n] = b'['; n += 1;
        n += ansi_u16(&mut buf[n..], row + 1);
        buf[n] = b';'; n += 1;
        n += ansi_u16(&mut buf[n..], col + 1);
        buf[n] = b'H'; n += 1;
        ssh_out_push(self.0, &buf[..n]);
    }

    fn flush_output(&mut self) {
        ssh_out_flush(self.0);
    }

    fn enter_altscreen(&mut self) {
        // Switch to alternate screen buffer and hide cursor
        crate::kernel::net::ssh::send_to_session(self.0, b"\x1b[?1049h\x1b[?25l");
    }

    fn exit_altscreen(&mut self) {
        // Restore main screen buffer and show cursor
        crate::kernel::net::ssh::send_to_session(self.0, b"\x1b[?1049l\x1b[?25h");
    }

    fn screen_cols(&self) -> u16 {
        crate::kernel::net::ssh::term_cols_for(self.0) as u16
    }

    fn screen_rows(&self) -> u16 {
        crate::kernel::net::ssh::term_rows_for(self.0) as u16
    }
}

// ── Login ─────────────────────────────────────────────────────────────────────

fn do_login(io: &mut dyn ShellIo) -> ShellEnv {
    let mut env = ShellEnv::new();
    loop {
        io.write_bytes(b"fastros login: ");
        let mut uname_buf = [0u8; 32];
        let ulen = read_line_simple(io, &mut uname_buf);
        if ulen == 0 { continue; }
        let username = &uname_buf[..ulen];
        io.write_bytes(b"Password: ");
        let mut pw = [0u8; 64];
        let plen = read_secret(io, &mut pw);
        if crate::kernel::users::verify(username, &pw[..plen]) {
            if let Some((uid, gid, home, hl)) = crate::kernel::users::lookup_user(username) {
                env.set_session(uid, gid, &home[..hl], username);
                print_motd(io);
                return env;
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

fn build_prompt(env: &ShellEnv, buf: &mut [u8; 256]) -> usize {
    let mut n = 0;
    macro_rules! push {
        ($s:expr) => { for &b in $s.iter() { if n < 255 { buf[n] = b; n += 1; } } }
    }
    push!(env.username());
    push!(b"@fastros:");
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
    if env.is_root() { push!(b"# "); } else { push!(b"$ "); }
    n
}

// ── SSH session management ────────────────────────────────────────────────────

/// One global CommandRegistry shared (read-only) by all sessions.
static mut REGISTRY: Option<CommandRegistry> = None;

/// Per-session kthread id (None = no thread spawned for this session slot yet).
static mut SESSION_THREADS: [Option<usize>; 4] = [None; 4];

/// Called from both the main loop and from VgaKeyboardIo::read_byte_blocking.
/// Spawns a new kthread for any SSH session that has reached ShellActive and
/// doesn't already have a thread.
fn check_and_spawn_ssh() {
    use crate::kernel::net::ssh::MAX_SESSIONS;
    for i in 0..MAX_SESSIONS {
        unsafe {
            let active = crate::kernel::net::ssh::session_is_active(i);
            if active && SESSION_THREADS[i].is_none() {
                if let Some(tid) = crate::kernel::kthread::spawn(ssh_session_thread, i) {
                    SESSION_THREADS[i] = Some(tid);
                    crate::drivers::char::serial::write(b"  shell: spawned kthread for ssh session ");
                    crate::drivers::char::serial::write_byte(b'0' + i as u8);
                    crate::drivers::char::serial::write(b" (kthread ");
                    crate::drivers::char::serial::write_byte(b'0' + tid as u8);
                    crate::drivers::char::serial::write(b")\n");
                }
            } else if !active && SESSION_THREADS[i].is_some() {
                SESSION_THREADS[i] = None;
            }
        }
    }
}

/// Entry point for each SSH session kthread. Called with the session index.
fn ssh_session_thread(idx: usize) {
    // Safety: REGISTRY is written once before any kthread is spawned.
    let registry = unsafe { REGISTRY.as_ref().unwrap() };
    run_ssh_session(registry, idx);
    // Clear our slot so the session can be reused
    unsafe { SESSION_THREADS[idx] = None; }
    // kthread_trampoline calls do_schedule() → this kthread is freed
}

// ── REPL entry points ─────────────────────────────────────────────────────────

pub fn run() -> ! {
    let registry = CommandRegistry::init();
    unsafe { REGISTRY = Some(registry); }

    // Main loop (kthread 0): poll network, spawn SSH kthreads, handle local keyboard.
    // SSH session kthreads run independently via yield_now() inside SshIo.
    loop {
        crate::kernel::net::poll_drivers();
        crate::kernel::net::ssh::poll();

        check_and_spawn_ssh();

        // If a local key is pressed, start the VGA session.
        // VgaKeyboardIo::read_byte_blocking() yields to SSH kthreads while
        // waiting for keyboard input, so SSH sessions keep running.
        if crate::drivers::char::keyboard::read_byte().is_some() {
            let registry = unsafe { REGISTRY.as_ref().unwrap() };
            run_local_session(registry);
        }

        // Yield to SSH session kthreads
        crate::kernel::kthread::yield_now();
    }
}

/// Run one SSH shell session (identified by session index).
/// Returns when the client disconnects.
fn run_ssh_session(registry: &CommandRegistry, idx: usize) {
    let mut io  = SshIo(idx);
    let mut env = ShellEnv::new();
    env.set_session(0, 0, b"/root", b"root");

    io.write_bytes(b"\r\nFastROS SSH shell\r\nType 'help' for available commands.\r\n\r\n");

    let mut editor = LineEditor::new();

    loop {
        if !crate::kernel::net::ssh::session_is_active(idx) { break; }

        let mut prompt_buf = [0u8; 256];
        let prompt_len = build_prompt(&env, &mut prompt_buf);
        let prompt = &prompt_buf[..prompt_len];
        io.write_bytes(prompt);

        let line = editor.read_line(&mut io, prompt, env.cwd());

        if !crate::kernel::net::ssh::session_is_active(idx) { break; }
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
                io.write_byte(c);
            }
            _ => {}
        }
    }
    n
}

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
