//! FastROS interactive shell
//!
//! Layer position: Layer 5 (userspace-equivalent, runs in kernel mode for now).
//! This module is the ONLY place that wires together:
//!   • Concrete I/O  (VGA + keyboard → ShellIo impl)
//!   • CommandRegistry (statically initialized)
//!   • LineEditor     (readline)
//!   • Parser         (token splitting)
//!   • Executor       (command dispatch)
//!   • ShellEnv       (CWD, exit code)
//!
//! Clean Architecture dependency flow (all arrows point inward):
//!
//!   VGA / Keyboard
//!        │
//!        ▼
//!   VgaKeyboardIo  ──implements──▶  ShellIo (trait)
//!                                        │
//!   CommandRegistry ◀── init ────  mod.rs (run)
//!   LineEditor       ◀── new  ────     │
//!   ShellEnv         ◀── new  ────     │
//!        │                            │
//!        └─────────── REPL loop ──────┘
//!                         │
//!                    parser::parse
//!                         │
//!                   executor::execute
//!                         │
//!               Command::execute (trait call)

pub mod command;
pub mod completion;
pub mod env;
pub mod executor;
pub mod history;
pub mod io;
pub mod memfs;
pub mod parser;
pub mod readline;

use command::CommandRegistry;
use env::ShellEnv;
use io::ShellIo;
use readline::LineEditor;

// ── Concrete I/O implementation ───────────────────────────────────────────────

/// Bridges VGA (output) and the PS/2 keyboard driver (input) to `ShellIo`.
/// This is the ONLY place in the shell that imports drivers directly.
struct VgaKeyboardIo;

impl ShellIo for VgaKeyboardIo {
    fn write_byte(&mut self, b: u8) {
        crate::drivers::display::vga::write(&[b]);
    }

    fn write_bytes(&mut self, s: &[u8]) {
        crate::drivers::display::vga::write(s);
    }

    fn read_byte(&mut self) -> Option<u8> {
        crate::drivers::char::keyboard::read_byte()
    }

    fn clear_screen(&mut self) {
        crate::drivers::display::vga::clear();
    }

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

// ── Shell banner ──────────────────────────────────────────────────────────────

fn print_banner(io: &mut dyn ShellIo) {
    io.write_bytes(b"\n");
    io.write_bytes(b"  FastROS Shell  v0.1.0\n");
    io.write_bytes(b"  Type 'help' for a list of commands.\n");
    io.write_bytes(b"\n");
}

// ── Prompt ────────────────────────────────────────────────────────────────────

/// Build "root@fastros:cwd# " into `buf`. Returns the prompt length.
/// Uses `~` when cwd is /root or a subdirectory of /root.
fn build_prompt(env: &ShellEnv, buf: &mut [u8; 256]) -> usize {
    let mut n = 0;
    macro_rules! push_bytes {
        ($s:expr) => {
            for &b in $s.iter() { if n < 256 { buf[n] = b; n += 1; } }
        }
    }
    push_bytes!(b"root@fastros:");
    let cwd = env.cwd();
    if cwd == b"/root" {
        push_bytes!(b"~");
    } else if cwd.len() > 6 && cwd.starts_with(b"/root/") {
        push_bytes!(b"~/");
        push_bytes!(&cwd[6..]);
    } else {
        push_bytes!(cwd);
    }
    push_bytes!(b"# ");
    n
}

// ── REPL entry point ──────────────────────────────────────────────────────────

/// Run the shell.  Never returns.
pub fn run() -> ! {
    let mut io       = VgaKeyboardIo;
    let mut env      = ShellEnv::new();
    let mut editor   = LineEditor::new();
    let     registry = CommandRegistry::init();

    print_banner(&mut io);

    loop {
        // Build and print prompt, then hand it to readline for redraws
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
