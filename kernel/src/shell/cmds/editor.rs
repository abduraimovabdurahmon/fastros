//! `nano` — a small full-screen text editor.
//!
//! A minimal but genuinely usable nano clone: open a file (or start empty),
//! edit on a raw terminal with arrow keys, insert/delete, and save. It degrades
//! to an error when stdout is not a terminal. Modeled on the pager's raw-mode
//! terminal handling.

use crate::errno::Errno;
use crate::shell::ctx::Ctx;
use crate::tty::{consts, Tty};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// A key decoded from the terminal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Char(u8),
    Enter,
    Backspace,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Ctrl(u8),
    Timeout,
    Hangup,
}

/// The terminal in raw mode; restores the saved settings on drop.
struct Term {
    tty: Arc<Tty>,
    saved: crate::tty::Termios,
}

impl Term {
    fn open(tty: Arc<Tty>) -> Term {
        let saved = tty.termios();
        let mut raw = saved;
        raw.lflag &= !(consts::ICANON | consts::ECHO | consts::ISIG | consts::IEXTEN);
        raw.iflag &= !(consts::IXON | consts::ICRNL);
        raw.oflag &= !consts::OPOST;
        raw.cc[consts::VMIN] = 0;
        raw.cc[consts::VTIME] = 2;
        tty.set_termios(raw);
        Term { tty, saved }
    }

    fn size(&self) -> (usize, usize) {
        let ws = self.tty.winsize();
        let cols = if ws.cols == 0 { 80 } else { ws.cols as usize };
        let rows = if ws.rows == 0 { 24 } else { ws.rows as usize };
        (cols.max(20), rows.max(4))
    }

    fn write(&self, s: &str) {
        let _ = self.tty.write(s.as_bytes());
    }

    fn byte(&self, wait: bool) -> Option<u8> {
        let mut b = [0u8; 1];
        loop {
            match self.tty.read(&mut b, false) {
                Ok(1) => return Some(b[0]),
                Ok(_) => {
                    if self.tty.is_hung_up() || !wait {
                        return None;
                    }
                }
                Err(Errno::EINTR) => crate::sched::with_current(|t| t.clear_signals()),
                Err(_) => return None,
            }
        }
    }

    fn key(&self) -> Key {
        let Some(b) = self.byte(false) else {
            return if self.tty.is_hung_up() { Key::Hangup } else { Key::Timeout };
        };
        match b {
            b'\r' | b'\n' => Key::Enter,
            0x7f | 0x08 => Key::Backspace,
            0x1b => self.escape(),
            c if c < 0x20 => Key::Ctrl(c),
            c => Key::Char(c),
        }
    }

    fn escape(&self) -> Key {
        match self.byte(false) {
            Some(b'[') => {
                let mut params = Vec::new();
                loop {
                    let Some(c) = self.byte(false) else { return Key::Timeout };
                    if (0x40..=0x7e).contains(&c) {
                        return match (params.as_slice(), c) {
                            (b"", b'A') => Key::Up,
                            (b"", b'B') => Key::Down,
                            (b"", b'C') => Key::Right,
                            (b"", b'D') => Key::Left,
                            (b"5", b'~') => Key::PageUp,
                            (b"6", b'~') => Key::PageDown,
                            (b"", b'H') | (b"1", b'~') | (b"7", b'~') => Key::Home,
                            (b"", b'F') | (b"4", b'~') | (b"8", b'~') => Key::End,
                            (b"3", b'~') => Key::Ctrl(4), // Delete → act like ^D (delete forward)
                            _ => Key::Timeout,
                        };
                    }
                    params.push(c);
                    if params.len() > 8 {
                        return Key::Timeout;
                    }
                }
            }
            Some(b'O') => match self.byte(false) {
                Some(b'A') => Key::Up,
                Some(b'B') => Key::Down,
                Some(b'C') => Key::Right,
                Some(b'D') => Key::Left,
                Some(b'H') => Key::Home,
                Some(b'F') => Key::End,
                _ => Key::Timeout,
            },
            _ => Key::Timeout,
        }
    }

    /// Prompt on the status row and read a line (Enter=confirm, ^C/Esc=cancel).
    fn prompt(&self, rows: usize, cols: usize, msg: &str, seed: &str) -> Option<String> {
        let mut s = seed.to_string();
        loop {
            let shown = format!("{msg}{s}");
            let shown: String = shown.chars().take(cols).collect();
            self.write(&format!("\x1b[{rows};1H\x1b[K\x1b[7m{shown}\x1b[m"));
            match self.byte(true)? {
                b'\r' | b'\n' => return Some(s),
                0x1b | 0x03 => return None,
                0x7f | 0x08 => {
                    s.pop();
                }
                c if c >= 0x20 => s.push(c as char),
                _ => {}
            }
        }
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        self.tty.set_termios(self.saved);
    }
}

/// The editor buffer and cursor.
struct Editor {
    lines: Vec<String>,
    name: String,
    cx: usize, // column (byte index within the line, ASCII assumed for movement)
    cy: usize, // line index
    top: usize, // first visible line
    modified: bool,
    status: String,
}

impl Editor {
    fn new(name: String, text: &str) -> Editor {
        let mut lines: Vec<String> = text.split('\n').map(|l| l.trim_end_matches('\r').to_string()).collect();
        // A file ending in '\n' splits into a trailing "" — drop it so we don't
        // show a phantom blank line, but keep at least one line to edit.
        if lines.len() > 1 && lines.last().map(|l| l.is_empty()).unwrap_or(false) {
            lines.pop();
        }
        if lines.is_empty() {
            lines.push(String::new());
        }
        Editor { lines, name, cx: 0, cy: 0, top: 0, modified: false, status: String::new() }
    }

    fn line_len(&self, y: usize) -> usize {
        self.lines.get(y).map(|l| l.len()).unwrap_or(0)
    }

    fn clamp_cx(&mut self) {
        self.cx = self.cx.min(self.line_len(self.cy));
    }

    fn insert_char(&mut self, c: char) {
        let line = &mut self.lines[self.cy];
        let at = self.cx.min(line.len());
        line.insert(at, c);
        self.cx = at + 1;
        self.modified = true;
    }

    fn insert_newline(&mut self) {
        let line = &mut self.lines[self.cy];
        let at = self.cx.min(line.len());
        let rest = line.split_off(at);
        self.lines.insert(self.cy + 1, rest);
        self.cy += 1;
        self.cx = 0;
        self.modified = true;
    }

    fn backspace(&mut self) {
        if self.cx > 0 {
            let line = &mut self.lines[self.cy];
            line.remove(self.cx - 1);
            self.cx -= 1;
            self.modified = true;
        } else if self.cy > 0 {
            // Join with the previous line.
            let cur = self.lines.remove(self.cy);
            self.cy -= 1;
            self.cx = self.line_len(self.cy);
            self.lines[self.cy].push_str(&cur);
            self.modified = true;
        }
    }

    fn delete_forward(&mut self) {
        let len = self.line_len(self.cy);
        if self.cx < len {
            self.lines[self.cy].remove(self.cx);
            self.modified = true;
        } else if self.cy + 1 < self.lines.len() {
            let next = self.lines.remove(self.cy + 1);
            self.lines[self.cy].push_str(&next);
            self.modified = true;
        }
    }

    fn cut_line(&mut self) {
        if self.lines.len() == 1 {
            self.lines[0].clear();
        } else {
            self.lines.remove(self.cy);
            if self.cy >= self.lines.len() {
                self.cy = self.lines.len() - 1;
            }
        }
        self.cx = 0;
        self.modified = true;
    }

    fn text(&self) -> String {
        let mut s = self.lines.join("\n");
        s.push('\n');
        s
    }
}

/// `nano [FILE]` — edit a file on the terminal.
pub fn nano(ctx: &mut Ctx) -> i32 {
    let name = ctx.args.iter().skip(1).find(|a| !a.starts_with('-')).cloned();
    let Some(tty) = ctx.stdout_tty() else {
        ctx.eprint("nano: standard output is not a terminal\n");
        return 1;
    };
    // Load the file if it exists; a missing file starts an empty "new" buffer.
    let (fname, text) = match &name {
        Some(n) => match crate::fs::ops::read_file(&ctx.fs(), n) {
            Ok(d) => (n.clone(), String::from_utf8_lossy(&d).into_owned()),
            Err(Errno::ENOENT) => (n.clone(), String::new()),
            Err(e) => {
                ctx.eprint(&format!("nano: {n}: {e}\n"));
                return 1;
            }
        },
        None => (String::from("Untitled"), String::new()),
    };
    let mut ed = Editor::new(fname, &text);
    if name.is_none() || text.is_empty() {
        ed.status = String::from("New Buffer");
    }
    ctx.flush();
    let term = Term::open(tty);
    term.write("\x1b[?1049h"); // alternate screen
    let code = run(ctx, &term, &mut ed);
    term.write("\x1b[?1049l"); // restore screen
    code
}

fn run(ctx: &mut Ctx, term: &Term, ed: &mut Editor) -> i32 {
    loop {
        let (cols, rows) = term.size();
        draw(term, ed, cols, rows);
        match term.key() {
            Key::Timeout => {
                if !crate::sched::sleep_ms(20) {
                    crate::sched::with_current(|t| t.clear_signals());
                }
            }
            Key::Hangup => return 0,
            Key::Char(c) => {
                ed.insert_char(c as char);
                ed.status.clear();
            }
            Key::Enter => {
                ed.insert_newline();
                ed.status.clear();
            }
            Key::Backspace => ed.backspace(),
            Key::Up => {
                if ed.cy > 0 {
                    ed.cy -= 1;
                    ed.clamp_cx();
                }
            }
            Key::Down => {
                if ed.cy + 1 < ed.lines.len() {
                    ed.cy += 1;
                    ed.clamp_cx();
                }
            }
            Key::Left => {
                if ed.cx > 0 {
                    ed.cx -= 1;
                } else if ed.cy > 0 {
                    ed.cy -= 1;
                    ed.cx = ed.line_len(ed.cy);
                }
            }
            Key::Right => {
                if ed.cx < ed.line_len(ed.cy) {
                    ed.cx += 1;
                } else if ed.cy + 1 < ed.lines.len() {
                    ed.cy += 1;
                    ed.cx = 0;
                }
            }
            Key::Home => ed.cx = 0,
            Key::End => ed.cx = ed.line_len(ed.cy),
            Key::PageUp => {
                let page = rows.saturating_sub(3);
                ed.cy = ed.cy.saturating_sub(page);
                ed.clamp_cx();
            }
            Key::PageDown => {
                let page = rows.saturating_sub(3);
                ed.cy = (ed.cy + page).min(ed.lines.len() - 1);
                ed.clamp_cx();
            }
            Key::Ctrl(4) => ed.delete_forward(), // ^D / Delete
            Key::Ctrl(11) => ed.cut_line(),      // ^K
            Key::Ctrl(1) => ed.cx = 0,           // ^A
            Key::Ctrl(5) => ed.cx = ed.line_len(ed.cy), // ^E
            Key::Ctrl(15) => save(ctx, term, ed, cols, rows), // ^O
            Key::Ctrl(24) => {
                // ^X: quit, offering to save a modified buffer.
                if ed.modified {
                    match term.prompt(rows, cols, "Save modified buffer? (Y/N) ", "") {
                        Some(a) if a.starts_with(['y', 'Y']) => {
                            save(ctx, term, ed, cols, rows);
                            return 0;
                        }
                        Some(a) if a.starts_with(['n', 'N']) => return 0,
                        _ => {} // cancelled
                    }
                } else {
                    return 0;
                }
            }
            Key::Ctrl(_) => {}
        }
    }
}

fn save(ctx: &mut Ctx, term: &Term, ed: &mut Editor, cols: usize, rows: usize) {
    let target = if ed.name == "Untitled" {
        match term.prompt(rows, cols, "File Name to Write: ", "") {
            Some(n) if !n.is_empty() => n,
            _ => {
                ed.status = String::from("Cancelled");
                return;
            }
        }
    } else {
        ed.name.clone()
    };
    match crate::fs::ops::write_file(&ctx.fs(), &target, ed.text().as_bytes(), 0o644) {
        Ok(()) => {
            ed.name = target;
            ed.modified = false;
            ed.status = format!("Wrote {} line{}", ed.lines.len(), if ed.lines.len() == 1 { "" } else { "s" });
        }
        Err(e) => ed.status = format!("Error writing: {e}"),
    }
}

fn draw(term: &Term, ed: &mut Editor, cols: usize, rows: usize) {
    let text_rows = rows.saturating_sub(2); // title + status/help
    // Keep the cursor line in view.
    if ed.cy < ed.top {
        ed.top = ed.cy;
    } else if ed.cy >= ed.top + text_rows {
        ed.top = ed.cy + 1 - text_rows;
    }

    let mut out = String::from("\x1b[H\x1b[2J");
    // Title bar (inverse).
    let title = format!("  nano  —  {}{}", ed.name, if ed.modified { " *" } else { "" });
    let title: String = pad(&title, cols);
    out.push_str(&format!("\x1b[7m{title}\x1b[m\r\n"));

    for r in 0..text_rows {
        let ly = ed.top + r;
        if let Some(line) = ed.lines.get(ly) {
            let shown: String = line.chars().take(cols).collect();
            out.push_str(&shown);
        } else {
            out.push('~');
        }
        out.push_str("\r\n");
    }

    // Status / shortcut line.
    if !ed.status.is_empty() {
        let s: String = pad(&format!("[ {} ]", ed.status), cols);
        out.push_str(&format!("\x1b[7m{s}\x1b[m"));
    } else {
        out.push_str("^O Save   ^X Exit   ^K Cut   ^A Home   ^E End");
    }

    // Position the hardware cursor.
    let scr_row = 2 + (ed.cy - ed.top); // 1-based; +1 for the title bar
    let scr_col = ed.cx.min(cols.saturating_sub(1)) + 1;
    out.push_str(&format!("\x1b[{scr_row};{scr_col}H"));
    term.write(&out);
}

fn pad(s: &str, cols: usize) -> String {
    let mut t: String = s.chars().take(cols).collect();
    let len = t.chars().count();
    if len < cols {
        t.push_str(&" ".repeat(cols - len));
    }
    t
}
