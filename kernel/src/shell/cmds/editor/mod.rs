//! Terminal text editors: `nano` (simple) and `vim` (modal). Both share the
//! raw-terminal handling here (`Term` + key decoding), modeled on the pager.

mod nano;
mod vim;

pub use nano::nano;
pub use vim::vim;

use crate::errno::Errno;
use crate::tty::{consts, Tty};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// A key decoded from the terminal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Key {
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
    Esc,
    Timeout,
    Hangup,
}

/// The terminal in raw mode; restores the saved settings on drop.
pub(super) struct Term {
    tty: Arc<Tty>,
    saved: crate::tty::Termios,
    /// A byte read past a lone ESC (not part of an escape sequence) is stored
    /// here so the next read returns it instead of losing it — so `ESC :wq`
    /// keeps its `:`.
    pushback: core::cell::Cell<Option<u8>>,
}

impl Term {
    pub(super) fn open(tty: Arc<Tty>) -> Term {
        let saved = tty.termios();
        let mut raw = saved;
        raw.lflag &= !(consts::ICANON | consts::ECHO | consts::ISIG | consts::IEXTEN);
        raw.iflag &= !(consts::IXON | consts::ICRNL);
        raw.oflag &= !consts::OPOST;
        raw.cc[consts::VMIN] = 0;
        raw.cc[consts::VTIME] = 2;
        tty.set_termios(raw);
        Term { tty, saved, pushback: core::cell::Cell::new(None) }
    }

    pub(super) fn size(&self) -> (usize, usize) {
        let ws = self.tty.winsize();
        let cols = if ws.cols == 0 { 80 } else { ws.cols as usize };
        let rows = if ws.rows == 0 { 24 } else { ws.rows as usize };
        (cols.max(20), rows.max(4))
    }

    pub(super) fn write(&self, s: &str) {
        let _ = self.tty.write(s.as_bytes());
    }

    fn byte(&self, wait: bool) -> Option<u8> {
        if let Some(b) = self.pushback.take() {
            return Some(b);
        }
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

    pub(super) fn key(&self) -> Key {
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
            None => Key::Esc, // a lone ESC
            Some(b'[') => {
                let mut params = Vec::new();
                loop {
                    let Some(c) = self.byte(false) else { return Key::Esc };
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
                            (b"3", b'~') => Key::Ctrl(4), // Delete → ^D (delete forward)
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
            // A byte after ESC that is not a CSI/SS3 introducer: this was a lone
            // ESC and a following key. Keep ESC's meaning and re-queue the byte.
            Some(b) => {
                self.pushback.set(Some(b));
                Key::Esc
            }
        }
    }

    /// Prompt on `row` (inverse video) and read a line. Enter confirms; ESC/^C
    /// cancels (returns None). Backspace on an empty line also cancels.
    pub(super) fn prompt(&self, row: usize, cols: usize, msg: &str, seed: &str) -> Option<String> {
        let mut s = seed.to_string();
        loop {
            let shown: String = format!("{msg}{s}").chars().take(cols).collect();
            self.write(&format!("\x1b[{row};1H\x1b[K{shown}"));
            match self.byte(true)? {
                b'\r' | b'\n' => return Some(s),
                0x1b | 0x03 => return None,
                0x7f | 0x08 => {
                    if s.is_empty() {
                        return None;
                    }
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

/// A shared text buffer with cursor + scroll — the common core of both editors.
pub(super) struct Buffer {
    pub lines: Vec<String>,
    pub name: String,
    pub cx: usize,
    pub cy: usize,
    pub top: usize,
    pub modified: bool,
}

impl Buffer {
    pub(super) fn from_text(name: String, text: &str) -> Buffer {
        let mut lines: Vec<String> = text.split('\n').map(|l| l.trim_end_matches('\r').to_string()).collect();
        if lines.len() > 1 && lines.last().map(|l| l.is_empty()).unwrap_or(false) {
            lines.pop();
        }
        if lines.is_empty() {
            lines.push(String::new());
        }
        Buffer { lines, name, cx: 0, cy: 0, top: 0, modified: false }
    }

    pub(super) fn line_len(&self, y: usize) -> usize {
        self.lines.get(y).map(|l| l.len()).unwrap_or(0)
    }

    pub(super) fn clamp_cx(&mut self) {
        self.cx = self.cx.min(self.line_len(self.cy));
    }

    pub(super) fn text(&self) -> String {
        let mut s = self.lines.join("\n");
        s.push('\n');
        s
    }
}

/// Load a file into text; a missing file yields an empty new buffer.
pub(super) fn load_file(ctx: &crate::shell::ctx::Ctx, name: &str) -> Result<String, Errno> {
    match crate::fs::ops::read_file(&ctx.fs(), name) {
        Ok(d) => Ok(String::from_utf8_lossy(&d).into_owned()),
        Err(Errno::ENOENT) => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// Truncate/pad `s` to exactly `cols` visible columns.
pub(super) fn pad(s: &str, cols: usize) -> String {
    let mut t: String = s.chars().take(cols).collect();
    let len = t.chars().count();
    if len < cols {
        t.push_str(&" ".repeat(cols - len));
    }
    t
}
