//! Full-screen terminal programs (top, htop, pagers): raw mode with a
//! guaranteed restore, key decoding (xterm/vt220 sequences) with timeouts,
//! and a screen buffer that only re-sends the lines that changed — which
//! keeps redraws cheap over SSH.

use crate::errno::Errno;
use crate::tty::{consts, Termios, Tty};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Ctrl(char),
    Enter,
    Esc,
    Tab,
    Backspace,
    Delete,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    F(u8),
    /// An unrecognized sequence.
    Unknown,
}

/// The terminal in raw mode on the alternate screen; dropping it restores
/// the previous settings and screen, whatever path the program exits by.
pub struct Terminal {
    tty: Arc<Tty>,
    saved: Termios,
    alt_screen: bool,
}

impl Terminal {
    /// Take over `tty`. `alt_screen` switches to the alternate buffer
    /// (top/htop), so the shell's screen comes back intact on exit.
    pub fn open(tty: Arc<Tty>, alt_screen: bool) -> Terminal {
        let saved = tty.termios();
        let mut t = saved;
        // Clear ISIG too: a full-screen program reads ^C/^Z/^\ as ordinary
        // keys (so ^C can quit it) rather than having them raised as signals.
        t.lflag &= !(consts::ICANON | consts::ECHO | consts::ECHONL | consts::IEXTEN | consts::ISIG);
        t.iflag &= !(consts::ICRNL | consts::IXON);
        t.cc[consts::VMIN] = 1;
        t.cc[consts::VTIME] = 0;
        tty.set_termios(t);
        let term = Terminal { tty, saved, alt_screen };
        if alt_screen {
            term.write("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J");
        } else {
            term.write("\x1b[?25l");
        }
        term
    }

    pub fn tty(&self) -> &Arc<Tty> {
        &self.tty
    }

    pub fn write(&self, s: &str) {
        let _ = self.tty.write(s.as_bytes());
    }

    /// (columns, rows), with sane minimums.
    pub fn size(&self) -> (usize, usize) {
        let ws = self.tty.winsize();
        ((ws.cols as usize).max(20), (ws.rows as usize).max(5))
    }

    fn byte_within(&self, ns: u64) -> Result<Option<u8>, Errno> {
        if !self.tty.input_ready() {
            let deadline = crate::time::now_ns() + ns;
            let r = self.tty.read_wq.wait_until_interruptible(|| (self.tty.input_ready() || self.tty.is_hung_up()).then_some(()), Some(deadline));
            if let Err(crate::sync::WaitResult::Interrupted) = r {
                return Err(Errno::EINTR);
            }
            if !self.tty.input_ready() {
                return if self.tty.is_hung_up() { Err(Errno::EIO) } else { Ok(None) };
            }
        }
        let mut b = [0u8; 1];
        match self.tty.read(&mut b, true) {
            Ok(1) => Ok(Some(b[0])),
            Ok(_) => Err(Errno::EIO),
            Err(Errno::EAGAIN) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Wait up to `timeout_ms` for a key. `Ok(None)` on timeout; `Err` when
    /// the terminal went away or a signal arrived (the caller exits).
    pub fn read_key(&self, timeout_ms: u64) -> Result<Option<Key>, Errno> {
        let Some(b) = self.byte_within(timeout_ms * 1_000_000)? else { return Ok(None) };
        let soon = || self.byte_within(40_000_000);
        Ok(Some(match b {
            b'\r' | b'\n' => Key::Enter,
            b'\t' => Key::Tab,
            0x7F | 0x08 => Key::Backspace,
            0x1B => match soon()? {
                None => Key::Esc,
                Some(b'[') => {
                    let mut params = String::new();
                    loop {
                        let Some(c) = soon()? else { break Key::Unknown };
                        if (0x40..=0x7E).contains(&c) {
                            break match (params.as_str(), c) {
                                ("", b'A') => Key::Up,
                                ("", b'B') => Key::Down,
                                ("", b'C') => Key::Right,
                                ("", b'D') => Key::Left,
                                ("", b'H') | ("1", b'~') | ("7", b'~') => Key::Home,
                                ("", b'F') | ("4", b'~') | ("8", b'~') => Key::End,
                                ("2", b'~') => Key::Unknown,
                                ("3", b'~') => Key::Delete,
                                ("5", b'~') => Key::PageUp,
                                ("6", b'~') => Key::PageDown,
                                ("11", b'~') => Key::F(1),
                                ("12", b'~') => Key::F(2),
                                ("13", b'~') => Key::F(3),
                                ("14", b'~') => Key::F(4),
                                ("15", b'~') => Key::F(5),
                                ("17", b'~') => Key::F(6),
                                ("18", b'~') => Key::F(7),
                                ("19", b'~') => Key::F(8),
                                ("20", b'~') => Key::F(9),
                                ("21", b'~') => Key::F(10),
                                ("23", b'~') => Key::F(11),
                                ("24", b'~') => Key::F(12),
                                // Linux console F1-F5.
                                ("[", b'A') => Key::F(1),
                                ("[", b'B') => Key::F(2),
                                ("[", b'C') => Key::F(3),
                                ("[", b'D') => Key::F(4),
                                ("[", b'E') => Key::F(5),
                                _ => Key::Unknown,
                            };
                        }
                        params.push(c as char);
                        if params.len() > 8 {
                            break Key::Unknown;
                        }
                    }
                }
                Some(b'O') => match soon()? {
                    Some(b'A') => Key::Up,
                    Some(b'B') => Key::Down,
                    Some(b'C') => Key::Right,
                    Some(b'D') => Key::Left,
                    Some(b'H') => Key::Home,
                    Some(b'F') => Key::End,
                    Some(b'P') => Key::F(1),
                    Some(b'Q') => Key::F(2),
                    Some(b'R') => Key::F(3),
                    Some(b'S') => Key::F(4),
                    _ => Key::Unknown,
                },
                Some(_) => Key::Unknown,
            },
            c if c < 0x20 => Key::Ctrl((c + b'@').to_ascii_lowercase() as char),
            c if c < 0x80 => Key::Char(c as char),
            c => {
                // UTF-8 lead byte: collect the continuation bytes.
                let need = if c >= 0xF0 { 3 } else if c >= 0xE0 { 2 } else { 1 };
                let mut v = alloc::vec![c];
                for _ in 0..need {
                    match soon()? {
                        Some(x) => v.push(x),
                        None => break,
                    }
                }
                core::str::from_utf8(&v).ok().and_then(|s| s.chars().next()).map(Key::Char).unwrap_or(Key::Unknown)
            }
        }))
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if self.alt_screen {
            self.write("\x1b[0m\x1b[?25h\x1b[?1049l");
        } else {
            self.write("\x1b[0m\x1b[?25h");
        }
        self.tty.set_termios(self.saved);
    }
}

/// A frame of lines (each may carry SGR escapes). [`Screen::present`]
/// sends only the lines that differ from the previous frame.
pub struct Screen {
    prev: Vec<String>,
    size: (usize, usize),
}

impl Screen {
    pub fn new() -> Screen {
        Screen { prev: Vec::new(), size: (0, 0) }
    }

    /// Force a full repaint on the next present (after a resize or `^L`).
    pub fn invalidate(&mut self) {
        self.prev.clear();
    }

    pub fn present(&mut self, term: &Terminal, lines: &[String]) {
        let size = term.size();
        let mut out = String::new();
        if size != self.size {
            self.size = size;
            self.prev.clear();
            out.push_str("\x1b[0m\x1b[2J");
        }
        let rows = size.1;
        for r in 0..rows {
            let line = lines.get(r).map(|s| s.as_str()).unwrap_or("");
            if self.prev.get(r).map(|s| s.as_str()) == Some(line) {
                continue;
            }
            out.push_str(&alloc::format!("\x1b[{};1H\x1b[0m{}\x1b[0m\x1b[K", r + 1, line));
        }
        self.prev = lines.iter().take(rows).cloned().collect();
        while self.prev.len() < rows {
            self.prev.push(String::new());
        }
        if !out.is_empty() {
            term.write(&out);
        }
    }
}

impl Default for Screen {
    fn default() -> Self {
        Self::new()
    }
}

/// Visible width of text that may contain SGR escape sequences.
pub fn visible_width(s: &str) -> usize {
    let mut n = 0;
    let mut esc = false;
    for c in s.chars() {
        if esc {
            if c.is_ascii_alphabetic() {
                esc = false;
            }
        } else if c == '\x1b' {
            esc = true;
        } else {
            n += 1;
        }
    }
    n
}

/// Cut `s` (with escapes) to `width` visible cells, then pad with spaces.
pub fn fit(s: &str, width: usize) -> String {
    let mut out = String::new();
    let mut n = 0;
    let mut esc = false;
    for c in s.chars() {
        if esc {
            out.push(c);
            if c.is_ascii_alphabetic() {
                esc = false;
            }
            continue;
        }
        if c == '\x1b' {
            esc = true;
            out.push(c);
            continue;
        }
        if n >= width {
            continue;
        }
        out.push(c);
        n += 1;
    }
    for _ in n..width {
        out.push(' ');
    }
    out
}
