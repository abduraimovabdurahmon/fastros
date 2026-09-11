//! Interactive line editor (emacs key bindings, history, completion).
//!
//! Redrawing is width-aware: after every change the editor moves to the
//! row where the prompt starts, rewrites prompt + line, clears the rest of
//! the screen and puts the cursor back — so long lines that wrap, prompts
//! with colours and terminal resizes never leave garbage behind.

use super::Shell;
use crate::errno::Errno;
use crate::fs::file::File;
use crate::tty::{consts, Tty};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

pub struct Editor {
    buf: Vec<char>,
    cursor: usize,
    /// Row of the cursor relative to the first row of the prompt.
    cursor_row: usize,
    /// Visible width of prompt + line at the last redraw (to know when the
    /// old tail must be cleared).
    drawn_width: usize,
    kill: Vec<char>,
    hist_pos: Option<usize>,
    saved_line: Vec<char>,
    last_was_tab: bool,
}

enum Key {
    Char(char),
    Enter,
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    WordLeft,
    WordRight,
    KillWordBack,
    Tab,
    Ctrl(u8),
    Eof,
    Ignore,
}

/// Visible width of a prompt: skips `\x01..\x02` spans and ANSI escapes.
fn visible_width(s: &str) -> usize {
    let mut w = 0;
    let mut hidden = false;
    let mut esc = false;
    for c in s.chars() {
        match c {
            '\x01' => hidden = true,
            '\x02' => hidden = false,
            '\x1b' => esc = true,
            _ if hidden => {}
            _ if esc => {
                if c.is_ascii_alphabetic() {
                    esc = false;
                }
            }
            _ if (c as u32) < 0x20 => {}
            _ => w += char_width(c),
        }
    }
    w
}

/// Terminal cell width of a character (East Asian wide chars take two).
fn char_width(c: char) -> usize {
    let u = c as u32;
    if (0x1100..=0x115F).contains(&u)
        || (0x2E80..=0xA4CF).contains(&u)
        || (0xAC00..=0xD7A3).contains(&u)
        || (0xF900..=0xFAFF).contains(&u)
        || (0xFE30..=0xFE4F).contains(&u)
        || (0xFF00..=0xFF60).contains(&u)
        || (0xFFE0..=0xFFE6).contains(&u)
        || (0x1F300..=0x1F64F).contains(&u)
        || (0x1F900..=0x1F9FF).contains(&u)
        || (0x20000..=0x3FFFD).contains(&u)
    {
        2
    } else {
        1
    }
}

fn strip_markers(s: &str) -> String {
    s.chars().filter(|&c| c != '\x01' && c != '\x02').collect()
}

impl Editor {
    pub fn new() -> Editor {
        Editor { buf: Vec::new(), cursor: 0, cursor_row: 0, drawn_width: 0, kill: Vec::new(), hist_pos: None, saved_line: Vec::new(), last_was_tab: false }
    }

    /// Read one line. `None` on end of input (^D on an empty line, hangup).
    pub fn read_line(&mut self, sh: &mut Shell, prompt: &str) -> Option<String> {
        let stdin = sh.proc.fds.lock().get(0).ok()?;
        let Some(tty) = stdin.tty() else {
            return plain_read_line(sh, &stdin, prompt);
        };
        let saved = tty.termios();
        let mut raw = saved;
        raw.lflag &= !(consts::ICANON | consts::ECHO | consts::ISIG | consts::IEXTEN);
        raw.iflag |= consts::ICRNL;
        raw.cc[consts::VMIN] = 1;
        raw.cc[consts::VTIME] = 0;
        tty.set_termios(raw);
        self.buf.clear();
        self.cursor = 0;
        self.fresh_line();
        self.drawn_width = 0;
        self.hist_pos = None;
        self.last_was_tab = false;
        // First draw: just the prompt, exactly as other shells print it.
        let _ = raw_write(&tty, strip_markers(prompt).as_bytes());
        self.drawn_width = visible_width(prompt);
        let cols = (tty.winsize().cols as usize).max(10);
        self.cursor_row = self.drawn_width / cols;
        if self.drawn_width > 0 && self.drawn_width % cols == 0 {
            let _ = raw_write(&tty, b" \r");
        }
        let result = self.edit_loop(sh, &tty, prompt);
        tty.set_termios(saved);
        result
    }

    fn edit_loop(&mut self, sh: &mut Shell, tty: &Arc<Tty>, prompt: &str) -> Option<String> {
        loop {
            let key = read_key(tty)?;
            let was_tab = core::mem::replace(&mut self.last_was_tab, false);
            match key {
                Key::Enter => {
                    self.cursor = self.buf.len();
                    self.redraw(tty, prompt);
                    let _ = tty.write(b"\n");
                    return Some(self.buf.iter().collect());
                }
                Key::Eof => {
                    if self.buf.is_empty() {
                        let _ = tty.write(b"\n");
                        return None;
                    }
                    if self.cursor < self.buf.len() {
                        self.buf.remove(self.cursor);
                    }
                }
                Key::Ctrl(b'C') => {
                    self.cursor = self.buf.len();
                    self.redraw(tty, prompt);
                    let _ = tty.write(b"^C\n");
                    self.buf.clear();
                    self.cursor = 0;
                    self.fresh_line();
                    self.hist_pos = None;
                    sh.status = 130;
                }
                Key::Char(c) => {
                    self.buf.insert(self.cursor, c);
                    self.cursor += 1;
                    // Typing at the end of a line that does not wrap: just echo.
                    let cols = (tty.winsize().cols as usize).max(10);
                    let new_width = self.drawn_width + char_width(c);
                    if self.cursor == self.buf.len() && new_width % cols != 0 && new_width / cols == self.drawn_width / cols {
                        let mut b = [0u8; 4];
                        let _ = raw_write(tty, c.encode_utf8(&mut b).as_bytes());
                        self.drawn_width = new_width;
                        continue;
                    }
                }
                Key::Backspace => {
                    if self.cursor > 0 {
                        self.cursor -= 1;
                        let c = self.buf.remove(self.cursor);
                        let cols = (tty.winsize().cols as usize).max(10);
                        let w = char_width(c);
                        // Erasing the last character on the same row: "\b \b".
                        if self.cursor == self.buf.len() && self.drawn_width % cols >= w && self.drawn_width % cols != 0 {
                            for _ in 0..w {
                                let _ = raw_write(tty, b"\x08 \x08");
                            }
                            self.drawn_width -= w;
                            continue;
                        }
                    }
                }
                Key::Delete => {
                    if self.cursor < self.buf.len() {
                        self.buf.remove(self.cursor);
                    }
                }
                Key::Left => self.cursor = self.cursor.saturating_sub(1),
                Key::Right => self.cursor = (self.cursor + 1).min(self.buf.len()),
                Key::Home => self.cursor = 0,
                Key::End => self.cursor = self.buf.len(),
                Key::WordLeft => {
                    while self.cursor > 0 && !self.buf[self.cursor - 1].is_alphanumeric() {
                        self.cursor -= 1;
                    }
                    while self.cursor > 0 && self.buf[self.cursor - 1].is_alphanumeric() {
                        self.cursor -= 1;
                    }
                }
                Key::WordRight => {
                    while self.cursor < self.buf.len() && !self.buf[self.cursor].is_alphanumeric() {
                        self.cursor += 1;
                    }
                    while self.cursor < self.buf.len() && self.buf[self.cursor].is_alphanumeric() {
                        self.cursor += 1;
                    }
                }
                Key::KillWordBack => {
                    let end = self.cursor;
                    while self.cursor > 0 && self.buf[self.cursor - 1] == ' ' {
                        self.cursor -= 1;
                    }
                    while self.cursor > 0 && self.buf[self.cursor - 1] != ' ' {
                        self.cursor -= 1;
                    }
                    self.kill = self.buf.drain(self.cursor..end).collect();
                }
                Key::Ctrl(b'K') => self.kill = self.buf.drain(self.cursor..).collect(),
                Key::Ctrl(b'U') => {
                    self.kill = self.buf.drain(..self.cursor).collect();
                    self.cursor = 0;
                }
                Key::Ctrl(b'Y') => {
                    for (i, &c) in self.kill.clone().iter().enumerate() {
                        self.buf.insert(self.cursor + i, c);
                    }
                    self.cursor += self.kill.len();
                }
                Key::Ctrl(b'T') => {
                    if self.cursor > 0 && self.buf.len() >= 2 {
                        let at = if self.cursor == self.buf.len() { self.cursor - 1 } else { self.cursor };
                        self.buf.swap(at - 1, at);
                        self.cursor = (at + 1).min(self.buf.len());
                    }
                }
                Key::Ctrl(b'L') => {
                    let _ = tty.write(b"\x1b[H\x1b[2J");
                    self.fresh_line();
                }
                Key::Up | Key::Ctrl(b'P') => self.history_step(sh, true),
                Key::Down | Key::Ctrl(b'N') => self.history_step(sh, false),
                Key::Ctrl(b'R') => {
                    if let Some(line) = self.reverse_search(sh, tty) {
                        self.buf = line.chars().collect();
                        self.cursor = self.buf.len();
                    }
                    self.fresh_line();
                }
                Key::Tab => {
                    self.complete(sh, tty, prompt, was_tab);
                    self.last_was_tab = true;
                }
                Key::Ctrl(_) | Key::Ignore => {}
            }
            self.redraw(tty, prompt);
        }
    }

    fn history_step(&mut self, sh: &Shell, up: bool) {
        let n = sh.history.len();
        if n == 0 {
            return;
        }
        let next = match (self.hist_pos, up) {
            (None, true) => {
                self.saved_line = self.buf.clone();
                Some(n - 1)
            }
            (None, false) => return,
            (Some(0), true) => Some(0),
            (Some(i), true) => Some(i - 1),
            (Some(i), false) if i + 1 < n => Some(i + 1),
            (Some(_), false) => None,
        };
        self.hist_pos = next;
        self.buf = match next {
            Some(i) => sh.history.get(i).unwrap_or("").chars().collect(),
            None => self.saved_line.clone(),
        };
        self.cursor = self.buf.len();
    }

    /// Redraw prompt and line and place the cursor.
    fn redraw(&mut self, tty: &Arc<Tty>, prompt: &str) {
        let cols = (tty.winsize().cols as usize).max(10);
        let pw = visible_width(prompt);
        let text: String = self.buf.iter().collect();
        let tw: usize = self.buf.iter().map(|&c| char_width(c)).sum();
        let cw: usize = self.buf[..self.cursor].iter().map(|&c| char_width(c)).sum();
        let mut out = String::with_capacity(prompt.len() + text.len() + 32);
        if self.cursor_row > 0 {
            out.push_str(&alloc::format!("\x1b[{}A", self.cursor_row));
        }
        out.push('\r');
        out.push_str(&strip_markers(prompt));
        out.push_str(&text);
        let end = pw + tw;
        // Clear what the previous, longer line left behind.
        if end < self.drawn_width {
            out.push_str("\x1b[J");
        }
        self.drawn_width = end;
        // At an exact multiple of the width the terminal defers the wrap:
        // force it so the cursor math below holds.
        if end > 0 && end % cols == 0 {
            out.push_str(" \r");
        }
        let end_row = end / cols;
        let pos = pw + cw;
        let row = pos / cols;
        let col = pos % cols;
        if pos != end {
            if end_row > row {
                out.push_str(&alloc::format!("\x1b[{}A", end_row - row));
            }
            out.push('\r');
            if col > 0 {
                out.push_str(&alloc::format!("\x1b[{col}C"));
            }
        }
        self.cursor_row = row;
        let _ = raw_write(tty, out.as_bytes());
    }

    fn reverse_search(&mut self, sh: &Shell, tty: &Arc<Tty>) -> Option<String> {
        let mut query = String::new();
        let mut found: Option<String> = None;
        loop {
            let shown = found.clone().unwrap_or_default();
            let line = alloc::format!("\r\x1b[J(reverse-i-search)`{query}': {shown}");
            let _ = raw_write(tty, line.as_bytes());
            match read_key(tty)? {
                Key::Char(c) => query.push(c),
                Key::Backspace => {
                    query.pop();
                }
                Key::Enter | Key::Right | Key::Left | Key::End | Key::Home => {
                    let _ = raw_write(tty, b"\r\x1b[J");
                    return found;
                }
                Key::Ctrl(b'C') | Key::Ctrl(b'G') | Key::Eof => {
                    let _ = raw_write(tty, b"\r\x1b[J");
                    return None;
                }
                _ => {}
            }
            found = (0..sh.history.len()).rev().filter_map(|i| sh.history.get(i)).find(|h| h.contains(query.as_str())).map(|s| s.to_string());
        }
    }

    // ── completion ──────────────────────────────────────────────────────

    fn complete(&mut self, sh: &mut Shell, tty: &Arc<Tty>, prompt: &str, second_tab: bool) {
        let before: String = self.buf[..self.cursor].iter().collect();
        let start = before.rfind(|c: char| c == ' ' || c == ';' || c == '|' || c == '&' || c == '(' || c == '<' || c == '>').map(|i| i + 1).unwrap_or(0);
        let word = &before[start..];
        let head = before[..start].trim_end();
        let command_position = head.is_empty() || head.ends_with(';') || head.ends_with('|') || head.ends_with('&') || head.ends_with('(') || head == "sudo" || head.ends_with(" sudo");
        let (cands, is_path) = if command_position && !word.contains('/') {
            (command_candidates(sh, word), false)
        } else {
            (path_candidates(sh, word), true)
        };
        if cands.is_empty() {
            let _ = raw_write(tty, b"\x07");
            return;
        }
        let common = common_prefix(&cands);
        let typed_tail = if is_path { word.rsplit('/').next().unwrap_or("") } else { word };
        let unescaped_tail = unescape(typed_tail);
        if cands.len() == 1 {
            let c = &cands[0];
            let rest = &c[unescaped_tail.len().min(c.len())..];
            let mut ins = escape(rest);
            if !c.ends_with('/') {
                ins.push(' ');
            }
            self.insert_str(&ins);
            return;
        }
        if common.len() > unescaped_tail.len() {
            let ins = escape(&common[unescaped_tail.len()..]);
            self.insert_str(&ins);
            return;
        }
        if !second_tab {
            let _ = raw_write(tty, b"\x07");
            return;
        }
        // Second Tab: list the candidates in columns under the line.
        self.cursor = self.buf.len();
        self.redraw(tty, prompt);
        let cols = (tty.winsize().cols as usize).max(20);
        let width = cands.iter().map(|c| c.chars().count()).max().unwrap_or(1) + 2;
        let per_row = (cols / width).max(1);
        let rows = cands.len().div_ceil(per_row);
        let mut out = String::from("\r\n");
        for r in 0..rows {
            for c in 0..per_row {
                if let Some(name) = cands.get(c * rows + r) {
                    let pad = width - name.chars().count();
                    out.push_str(name);
                    if c + 1 < per_row {
                        out.extend(core::iter::repeat_n(' ', pad));
                    }
                }
            }
            out.push_str("\r\n");
        }
        let _ = raw_write(tty, out.as_bytes());
        self.fresh_line();
    }

    /// The cursor is at the start of a fresh line (nothing of ours above it).
    fn fresh_line(&mut self) {
        self.cursor_row = 0;
        self.drawn_width = 0;
    }

    fn insert_str(&mut self, s: &str) {
        for c in s.chars() {
            self.buf.insert(self.cursor, c);
            self.cursor += 1;
        }
    }
}

fn escape(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        if " \t'\"\\$`&|;()<>*?[]#!".contains(c) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

fn unescape(s: &str) -> String {
    let mut o = String::new();
    let mut esc = false;
    for c in s.chars() {
        if esc {
            o.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c != '\'' && c != '"' {
            o.push(c);
        }
    }
    o
}

fn common_prefix(v: &[String]) -> String {
    let first: Vec<char> = v[0].chars().collect();
    let mut n = first.len();
    for s in &v[1..] {
        n = n.min(s.chars().zip(first.iter()).take_while(|(a, b)| a == *b).count());
    }
    first[..n].iter().collect()
}

fn command_candidates(sh: &Shell, prefix: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for n in super::builtins::names() {
        v.push(n.to_string());
    }
    for d in super::cmds::all() {
        v.push(d.name.to_string());
    }
    v.extend(sh.funcs.keys().cloned());
    v.extend(sh.aliases.keys().cloned());
    let ctx = crate::fs::ops::Ctx::of(&sh.proc);
    for dir in sh.var("PATH").unwrap_or_default().split(':').filter(|d| !d.is_empty() && *d != "/bin") {
        if let Ok(es) = crate::fs::ops::list_dir(&ctx, dir) {
            v.extend(es.into_iter().map(|e| e.name));
        }
    }
    v.retain(|n| n.starts_with(prefix));
    v.sort();
    v.dedup();
    v
}

fn path_candidates(sh: &Shell, word: &str) -> Vec<String> {
    let word = unescape(word);
    let (dir, prefix) = match word.rfind('/') {
        Some(i) => (&word[..=i], &word[i + 1..]),
        None => ("", word.as_str()),
    };
    let lookup = if dir.is_empty() {
        String::from(".")
    } else if let Some(rest) = dir.strip_prefix('~') {
        alloc::format!("{}{}", sh.var("HOME").unwrap_or_default(), rest)
    } else {
        dir.to_string()
    };
    let ctx = crate::fs::ops::Ctx::of(&sh.proc);
    let Ok(entries) = crate::fs::ops::list_dir(&ctx, &lookup) else { return Vec::new() };
    let mut v: Vec<String> = entries
        .into_iter()
        .filter(|e| e.name.starts_with(prefix) && (prefix.starts_with('.') || !e.name.starts_with('.')))
        .map(|e| {
            let full = alloc::format!("{}/{}", lookup.trim_end_matches('/'), e.name);
            let is_dir = e.kind == crate::fs::FileType::Directory || crate::fs::ops::stat(&ctx, &full, true).is_ok_and(|m| m.kind == crate::fs::FileType::Directory);
            if is_dir {
                alloc::format!("{}/", e.name)
            } else {
                e.name
            }
        })
        .collect();
    v.sort();
    v
}

fn raw_write(tty: &Arc<Tty>, b: &[u8]) -> Result<(), Errno> {
    // Raw mode has OPOST off for our own bytes? No: keep ONLCR but we only
    // emit explicit \r\n sequences here, so write straight through.
    tty.write(b).map(|_| ())
}

fn read_byte(tty: &Arc<Tty>) -> Option<u8> {
    let mut b = [0u8; 1];
    loop {
        match tty.read(&mut b, false) {
            Ok(1) => return Some(b[0]),
            Ok(_) => return None, // hangup / EOF
            Err(Errno::EINTR) => {
                if !crate::proc::absorb_signals() {
                    return None;
                }
                continue;
            }
            Err(_) => return None,
        }
    }
}

/// Next byte if one arrives quickly (to tell ESC from an escape sequence).
fn read_byte_soon(tty: &Arc<Tty>) -> Option<u8> {
    for _ in 0..50 {
        if tty.input_ready() {
            return read_byte(tty);
        }
        crate::sched::sleep_ms(1);
    }
    None
}

fn read_key(tty: &Arc<Tty>) -> Option<Key> {
    let b = read_byte(tty)?;
    Some(match b {
        b'\n' | b'\r' => Key::Enter,
        0x7F | 0x08 => Key::Backspace,
        b'\t' => Key::Tab,
        0x04 => Key::Eof,
        0x17 => Key::KillWordBack,
        0x01 => Key::Home,
        0x05 => Key::End,
        0x02 => Key::Left,
        0x06 => Key::Right,
        0x1B => match read_byte_soon(tty) {
            Some(b'[') => {
                let mut params = String::new();
                loop {
                    let c = read_byte_soon(tty)?;
                    if (0x40..=0x7E).contains(&c) {
                        break match (params.as_str(), c) {
                            ("", b'A') => Key::Up,
                            ("", b'B') => Key::Down,
                            ("", b'C') => Key::Right,
                            ("", b'D') => Key::Left,
                            ("", b'H') | ("1", b'~') | ("7", b'~') => Key::Home,
                            ("", b'F') | ("4", b'~') | ("8", b'~') => Key::End,
                            ("3", b'~') => Key::Delete,
                            ("1;5", b'D') | ("1;3", b'D') => Key::WordLeft,
                            ("1;5", b'C') | ("1;3", b'C') => Key::WordRight,
                            _ => Key::Ignore,
                        };
                    }
                    params.push(c as char);
                    if params.len() > 8 {
                        break Key::Ignore;
                    }
                }
            }
            Some(b'O') => match read_byte_soon(tty) {
                Some(b'A') => Key::Up,
                Some(b'B') => Key::Down,
                Some(b'C') => Key::Right,
                Some(b'D') => Key::Left,
                Some(b'H') => Key::Home,
                Some(b'F') => Key::End,
                _ => Key::Ignore,
            },
            Some(b'b') => Key::WordLeft,
            Some(b'f') => Key::WordRight,
            Some(0x7F) => Key::KillWordBack,
            _ => Key::Ignore,
        },
        c if c < 0x20 => Key::Ctrl(c + b'@'),
        c => {
            // UTF-8: collect continuation bytes.
            let need = if c >= 0xF0 {
                3
            } else if c >= 0xE0 {
                2
            } else if c >= 0xC0 {
                1
            } else {
                0
            };
            let mut bytes = alloc::vec![c];
            for _ in 0..need {
                bytes.push(read_byte(tty)?);
            }
            match core::str::from_utf8(&bytes).ok().and_then(|s| s.chars().next()) {
                Some(ch) => Key::Char(ch),
                None => Key::Ignore,
            }
        }
    })
}

/// Line input without a terminal (e.g. `ssh host` with no pty).
fn plain_read_line(sh: &Shell, stdin: &Arc<dyn File>, prompt: &str) -> Option<String> {
    sh.out(&strip_markers(prompt));
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match stdin.read(&mut b) {
            Ok(1) => {
                if b[0] == b'\n' {
                    break;
                }
                line.push(b[0]);
            }
            Ok(_) => {
                if line.is_empty() {
                    return None;
                }
                break;
            }
            Err(Errno::EINTR) => {
                if !crate::proc::absorb_signals() {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    Some(String::from_utf8_lossy(&line).trim_end_matches('\r').to_string())
}
