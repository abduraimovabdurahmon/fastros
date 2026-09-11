//! Terminal pagers: `less` (full-screen, on the alternate screen) and
//! `more` (page-at-a-time, scrolling). Both read keys from the terminal on
//! stdout, so `cmd | less` works, and both degrade to `cat` when stdout is
//! not a terminal. Input is loaded lazily: `yes | less` shows its first
//! screen at once, and `G` on an endless pipe can be interrupted with ^C.

use super::posixre::{self, Flags, Syntax};
use crate::errno::Errno;
use crate::fs::file::File;
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use crate::tty::{consts, Tty};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;

// ── document ───────────────────────────────────────────────────────────────

struct Doc {
    name: String,
    lines: Vec<Vec<u8>>,
    src: Option<Arc<dyn File>>,
    partial: Vec<u8>,
    eof: bool,
    bytes_read: u64,
    /// Total size when known (regular files), for percentages.
    size: Option<u64>,
}

impl Doc {
    fn new(name: String, src: Arc<dyn File>) -> Doc {
        let size = src.stat().ok().filter(|m| m.kind == crate::fs::FileType::Regular).map(|m| m.size);
        Doc { name, lines: Vec::new(), src: Some(src), partial: Vec::new(), eof: false, bytes_read: 0, size }
    }

    /// Read more input; false at end of file.
    fn read_more(&mut self) -> bool {
        if self.eof {
            return false;
        }
        let Some(f) = self.src.clone() else {
            self.eof = true;
            return false;
        };
        let mut buf = alloc::vec![0u8; 16 * 1024];
        match f.read(&mut buf) {
            Ok(0) | Err(_) => {
                self.eof = true;
                if !self.partial.is_empty() {
                    let l = core::mem::take(&mut self.partial);
                    self.lines.push(l);
                }
                self.src = None;
                false
            }
            Ok(n) => {
                self.bytes_read += n as u64;
                for &b in &buf[..n] {
                    if b == b'\n' {
                        let l = core::mem::take(&mut self.partial);
                        self.lines.push(l);
                    } else {
                        self.partial.push(b);
                    }
                }
                true
            }
        }
    }

    /// Make sure line `i` is loaded if it exists.
    fn ensure(&mut self, i: usize) -> bool {
        while self.lines.len() <= i {
            if !self.read_more() {
                break;
            }
        }
        i < self.lines.len()
    }
}

// ── rendering ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Style {
    raw_ansi: bool,
    line_numbers: bool,
    chop: bool,
}

/// One visible unit: text to emit, cell width, byte offset in the line.
struct Cell {
    text: String,
    width: usize,
    off: usize,
}

fn char_width(c: char) -> usize {
    let u = c as u32;
    if (0x1100..=0x115F).contains(&u) || (0x2E80..=0xA4CF).contains(&u) || (0xAC00..=0xD7A3).contains(&u) || (0xF900..=0xFAFF).contains(&u) || (0xFF00..=0xFF60).contains(&u) || (0x1F300..=0x1F64F).contains(&u) || (0x1F900..=0x1F9FF).contains(&u) || (0x20000..=0x3FFFD).contains(&u) {
        2
    } else {
        1
    }
}

fn cells(line: &[u8], st: Style) -> Vec<Cell> {
    let mut out = Vec::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        let b = line[i];
        // SGR colour sequences pass through with -R.
        if b == 0x1b && st.raw_ansi && line.get(i + 1) == Some(&b'[') {
            let mut j = i + 2;
            while j < line.len() && (line[j].is_ascii_digit() || line[j] == b';') {
                j += 1;
            }
            if j < line.len() && line[j] == b'm' {
                out.push(Cell { text: String::from_utf8_lossy(&line[i..=j]).into_owned(), width: 0, off: i });
                i = j + 1;
                continue;
            }
        }
        if b == b'\t' {
            out.push(Cell { text: String::from("\t"), width: 0, off: i });
            i += 1;
            continue;
        }
        if b < 0x20 || b == 0x7f {
            let shown = if b == 0x7f { '?' } else { (b + b'@') as char };
            out.push(Cell { text: alloc::format!("\x1b[7m^{shown}\x1b[27m"), width: 2, off: i });
            i += 1;
            continue;
        }
        let len = match b {
            0xF0..=0xF7 => 4,
            0xE0..=0xEF => 3,
            0xC0..=0xDF => 2,
            _ => 1,
        };
        match line.get(i..i + len).and_then(|s| core::str::from_utf8(s).ok()).and_then(|s| s.chars().next()) {
            Some(c) if len > 1 || b < 0x80 => {
                out.push(Cell { text: c.to_string(), width: char_width(c), off: i });
                i += len;
            }
            _ => {
                out.push(Cell { text: alloc::format!("\x1b[7m<{:02X}>\x1b[27m", b), width: 4, off: i });
                i += 1;
            }
        }
    }
    out
}

/// Split a line into screen rows of at most `width` cells; tabs expand to
/// 8-column stops. Matches in `hl` (byte ranges) are shown reversed.
fn layout(line: &[u8], st: Style, width: usize, hscroll: usize, hl: &[(usize, usize)]) -> Vec<String> {
    let width = width.max(1);
    let mut rows: Vec<String> = Vec::new();
    let mut row = String::new();
    let mut col = 0; // column within the logical line
    let mut row_start = 0; // logical column where this row starts
    let mut in_hl = false;
    let limit = |row_start: usize| if st.chop { hscroll + width } else { row_start + width };
    for c in cells(line, st) {
        let lit = hl.iter().any(|&(s, e)| c.off >= s && c.off < e);
        let (text, w) = if c.text == "\t" {
            let n = 8 - col % 8;
            (" ".repeat(n), n)
        } else {
            (c.text, c.width)
        };
        if !st.chop && col + w > limit(row_start) && col > row_start {
            if in_hl {
                row.push_str("\x1b[27m");
                in_hl = false;
            }
            rows.push(core::mem::take(&mut row));
            row_start = col;
        }
        let visible = if st.chop { col >= hscroll && col + w <= hscroll + width } else { true };
        if visible {
            if lit != in_hl {
                row.push_str(if lit { "\x1b[7m" } else { "\x1b[27m" });
                in_hl = lit;
            }
            row.push_str(&text);
        } else if w == 0 {
            // Keep colour state even for hidden cells.
            row.push_str(&text);
        }
        col += w;
    }
    if in_hl {
        row.push_str("\x1b[27m");
    }
    if st.raw_ansi {
        row.push_str("\x1b[m");
    }
    rows.push(row);
    rows
}

// ── keys ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Char(u8),
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    /// No key within the poll interval.
    Timeout,
    Hangup,
}

struct Term {
    tty: Arc<Tty>,
    saved: crate::tty::Termios,
}

impl Term {
    fn open(tty: Arc<Tty>) -> Term {
        let saved = tty.termios();
        let mut raw = saved;
        raw.lflag &= !(consts::ICANON | consts::ECHO | consts::ISIG | consts::IEXTEN);
        raw.iflag |= consts::ICRNL;
        // The pagers emit explicit `\r\n`; no output translation.
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
        (cols.max(10), rows.max(3))
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
                    if self.tty.is_hung_up() {
                        return None;
                    }
                    if !wait {
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
        if b != 0x1b {
            return Key::Char(b);
        }
        match self.byte(false) {
            Some(b'[') => {
                let mut params = Vec::new();
                loop {
                    let Some(c) = self.byte(false) else { return Key::Char(0x1b) };
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
            Some(b'v') => Key::PageUp,
            Some(b'<') => Key::Home,
            Some(b'>') => Key::End,
            _ => Key::Char(0x1b),
        }
    }

    /// Read a line on the bottom row after `prompt` (search patterns, `:`).
    /// None if cancelled.
    fn read_line(&self, prompt: &str, row: usize) -> Option<String> {
        let mut s = String::new();
        loop {
            self.write(&alloc::format!("\x1b[{row};1H\x1b[K{prompt}{s}"));
            let b = self.byte(true)?;
            match b {
                b'\n' | b'\r' => return Some(s),
                0x7f | 0x08 => {
                    if s.pop().is_none() {
                        return None;
                    }
                }
                0x03 | 0x07 | 0x1b => return None,
                0x15 => s.clear(),
                c if c >= 0x20 => {
                    // Collect a whole UTF-8 sequence.
                    let need = match c {
                        0xF0..=0xF7 => 3,
                        0xE0..=0xEF => 2,
                        0xC0..=0xDF => 1,
                        _ => 0,
                    };
                    let mut v = alloc::vec![c];
                    for _ in 0..need {
                        v.push(self.byte(true)?);
                    }
                    s.push_str(&String::from_utf8_lossy(&v));
                }
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

/// Collect the inputs as documents; `-` / no operand is stdin.
fn open_docs(ctx: &mut Ctx, operands: &[String]) -> (Vec<Doc>, bool) {
    let mut docs = Vec::new();
    let mut err = false;
    let list: Vec<String> = if operands.is_empty() { alloc::vec![String::from("-")] } else { operands.to_vec() };
    for name in list {
        match ctx.open_input(&name) {
            Ok(f) => docs.push(Doc::new(name, f)),
            Err(e) => {
                let n = ctx.name().to_string();
                ctx.eprint(&alloc::format!("{n}: {name}: {e}\n"));
                err = true;
            }
        }
    }
    (docs, err)
}

/// Not a terminal: copy everything (with `more`'s file headers).
fn cat_docs(ctx: &mut Ctx, docs: &mut [Doc], headers: bool) {
    let n = docs.len();
    for d in docs.iter_mut() {
        if headers && n > 1 {
            ctx.print(&alloc::format!("::::::::::::::\n{}\n::::::::::::::\n", d.name));
        }
        let Some(f) = d.src.take() else { continue };
        let mut buf = alloc::vec![0u8; 32 * 1024];
        loop {
            match f.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(k) => ctx.write(&buf[..k]),
            }
            if ctx.should_stop() {
                return;
            }
        }
    }
}

// ── less ───────────────────────────────────────────────────────────────────

struct Less {
    docs: Vec<Doc>,
    cur: usize,
    st: Style,
    icase_smart: bool,
    icase: bool,
    quit_at_eof: bool,
    top: usize,
    /// Row offset inside the top line (wrap mode).
    top_sub: usize,
    hscroll: usize,
    search: Option<(regex::bytes::Regex, bool)>,
    message: Option<String>,
    first_screen: bool,
}

impl Less {
    fn doc(&mut self) -> &mut Doc {
        &mut self.docs[self.cur]
    }

    fn text_width(&self, cols: usize) -> usize {
        if self.st.line_numbers {
            cols.saturating_sub(8).max(1)
        } else {
            cols
        }
    }

    fn hl_ranges(&self, line: &[u8]) -> Vec<(usize, usize)> {
        match &self.search {
            Some((re, _)) => re.find_iter(line).filter(|m| m.end() > m.start()).map(|m| (m.start(), m.end())).collect(),
            None => Vec::new(),
        }
    }

    fn rows_of(&self, i: usize, cols: usize) -> Vec<String> {
        let line = &self.docs[self.cur].lines[i];
        let hl = self.hl_ranges(line);
        layout(line, self.st, self.text_width(cols), self.hscroll, &hl)
    }

    /// Screen rows from the top position: (line index, row text).
    fn screen(&mut self, cols: usize, height: usize) -> Vec<Option<(usize, usize, String)>> {
        let mut out = Vec::with_capacity(height);
        let mut i = self.top;
        let mut sub = self.top_sub;
        while out.len() < height {
            if !self.doc().ensure(i) {
                out.push(None);
                continue;
            }
            let rows = self.rows_of(i, cols);
            for (k, r) in rows.into_iter().enumerate().skip(sub) {
                if out.len() >= height {
                    break;
                }
                out.push(Some((i, k, r)));
            }
            sub = 0;
            i += 1;
        }
        out
    }

    /// Is the last line of the document visible on this screen?
    fn at_end(&mut self, cols: usize, height: usize) -> bool {
        let s = self.screen(cols, height);
        let last_shown = s.iter().rev().find_map(|r| r.as_ref().map(|(i, k, _)| (*i, *k)));
        match last_shown {
            None => true,
            Some((i, k)) => {
                let more_lines = self.doc().ensure(i + 1);
                !more_lines && k + 1 >= self.rows_of(i, cols).len()
            }
        }
    }

    fn scroll_down(&mut self, n: usize, cols: usize, height: usize) {
        for _ in 0..n {
            if self.at_end(cols, height) {
                break;
            }
            let rows = self.rows_of(self.top, cols).len();
            if self.top_sub + 1 < rows {
                self.top_sub += 1;
            } else {
                self.top += 1;
                self.top_sub = 0;
            }
        }
    }

    fn scroll_up(&mut self, n: usize, cols: usize) {
        for _ in 0..n {
            if self.top_sub > 0 {
                self.top_sub -= 1;
            } else if self.top > 0 {
                self.top -= 1;
                self.top_sub = self.rows_of(self.top, cols).len().saturating_sub(1);
            } else {
                break;
            }
        }
    }

    fn goto_line(&mut self, n: usize) {
        let d = self.doc();
        d.ensure(n);
        let max = d.lines.len().saturating_sub(1);
        self.top = n.min(max);
        self.top_sub = 0;
    }

    /// `G`: load everything (interruptible with ^C), then show the last page.
    fn goto_end(&mut self, term: &Term, cols: usize, height: usize) {
        while !self.docs[self.cur].eof {
            if term.tty.input_ready() {
                if let Some(0x03) = term.byte(false) {
                    self.message = Some(String::from("(interrupted)"));
                    break;
                }
            }
            self.docs[self.cur].read_more();
        }
        let total = self.docs[self.cur].lines.len();
        self.top = total;
        self.top_sub = 0;
        // Walk back one screen.
        let mut rows = 0;
        while self.top > 0 {
            let r = self.rows_of(self.top - 1, cols).len();
            if rows + r > height {
                self.top_sub = rows + r - height;
                self.top -= 1;
                break;
            }
            rows += r;
            self.top -= 1;
        }
    }

    fn find(&mut self, forward: bool, from: usize) -> Option<usize> {
        let (re, _) = self.search.clone()?;
        let mut i = from;
        loop {
            if forward {
                if !self.docs[self.cur].ensure(i) {
                    return None;
                }
            } else if i >= self.docs[self.cur].lines.len() {
                return None;
            }
            if re.is_match(&self.docs[self.cur].lines[i]) {
                return Some(i);
            }
            if forward {
                i += 1;
            } else {
                if i == 0 {
                    return None;
                }
                i -= 1;
            }
            if i % 4096 == 0 {
                crate::sched::cond_resched();
            }
        }
    }

    fn prompt(&mut self, cols: usize, height: usize) -> String {
        if let Some(m) = self.message.take() {
            return alloc::format!("\x1b[7m{m}\x1b[27m");
        }
        let end = self.at_end(cols, height);
        let n = self.docs.len();
        if end {
            if self.cur + 1 < n {
                return alloc::format!("\x1b[7m(END) - Next: {}\x1b[27m", self.docs[self.cur + 1].name);
            }
            return String::from("\x1b[7m(END)\x1b[27m");
        }
        if self.first_screen && self.docs[self.cur].name != "-" {
            let name = self.docs[self.cur].name.clone();
            if n > 1 {
                return alloc::format!("\x1b[7m{} (file {} of {})\x1b[27m", name, self.cur + 1, n);
            }
            return alloc::format!("\x1b[7m{name}\x1b[27m");
        }
        String::from(":")
    }

    fn draw(&mut self, term: &Term) {
        let (cols, rows) = term.size();
        let height = rows - 1;
        let screen = self.screen(cols, height);
        let mut out = String::from("\x1b[H");
        for r in screen {
            match r {
                Some((i, k, text)) => {
                    if self.st.line_numbers {
                        if k == 0 {
                            let _ = write!(out, "{:>7} ", i + 1);
                        } else {
                            out.push_str("        ");
                        }
                    }
                    out.push_str(&text);
                }
                None => out.push('~'),
            }
            out.push_str("\x1b[K\r\n");
        }
        let p = self.prompt(cols, height);
        out.push_str(&p);
        out.push_str("\x1b[K");
        term.write(&out);
        self.first_screen = false;
    }

    fn info(&mut self, cols: usize, height: usize) -> String {
        let d = &self.docs[self.cur];
        let total = if d.eof { alloc::format!("/{}", d.lines.len()) } else { String::new() };
        let bottom = (self.top + height).min(d.lines.len());
        let mut s = alloc::format!("{} lines {}-{}{}", if d.name == "-" { "Standard input" } else { d.name.as_str() }, self.top + 1, bottom, total);
        if let Some(sz) = d.size {
            let _ = write!(s, " byte {}", sz);
        }
        let _ = cols;
        s.push_str(if self.at_end(cols, height) { " (END)" } else { "" });
        s
    }

    fn run(&mut self, term: &Term) {
        let mut count: Option<usize> = None;
        let mut last_size = term.size();
        self.draw(term);
        loop {
            let key = term.key();
            let (cols, rows) = term.size();
            let height = rows - 1;
            if key == Key::Hangup {
                return;
            }
            if key == Key::Timeout {
                if (cols, rows) != last_size {
                    last_size = (cols, rows);
                    self.draw(term);
                }
                continue;
            }
            last_size = (cols, rows);
            let n = count.take();
            let times = n.unwrap_or(1);
            match key {
                Key::Char(c @ b'0'..=b'9') => {
                    let v = n.unwrap_or(0).saturating_mul(10).saturating_add((c - b'0') as usize);
                    count = Some(v);
                    term.write(&alloc::format!("\x1b[{rows};1H\x1b[K:{v}"));
                    continue;
                }
                Key::Char(b'q') | Key::Char(b'Q') => return,
                Key::Char(b'Z') => {
                    if term.byte(true) == Some(b'Z') {
                        return;
                    }
                }
                Key::Char(b' ') | Key::Char(b'f') | Key::Char(0x06) | Key::Char(0x16) | Key::PageDown => {
                    if self.quit_at_eof && self.at_end(cols, height) {
                        return;
                    }
                    self.scroll_down(n.unwrap_or(height), cols, height);
                }
                Key::Char(b'z') => self.scroll_down(n.unwrap_or(height), cols, height),
                Key::Char(b'b') | Key::Char(0x02) | Key::PageUp => self.scroll_up(n.unwrap_or(height), cols),
                Key::Char(b'j') | Key::Char(b'e') | Key::Char(0x05) | Key::Char(0x0e) | Key::Char(b'\n') | Key::Char(b'\r') | Key::Down => self.scroll_down(times, cols, height),
                Key::Char(b'k') | Key::Char(b'y') | Key::Char(0x19) | Key::Char(0x10) | Key::Char(0x0b) | Key::Up => self.scroll_up(times, cols),
                Key::Char(b'd') | Key::Char(0x04) => self.scroll_down(n.unwrap_or(height / 2), cols, height),
                Key::Char(b'u') | Key::Char(0x15) => self.scroll_up(n.unwrap_or(height / 2), cols),
                Key::Char(b'g') | Key::Char(b'<') | Key::Home => self.goto_line(n.map(|v| v.saturating_sub(1)).unwrap_or(0)),
                Key::Char(b'G') | Key::Char(b'>') | Key::End => match n {
                    Some(v) => self.goto_line(v.saturating_sub(1)),
                    None => self.goto_end(term, cols, height),
                },
                Key::Char(b'p') | Key::Char(b'%') => {
                    let d = &mut self.docs[self.cur];
                    while d.read_more() {}
                    let total = d.lines.len();
                    let pct = n.unwrap_or(0).min(100);
                    self.goto_line(total * pct / 100);
                }
                Key::Right => {
                    if self.st.chop {
                        self.hscroll += cols / 2;
                    }
                }
                Key::Left => {
                    if self.st.chop {
                        self.hscroll = self.hscroll.saturating_sub(cols / 2);
                    }
                }
                Key::Char(b'/') | Key::Char(b'?') => {
                    let forward = key == Key::Char(b'/');
                    let Some(pat) = term.read_line(if forward { "/" } else { "?" }, rows) else {
                        self.draw(term);
                        continue;
                    };
                    if !pat.is_empty() {
                        let icase = self.icase || (self.icase_smart && !pat.chars().any(|c| c.is_uppercase()));
                        match posixre::compile_bytes(&[pat], Syntax::Extended, Flags { icase, ..Default::default() }) {
                            Ok(re) => self.search = Some((re, forward)),
                            Err(m) => {
                                self.message = Some(m);
                                self.draw(term);
                                continue;
                            }
                        }
                    }
                    self.search_step(forward, times);
                }
                Key::Char(b'n') | Key::Char(b'N') => {
                    let Some((_, dir)) = self.search.clone() else {
                        self.message = Some(String::from("No previous regular expression"));
                        self.draw(term);
                        continue;
                    };
                    let forward = if key == Key::Char(b'n') { dir } else { !dir };
                    self.search_step(forward, times);
                }
                Key::Char(b'=') | Key::Char(0x07) => {
                    let s = self.info(cols, height);
                    self.message = Some(s);
                }
                Key::Char(b':') => {
                    let Some(cmd) = term.read_line(":", rows) else {
                        self.draw(term);
                        continue;
                    };
                    match cmd.trim() {
                        "q" | "Q" => return,
                        "n" => self.switch(1),
                        "p" => self.switch(-1),
                        "x" => {
                            self.cur = 0;
                            self.top = 0;
                            self.top_sub = 0;
                        }
                        "" => {}
                        _ => self.message = Some(String::from("Unknown command")),
                    }
                }
                Key::Char(b'r') | Key::Char(0x0c) | Key::Char(0x12) => term.write("\x1b[H\x1b[2J"),
                Key::Char(b'h') | Key::Char(b'H') => self.message = Some(String::from("q:quit  SPACE/b:page  j/k:line  d/u:half  g/G:top/end  /?:search  n/N:next  =:info")),
                _ => {}
            }
            self.draw(term);
        }
    }

    fn switch(&mut self, dir: isize) {
        let next = self.cur as isize + dir;
        if next < 0 || next as usize >= self.docs.len() {
            self.message = Some(String::from(if dir > 0 { "No next file" } else { "No previous file" }));
            return;
        }
        self.cur = next as usize;
        self.top = 0;
        self.top_sub = 0;
        self.first_screen = true;
    }

    fn search_step(&mut self, forward: bool, times: usize) {
        let mut pos = self.top;
        for _ in 0..times {
            let from = if forward { pos + 1 } else if pos == 0 { usize::MAX } else { pos - 1 };
            if from == usize::MAX {
                self.message = Some(String::from("Pattern not found"));
                return;
            }
            match self.find(forward, from) {
                Some(i) => pos = i,
                None => {
                    self.message = Some(String::from("Pattern not found"));
                    return;
                }
            }
        }
        self.top = pos;
        self.top_sub = 0;
    }
}

pub fn less(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "NSRrFXiIEeKsMmcCqQ~",
        values: "xP",
        long: &[
            ("LINE-NUMBERS", 'N', false),
            ("chop-long-lines", 'S', false),
            ("RAW-CONTROL-CHARS", 'R', false),
            ("raw-control-chars", 'r', false),
            ("quit-if-one-screen", 'F', false),
            ("no-init", 'X', false),
            ("ignore-case", 'i', false),
            ("IGNORE-CASE", 'I', false),
            ("QUIT-AT-EOF", 'E', false),
            ("quit-at-eof", 'e', false),
            ("quit-on-intr", 'K', false),
        ],
    };
    // LESS environment options come first, like the real less.
    let mut args = alloc::vec![ctx.args[0].clone()];
    if let Some(env) = ctx.env("LESS") {
        for w in env.split_whitespace() {
            args.push(if w.starts_with('-') { w.to_string() } else { alloc::format!("-{w}") });
        }
    }
    args.extend(ctx.args[1..].iter().cloned());
    let p = match parse_opts(&args, &SPEC) {
        Ok(p) => p,
        Err(m) => {
            ctx.fail(m);
            return 1;
        }
    };
    let out_tty = ctx.stdout_tty();
    if p.operands.is_empty() && ctx.stdin_tty().is_some() {
        ctx.eprint("Missing filename (\"less --help\" for help)\n");
        return 1;
    }
    let (mut docs, err) = open_docs(ctx, &p.operands);
    let Some(tty) = out_tty else {
        cat_docs(ctx, &mut docs, false);
        return if err { 1 } else { 0 };
    };
    if docs.is_empty() {
        return 1;
    }
    ctx.flush();
    let st = Style { raw_ansi: p.has('R') || p.has('r'), line_numbers: p.has('N'), chop: p.has('S') };
    let mut less = Less {
        docs,
        cur: 0,
        st,
        icase_smart: p.has('i'),
        icase: p.has('I'),
        quit_at_eof: p.has('e') || p.has('E'),
        top: 0,
        top_sub: 0,
        hscroll: 0,
        search: None,
        message: None,
        first_screen: true,
    };
    let term = Term::open(tty);
    let (cols, rows) = term.size();
    // -F: a single file that fits on one screen is just printed.
    if p.has('F') && less.docs.len() == 1 && less.at_end(cols, rows - 1) {
        let mut out = String::new();
        let n = less.docs[0].lines.len();
        for i in 0..n {
            for r in less.rows_of(i, cols) {
                out.push_str(&r);
                out.push_str("\r\n");
            }
        }
        term.write(&out);
        return if err { 1 } else { 0 };
    }
    let alt = !p.has('X');
    if alt {
        term.write("\x1b[?1049h\x1b[H\x1b[2J");
    }
    less.run(&term);
    if alt {
        term.write("\x1b[?1049l");
    } else {
        term.write("\r\x1b[K");
    }
    drop(term);
    if err {
        1
    } else {
        0
    }
}

// ── more ───────────────────────────────────────────────────────────────────

pub fn more(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "dlfpcsu", values: "n", long: &[("lines", 'n', true)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => {
            ctx.fail(m);
            return 1;
        }
    };
    let (mut docs, err) = open_docs(ctx, &p.operands);
    let Some(tty) = ctx.stdout_tty() else {
        cat_docs(ctx, &mut docs, true);
        return if err { 1 } else { 0 };
    };
    if p.operands.is_empty() && ctx.stdin_tty().is_some() {
        ctx.eprint("more: bad usage\nTry 'more --help' for more information.\n");
        return 1;
    }
    ctx.flush();
    let term = Term::open(tty);
    let st = Style { raw_ansi: true, line_numbers: false, chop: false };
    let squeeze = p.has('s');
    let n_docs = docs.len();
    let mut search: Option<regex::bytes::Regex> = None;
    'files: for di in 0..n_docs {
        let (cols, rows) = term.size();
        let page = p.value('n').and_then(|v| v.parse::<usize>().ok()).unwrap_or(rows - 1).max(1);
        let mut used = 0;
        if n_docs > 1 {
            let h = alloc::format!("::::::::::::::\r\n{}\r\n::::::::::::::\r\n", docs[di].name);
            term.write(&h);
            used = 3;
        }
        let mut i = 0;
        let mut want = page.saturating_sub(used);
        let mut last_blank = false;
        loop {
            // Print until `want` screen rows are used or the file ends.
            while want > 0 {
                if !docs[di].ensure(i) {
                    break;
                }
                let line = docs[di].lines[i].clone();
                i += 1;
                if squeeze && line.is_empty() {
                    if last_blank {
                        continue;
                    }
                    last_blank = true;
                } else {
                    last_blank = false;
                }
                let rows_of = layout(&line, st, cols, 0, &[]);
                let mut s = String::new();
                for r in &rows_of {
                    s.push_str(r);
                    s.push_str("\r\n");
                }
                term.write(&s);
                want = want.saturating_sub(rows_of.len());
            }
            let at_eof = !docs[di].ensure(i);
            if at_eof && di + 1 == n_docs {
                break 'files;
            }
            let prompt = if at_eof {
                alloc::format!("--More--(Next file: {})", docs[di + 1].name)
            } else {
                match docs[di].size {
                    Some(sz) if sz > 0 => {
                        let consumed: u64 = docs[di].lines[..i].iter().map(|l| l.len() as u64 + 1).sum();
                        alloc::format!("--More--({}%)", (consumed * 100 / sz).min(100))
                    }
                    _ => String::from("--More--"),
                }
            };
            term.write(&alloc::format!("\x1b[7m{prompt}\x1b[27m"));
            let key = loop {
                match term.key() {
                    Key::Timeout => continue,
                    k => break k,
                }
            };
            term.write("\r\x1b[K");
            match key {
                Key::Hangup | Key::Char(b'q') | Key::Char(b'Q') | Key::Char(0x03) => break 'files,
                Key::Char(b' ') | Key::Char(b'z') | Key::PageDown => want = page,
                Key::Char(b'\n') | Key::Char(b'\r') | Key::Char(b'j') | Key::Down => want = 1,
                Key::Char(b'd') | Key::Char(0x04) => want = page / 2,
                Key::Char(b'b') | Key::Char(0x02) | Key::PageUp => {
                    i = i.saturating_sub(2 * page);
                    term.write("\r\n...back 1 page\r\n");
                    want = page;
                }
                Key::Char(b'=') => {
                    term.write(&alloc::format!("\x1b[7m{}\x1b[27m", i));
                    want = 0;
                    let _ = term.byte(true);
                    term.write("\r\x1b[K");
                }
                Key::Char(b'/') => {
                    let (_, rows) = term.size();
                    if let Some(pat) = term.read_line("/", rows) {
                        if !pat.is_empty() {
                            search = posixre::compile_bytes(&[pat], Syntax::Basic, Flags::default()).ok();
                        }
                    }
                    term.write("\r\x1b[K");
                    let Some(re) = &search else {
                        want = 0;
                        continue;
                    };
                    let mut j = i;
                    let mut found = None;
                    while docs[di].ensure(j) {
                        if re.is_match(&docs[di].lines[j]) {
                            found = Some(j);
                            break;
                        }
                        j += 1;
                    }
                    match found {
                        Some(j) => {
                            term.write("\r\n...skipping\r\n");
                            i = j.saturating_sub(2);
                            want = page;
                        }
                        None => {
                            term.write("\x1b[7mPattern not found\x1b[27m");
                            let _ = term.byte(true);
                            term.write("\r\x1b[K");
                            want = 0;
                        }
                    }
                }
                _ => want = 0,
            }
            if at_eof && want > 0 {
                continue 'files;
            }
        }
    }
    drop(term);
    if err {
        1
    } else {
        0
    }
}
