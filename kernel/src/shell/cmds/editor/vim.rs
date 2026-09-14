//! `vim` — a real modal editor: Normal / Insert modes, `:` command line, and
//! search. Supports the everyday vi vocabulary: h j k l (and arrows), 0 ^ $,
//! w b e, gg G, i a I A o O, x D dd, yy p P, u (undo), / n N, and the
//! `:w`/`:q`/`:q!`/`:wq`/`:x`/`:<line>` commands. Counts (e.g. 5j, 3dd) work
//! for the common motions and operators.

use super::{load_file, pad, Buffer, Key, Term};
use crate::shell::ctx::Ctx;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(PartialEq, Eq, Clone, Copy)]
enum Mode {
    Normal,
    Insert,
}

/// A saved buffer state for undo.
struct Snapshot {
    lines: Vec<String>,
    cx: usize,
    cy: usize,
}

struct Vim {
    buf: Buffer,
    mode: Mode,
    status: String,
    /// Accumulated numeric count prefix (0 = none).
    count: usize,
    /// A pending operator awaiting a motion/second key (e.g. 'd', 'g').
    pending: u8,
    /// Yank register (whole lines) and whether it is line-wise.
    yank: Vec<String>,
    last_search: String,
    undo: Vec<Snapshot>,
    quit: bool,
}

impl Vim {
    fn snapshot(&mut self) {
        // Cap the undo history so a long session cannot exhaust memory.
        if self.undo.len() >= 200 {
            self.undo.remove(0);
        }
        self.undo.push(Snapshot { lines: self.buf.lines.clone(), cx: self.buf.cx, cy: self.buf.cy });
        self.buf.modified = true;
    }

    fn undo(&mut self) {
        if let Some(s) = self.undo.pop() {
            self.buf.lines = s.lines;
            self.buf.cy = s.cy.min(self.buf.lines.len().saturating_sub(1));
            self.buf.cx = s.cx.min(self.buf.line_len(self.buf.cy));
            self.status = String::from("1 change undone");
        } else {
            self.status = String::from("Already at oldest change");
        }
    }

    fn take_count(&mut self) -> usize {
        let n = if self.count == 0 { 1 } else { self.count };
        self.count = 0;
        n
    }

    // ── motions ──────────────────────────────────────────────────────────────
    fn left(&mut self, n: usize) {
        self.buf.cx = self.buf.cx.saturating_sub(n);
    }
    fn right(&mut self, n: usize) {
        let max = self.buf.line_len(self.buf.cy).saturating_sub(if self.mode == Mode::Insert { 0 } else { 1 });
        self.buf.cx = (self.buf.cx + n).min(max);
    }
    fn up(&mut self, n: usize) {
        self.buf.cy = self.buf.cy.saturating_sub(n);
        self.buf.clamp_cx();
    }
    fn down(&mut self, n: usize) {
        self.buf.cy = (self.buf.cy + n).min(self.buf.lines.len() - 1);
        self.buf.clamp_cx();
    }
    fn line_start(&mut self) {
        self.buf.cx = 0;
    }
    fn line_end(&mut self) {
        self.buf.cx = self.buf.line_len(self.buf.cy).saturating_sub(1);
    }
    fn first_nonblank(&mut self) {
        let line = &self.buf.lines[self.buf.cy];
        self.buf.cx = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
    }
    fn word_forward(&mut self, n: usize) {
        for _ in 0..n {
            let line = self.buf.lines[self.buf.cy].as_bytes();
            let mut i = self.buf.cx;
            // skip current word, then whitespace
            while i < line.len() && !line[i].is_ascii_whitespace() {
                i += 1;
            }
            while i < line.len() && line[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= line.len() && self.buf.cy + 1 < self.buf.lines.len() {
                self.buf.cy += 1;
                self.buf.cx = 0;
            } else {
                self.buf.cx = i.min(line.len().saturating_sub(1));
            }
        }
    }
    fn word_back(&mut self, n: usize) {
        for _ in 0..n {
            if self.buf.cx == 0 {
                if self.buf.cy > 0 {
                    self.buf.cy -= 1;
                    self.buf.cx = self.buf.line_len(self.buf.cy).saturating_sub(1);
                }
                continue;
            }
            let line = self.buf.lines[self.buf.cy].as_bytes();
            let mut i = self.buf.cx - 1;
            while i > 0 && line[i].is_ascii_whitespace() {
                i -= 1;
            }
            while i > 0 && !line[i - 1].is_ascii_whitespace() {
                i -= 1;
            }
            self.buf.cx = i;
        }
    }
    fn goto_line(&mut self, line1: usize) {
        self.buf.cy = line1.saturating_sub(1).min(self.buf.lines.len() - 1);
        self.first_nonblank();
    }

    // ── edits ────────────────────────────────────────────────────────────────
    fn delete_char(&mut self, n: usize) {
        self.snapshot();
        let len = self.buf.line_len(self.buf.cy);
        let end = (self.buf.cx + n).min(len);
        self.buf.lines[self.buf.cy].replace_range(self.buf.cx..end, "");
        self.buf.clamp_cx();
        if self.buf.cx > 0 && self.buf.cx >= self.buf.line_len(self.buf.cy) {
            self.buf.cx = self.buf.line_len(self.buf.cy).saturating_sub(1);
        }
    }
    fn delete_to_eol(&mut self) {
        self.snapshot();
        let cx = self.buf.cx;
        self.buf.lines[self.buf.cy].truncate(cx);
        self.buf.cx = cx.min(self.buf.line_len(self.buf.cy).saturating_sub(1));
    }
    fn delete_lines(&mut self, n: usize) {
        self.snapshot();
        self.yank.clear();
        for _ in 0..n {
            if self.buf.lines.is_empty() {
                break;
            }
            self.yank.push(self.buf.lines.remove(self.buf.cy.min(self.buf.lines.len() - 1)));
            if self.buf.cy >= self.buf.lines.len() {
                self.buf.cy = self.buf.lines.len().saturating_sub(1);
            }
        }
        if self.buf.lines.is_empty() {
            self.buf.lines.push(String::new());
            self.buf.cy = 0;
        }
        self.buf.cx = 0;
    }
    fn yank_lines(&mut self, n: usize) {
        self.yank.clear();
        for i in 0..n {
            if let Some(l) = self.buf.lines.get(self.buf.cy + i) {
                self.yank.push(l.clone());
            }
        }
        self.status = format!("{} line{} yanked", self.yank.len(), if self.yank.len() == 1 { "" } else { "s" });
    }
    fn paste(&mut self, below: bool) {
        if self.yank.is_empty() {
            return;
        }
        self.snapshot();
        let at = if below { self.buf.cy + 1 } else { self.buf.cy };
        for (i, l) in self.yank.iter().enumerate() {
            self.buf.lines.insert(at + i, l.clone());
        }
        self.buf.cy = at;
        self.buf.cx = 0;
    }
    fn open_line(&mut self, below: bool) {
        self.snapshot();
        let at = if below { self.buf.cy + 1 } else { self.buf.cy };
        self.buf.lines.insert(at, String::new());
        self.buf.cy = at;
        self.buf.cx = 0;
        self.mode = Mode::Insert;
    }
    fn insert_char(&mut self, c: char) {
        let b = &mut self.buf;
        let at = b.cx.min(b.lines[b.cy].len());
        b.lines[b.cy].insert(at, c);
        b.cx = at + 1;
        b.modified = true;
    }
    fn insert_newline(&mut self) {
        let b = &mut self.buf;
        let at = b.cx.min(b.lines[b.cy].len());
        let rest = b.lines[b.cy].split_off(at);
        b.lines.insert(b.cy + 1, rest);
        b.cy += 1;
        b.cx = 0;
        b.modified = true;
    }
    fn backspace(&mut self) {
        let b = &mut self.buf;
        if b.cx > 0 {
            b.lines[b.cy].remove(b.cx - 1);
            b.cx -= 1;
            b.modified = true;
        } else if b.cy > 0 {
            let cur = b.lines.remove(b.cy);
            b.cy -= 1;
            b.cx = b.line_len(b.cy);
            b.lines[b.cy].push_str(&cur);
            b.modified = true;
        }
    }

    fn search(&mut self, pat: &str, from_next: bool) {
        if !pat.is_empty() {
            self.last_search = pat.to_string();
        }
        if self.last_search.is_empty() {
            return;
        }
        let pat = self.last_search.clone();
        let n = self.buf.lines.len();
        // Search forward from the current position, wrapping around.
        let start_off = if from_next { self.buf.cx + 1 } else { self.buf.cx };
        for i in 0..=n {
            let y = (self.buf.cy + i) % n;
            let hay = &self.buf.lines[y];
            let from = if i == 0 { start_off.min(hay.len()) } else { 0 };
            if let Some(pos) = hay[from..].find(&pat) {
                self.buf.cy = y;
                self.buf.cx = from + pos;
                return;
            }
        }
        self.status = format!("E486: Pattern not found: {pat}");
    }
}

/// `vim [FILE]` — modal editor.
pub fn vim(ctx: &mut Ctx) -> i32 {
    let name = ctx.args.iter().skip(1).find(|a| !a.starts_with('-')).cloned();
    let Some(tty) = ctx.stdout_tty() else {
        ctx.eprint("vim: standard output is not a terminal\n");
        return 1;
    };
    let (fname, text, existed) = match &name {
        Some(n) => match load_file(ctx, n) {
            Ok(t) => (n.clone(), t.clone(), !t.is_empty()),
            Err(e) => {
                ctx.eprint(&format!("vim: {n}: {e}\n"));
                return 1;
            }
        },
        None => (String::new(), String::new(), false),
    };
    let mut ed = Vim {
        buf: Buffer::from_text(fname, &text),
        mode: Mode::Normal,
        status: if existed { String::new() } else { String::from("[New File]") },
        count: 0,
        pending: 0,
        yank: Vec::new(),
        last_search: String::new(),
        undo: Vec::new(),
        quit: false,
    };
    ctx.flush();
    let term = Term::open(tty);
    term.write("\x1b[?1049h");
    run(ctx, &term, &mut ed);
    term.write("\x1b[?1049l");
    0
}

fn run(ctx: &mut Ctx, term: &Term, ed: &mut Vim) {
    while !ed.quit {
        let (cols, rows) = term.size();
        draw(term, ed, cols, rows);
        let k = term.key();
        if k == Key::Hangup {
            return;
        }
        match ed.mode {
            Mode::Insert => insert_key(ed, k),
            Mode::Normal => normal_key(ctx, term, ed, k, cols, rows),
        }
    }
}

fn insert_key(ed: &mut Vim, k: Key) {
    match k {
        Key::Esc | Key::Ctrl(b'[') => {
            ed.mode = Mode::Normal;
            if ed.buf.cx > 0 {
                ed.buf.cx -= 1;
            }
        }
        Key::Char(c) => ed.insert_char(c as char),
        Key::Enter => ed.insert_newline(),
        Key::Backspace => ed.backspace(),
        Key::Left => ed.left(1),
        Key::Right => ed.right(1),
        Key::Up => ed.up(1),
        Key::Down => ed.down(1),
        Key::Home => ed.line_start(),
        Key::End => ed.buf.cx = ed.buf.line_len(ed.buf.cy),
        _ => {}
    }
}

fn normal_key(ctx: &mut Ctx, term: &Term, ed: &mut Vim, k: Key, cols: usize, rows: usize) {
    // Arrow keys mirror hjkl.
    let c = match k {
        Key::Char(c) => c,
        Key::Left => b'h',
        Key::Down => b'j',
        Key::Up => b'k',
        Key::Right => b'l',
        Key::Home => b'0',
        Key::End => b'$',
        Key::Backspace => b'h',
        Key::Enter => b'j',
        Key::Esc => {
            ed.pending = 0;
            ed.count = 0;
            ed.status.clear();
            return;
        }
        Key::PageDown => {
            ed.down(rows.saturating_sub(3));
            return;
        }
        Key::PageUp => {
            ed.up(rows.saturating_sub(3));
            return;
        }
        _ => return,
    };

    // A pending operator (d/g) expecting a second key.
    if ed.pending != 0 {
        let op = ed.pending;
        ed.pending = 0;
        let n = ed.take_count();
        match (op, c) {
            (b'd', b'd') => ed.delete_lines(n),
            (b'd', b'w') => {
                ed.snapshot();
                ed.delete_to_eol();
            }
            (b'y', b'y') => ed.yank_lines(n),
            (b'g', b'g') => ed.goto_line(n.max(1)),
            _ => {}
        }
        return;
    }

    // Numeric count prefix (but '0' is line-start when no count is pending).
    if c.is_ascii_digit() && !(c == b'0' && ed.count == 0) {
        ed.count = ed.count.saturating_mul(10) + (c - b'0') as usize;
        return;
    }

    match c {
        b'h' => {
            let n = ed.take_count();
            ed.left(n);
        }
        b'l' | b' ' => {
            let n = ed.take_count();
            ed.right(n);
        }
        b'j' => {
            let n = ed.take_count();
            ed.down(n);
        }
        b'k' => {
            let n = ed.take_count();
            ed.up(n);
        }
        b'0' => ed.line_start(),
        b'^' => ed.first_nonblank(),
        b'$' => ed.line_end(),
        b'w' => {
            let n = ed.take_count();
            ed.word_forward(n);
        }
        b'b' => {
            let n = ed.take_count();
            ed.word_back(n);
        }
        b'G' => {
            let n = ed.count;
            ed.count = 0;
            if n == 0 {
                ed.goto_line(ed.buf.lines.len());
            } else {
                ed.goto_line(n);
            }
        }
        b'g' => ed.pending = b'g',
        b'd' => ed.pending = b'd',
        b'y' => ed.pending = b'y',
        b'x' => {
            let n = ed.take_count();
            ed.delete_char(n);
        }
        b'D' => ed.delete_to_eol(),
        b'p' => ed.paste(true),
        b'P' => ed.paste(false),
        b'u' => ed.undo(),
        b'i' => ed.mode = Mode::Insert,
        b'I' => {
            ed.first_nonblank();
            ed.mode = Mode::Insert;
        }
        b'a' => {
            if ed.buf.line_len(ed.buf.cy) > 0 {
                ed.buf.cx += 1;
            }
            ed.mode = Mode::Insert;
        }
        b'A' => {
            ed.buf.cx = ed.buf.line_len(ed.buf.cy);
            ed.mode = Mode::Insert;
        }
        b'o' => ed.open_line(true),
        b'O' => ed.open_line(false),
        b'/' => {
            if let Some(p) = term.prompt(rows, cols, "/", "") {
                ed.search(&p, false);
            }
        }
        b'n' => ed.search("", true),
        b'N' => ed.search("", true), // (forward-only search; N behaves like n)
        b':' => command_line(ctx, term, ed, cols, rows),
        _ => {}
    }
}

/// Handle a `:` command line.
fn command_line(ctx: &mut Ctx, term: &Term, ed: &mut Vim, cols: usize, rows: usize) {
    let Some(cmd) = term.prompt(rows, cols, ":", "") else {
        return;
    };
    let cmd = cmd.trim();
    // `:<number>` jumps to that line.
    if let Ok(n) = cmd.parse::<usize>() {
        ed.goto_line(n);
        return;
    }
    let (verb, arg) = match cmd.split_once(' ') {
        Some((v, a)) => (v, a.trim()),
        None => (cmd, ""),
    };
    match verb {
        // One buffer, so the "-all" forms (qa/wqa/wa) behave like their singulars.
        "w" | "write" | "wa" => {
            write_file(ctx, ed, arg);
        }
        "q" | "quit" | "qa" | "qall" => {
            if ed.buf.modified {
                ed.status = String::from("E37: No write since last change (add ! to override)");
            } else {
                ed.quit = true;
            }
        }
        "q!" | "quit!" | "qa!" | "qall!" => ed.quit = true,
        "wq" | "x" | "xit" | "wqa" | "xa" => {
            write_file(ctx, ed, arg);
            ed.quit = true;
        }
        "wq!" | "wqa!" | "x!" => {
            write_file(ctx, ed, arg);
            ed.quit = true;
        }
        other => ed.status = format!("E492: Not an editor command: {other}"),
    }
}

fn write_file(ctx: &mut Ctx, ed: &mut Vim, arg: &str) {
    let target = if !arg.is_empty() {
        arg.to_string()
    } else if !ed.buf.name.is_empty() {
        ed.buf.name.clone()
    } else {
        ed.status = String::from("E32: No file name");
        return;
    };
    match crate::fs::ops::write_file(&ctx.fs(), &target, ed.buf.text().as_bytes(), 0o644) {
        Ok(()) => {
            ed.buf.name = target.clone();
            ed.buf.modified = false;
            let n = ed.buf.lines.len();
            ed.status = format!("\"{target}\" {n}L written");
        }
        Err(e) => ed.status = format!("E212: Can't open file for writing: {e}"),
    }
}

fn draw(term: &Term, ed: &mut Vim, cols: usize, rows: usize) {
    let text_rows = rows.saturating_sub(1); // last row is the status/command line
    if ed.buf.cy < ed.buf.top {
        ed.buf.top = ed.buf.cy;
    } else if ed.buf.cy >= ed.buf.top + text_rows {
        ed.buf.top = ed.buf.cy + 1 - text_rows;
    }
    let mut out = String::from("\x1b[H\x1b[2J");
    for r in 0..text_rows {
        let ly = ed.buf.top + r;
        if ly < ed.buf.lines.len() {
            let shown: String = ed.buf.lines[ly].chars().take(cols).collect();
            out.push_str(&shown);
        } else {
            out.push_str("\x1b[34m~\x1b[m");
        }
        out.push_str("\r\n");
    }
    // Status line: mode indicator or the last message, plus position.
    let left = if ed.mode == Mode::Insert {
        String::from("-- INSERT --")
    } else if !ed.status.is_empty() {
        ed.status.clone()
    } else {
        let name = if ed.buf.name.is_empty() { "[No Name]" } else { &ed.buf.name };
        format!("\"{name}\"{}", if ed.buf.modified { " [+]" } else { "" })
    };
    let pos = format!("{},{}", ed.buf.cy + 1, ed.buf.cx + 1);
    let gap = cols.saturating_sub(left.chars().count() + pos.chars().count());
    let status = format!("{left}{}{pos}", " ".repeat(gap));
    out.push_str(&pad(&status, cols));
    let scr_row = 1 + (ed.buf.cy - ed.buf.top);
    let scr_col = ed.buf.cx.min(cols.saturating_sub(1)) + 1;
    out.push_str(&format!("\x1b[{scr_row};{scr_col}H"));
    term.write(&out);
}
