//! `sed`: the GNU stream editor.
//!
//! The script is compiled once into a flat command list (blocks become
//! jumps), then each input line runs through it with a pattern space, a
//! hold space and per-command range state. Supported: every POSIX command
//! plus the common GNU ones (`F z T R W e`-less set), `-n -e -f -E -s -i -z`,
//! addresses `N $ /re/I \%re% first~step addr,+N addr,~N 0,/re/` and `!`.

use super::posixre::{self, Flags, Syntax};
use crate::errno::Errno;
use crate::fs::file::{flags, File};
use crate::fs::ops;
use crate::shell::ctx::Ctx;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use regex::bytes::Regex;

// ── compiled script ────────────────────────────────────────────────────────

#[derive(Clone)]
enum Addr {
    Line(u64),
    Last,
    /// `None`: the last regex used at run time (`//`).
    Re(Option<Regex>),
    Step(u64, u64),
    /// `0` in `0,/re/`.
    Zero,
}

#[derive(Clone)]
enum Addr2 {
    A(Addr),
    Plus(u64),
    Multiple(u64),
}

enum Repl {
    Lit(Vec<u8>),
    Group(usize),
    Upper,
    Lower,
    OneUpper,
    OneLower,
    End,
}

struct Subst {
    re: Option<Regex>,
    repl: Vec<Repl>,
    global: bool,
    nth: usize,
    print: usize,
    wfile: Option<usize>,
}

enum Kind {
    /// `{`: jump past the matching `}` when the address does not match.
    Block(usize),
    EndBlock,
    LineNo,
    Append(String),
    Insert(String),
    Change(String),
    Branch(usize),
    BranchIf(usize),
    BranchIfNot(usize),
    Delete,
    DeleteFirst,
    GetHold,
    GetHoldAppend,
    Hold,
    HoldAppend,
    Exchange,
    List(usize),
    Next,
    NextAppend,
    Print,
    PrintFirst,
    Quit(i32),
    QuitSilent(i32),
    ReadFile(String),
    ReadLine(usize),
    WriteFile(usize),
    WriteFirst(usize),
    Subst(Subst),
    Translit(Vec<(char, char)>),
    Zap,
    FileName,
    Nop,
}

struct Cmd {
    a1: Option<Addr>,
    a2: Option<Addr2>,
    neg: bool,
    kind: Kind,
}

/// Unresolved branch targets while parsing.
enum Pending {
    Label(usize, String),
}

struct Compiler<'a> {
    s: Vec<char>,
    i: usize,
    ere: bool,
    cmds: Vec<Cmd>,
    labels: BTreeMap<String, usize>,
    pending: Vec<Pending>,
    blocks: Vec<usize>,
    wfiles: &'a mut Vec<(String, Option<Arc<dyn File>>)>,
    rfiles: &'a mut Vec<String>,
}

type CResult<T> = Result<T, String>;

impl Compiler<'_> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.i += 1;
        }
        c
    }
    fn err<T>(&self, m: &str) -> CResult<T> {
        Err(alloc::format!("-e expression #1, char {}: {m}", self.i))
    }
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.i += 1;
        }
    }
    fn skip_ws_nl(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t') | Some('\n') | Some(';')) {
            self.i += 1;
        }
    }

    fn number(&mut self) -> u64 {
        let mut n: u64 = 0;
        while let Some(c) = self.peek().filter(|c| c.is_ascii_digit()) {
            n = n.saturating_mul(10).saturating_add(c.to_digit(10).unwrap_or(0) as u64);
            self.i += 1;
        }
        n
    }

    /// Text up to an unescaped `delim`, with `\delim` made literal.
    fn delimited(&mut self, delim: char, is_regex: bool) -> CResult<String> {
        let mut o = String::new();
        loop {
            let Some(c) = self.bump() else { return self.err(&alloc::format!("unterminated address regex")) };
            if c == delim {
                return Ok(o);
            }
            if c == '\\' {
                let Some(n) = self.bump() else { return self.err("unterminated address regex") };
                if n == delim {
                    if is_regex && delim != '^' && delim != '\\' {
                        // A literal delimiter inside a regex.
                        if delim == ']' {
                            o.push_str("[]]");
                        } else {
                            o.push('[');
                            o.push(delim);
                            o.push(']');
                        }
                    } else if is_regex {
                        o.push('\\');
                        o.push(n);
                    } else {
                        o.push(n);
                    }
                } else if n == '\n' && !is_regex {
                    o.push('\n');
                } else {
                    o.push('\\');
                    o.push(n);
                }
                continue;
            }
            if c == '\n' && is_regex {
                return self.err("unterminated address regex");
            }
            o.push(c);
        }
    }

    fn regex(&self, pat: &str, icase: bool, multi: bool) -> CResult<Option<Regex>> {
        if pat.is_empty() {
            return Ok(None);
        }
        let syn = if self.ere { Syntax::Extended } else { Syntax::Basic };
        posixre::compile_bytes(&[pat.to_string()], syn, Flags { icase, multiline: multi, dot_nl: true, ..Default::default() }).map(Some).map_err(|m| alloc::format!("-e expression #1, char {}: {m}", self.i))
    }

    fn address(&mut self) -> CResult<Option<Addr>> {
        match self.peek() {
            Some(c) if c.is_ascii_digit() => {
                let n = self.number();
                if self.peek() == Some('~') {
                    self.i += 1;
                    let step = self.number();
                    return Ok(Some(Addr::Step(n, step)));
                }
                Ok(Some(if n == 0 { Addr::Zero } else { Addr::Line(n) }))
            }
            Some('$') => {
                self.i += 1;
                Ok(Some(Addr::Last))
            }
            Some('/') | Some('\\') => {
                let delim = if self.bump() == Some('\\') {
                    match self.bump() {
                        Some(d) if d != '\n' && d != '\\' => d,
                        _ => return self.err("unexpected `,'"),
                    }
                } else {
                    '/'
                };
                let pat = self.delimited(delim, true)?;
                let mut icase = false;
                let mut multi = false;
                loop {
                    match self.peek() {
                        Some('I') => icase = true,
                        Some('M') => multi = true,
                        _ => break,
                    }
                    self.i += 1;
                }
                Ok(Some(Addr::Re(self.regex(&pat, icase, multi)?)))
            }
            _ => Ok(None),
        }
    }

    /// Rest of the line (for `a i c r w b t : ...`), honouring `\` escapes
    /// for text commands.
    fn text_arg(&mut self) -> CResult<String> {
        self.skip_ws();
        // `a\` newline text  |  `a text` (GNU one-liner)  |  `a\text`.
        if self.peek() == Some('\\') {
            self.i += 1;
            if self.peek() == Some('\n') {
                self.i += 1;
            }
        }
        let mut o = String::new();
        loop {
            match self.bump() {
                None => break,
                Some('\n') => break,
                Some('\\') => match self.bump() {
                    Some('\n') => o.push('\n'),
                    Some('t') => o.push('\t'),
                    Some(c) => o.push(c),
                    None => break,
                },
                Some(c) => o.push(c),
            }
        }
        Ok(o)
    }

    fn word_arg(&mut self) -> String {
        self.skip_ws();
        let mut o = String::new();
        while let Some(c) = self.peek() {
            if c == '\n' || c == ';' || c == '}' {
                break;
            }
            o.push(c);
            self.i += 1;
        }
        o.trim_end().to_string()
    }

    fn filename_arg(&mut self) -> String {
        self.skip_ws();
        let mut o = String::new();
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            o.push(c);
            self.i += 1;
        }
        o
    }

    fn wfile(&mut self, name: String) -> usize {
        if let Some(i) = self.wfiles.iter().position(|(n, _)| *n == name) {
            return i;
        }
        self.wfiles.push((name, None));
        self.wfiles.len() - 1
    }

    fn replacement(&mut self, delim: char) -> CResult<Vec<Repl>> {
        let mut parts = Vec::new();
        let mut lit: Vec<u8> = Vec::new();
        let flush = |lit: &mut Vec<u8>, parts: &mut Vec<Repl>| {
            if !lit.is_empty() {
                parts.push(Repl::Lit(core::mem::take(lit)));
            }
        };
        loop {
            let Some(c) = self.bump() else { return self.err("unterminated `s' command") };
            if c == delim {
                break;
            }
            let mut b = [0u8; 4];
            match c {
                '&' => {
                    flush(&mut lit, &mut parts);
                    parts.push(Repl::Group(0));
                }
                '\\' => {
                    let Some(n) = self.bump() else { return self.err("unterminated `s' command") };
                    match n {
                        '0'..='9' => {
                            flush(&mut lit, &mut parts);
                            parts.push(Repl::Group(n.to_digit(10).unwrap_or(0) as usize));
                        }
                        'n' => lit.push(b'\n'),
                        't' => lit.push(b'\t'),
                        'r' => lit.push(b'\r'),
                        'a' => lit.push(0x07),
                        'f' => lit.push(0x0c),
                        'v' => lit.push(0x0b),
                        '\n' => lit.push(b'\n'),
                        'U' | 'L' | 'u' | 'l' | 'E' => {
                            flush(&mut lit, &mut parts);
                            parts.push(match n {
                                'U' => Repl::Upper,
                                'L' => Repl::Lower,
                                'u' => Repl::OneUpper,
                                'l' => Repl::OneLower,
                                _ => Repl::End,
                            });
                        }
                        other => lit.extend_from_slice(other.encode_utf8(&mut b).as_bytes()),
                    }
                }
                other => lit.extend_from_slice(other.encode_utf8(&mut b).as_bytes()),
            }
        }
        flush(&mut lit, &mut parts);
        Ok(parts)
    }

    fn end_of_command(&mut self) -> CResult<()> {
        self.skip_ws();
        match self.peek() {
            None | Some('\n') | Some(';') | Some('}') | Some('#') => Ok(()),
            Some(_) => self.err("extra characters after command"),
        }
    }

    fn compile(&mut self) -> CResult<()> {
        loop {
            self.skip_ws_nl();
            let Some(c) = self.peek() else { break };
            if c == '#' {
                while self.peek().is_some_and(|c| c != '\n') {
                    self.i += 1;
                }
                continue;
            }
            let a1 = self.address()?;
            let mut a2 = None;
            if a1.is_some() && self.peek() == Some(',') {
                self.i += 1;
                self.skip_ws();
                a2 = Some(match self.peek() {
                    Some('+') => {
                        self.i += 1;
                        Addr2::Plus(self.number())
                    }
                    Some('~') => {
                        self.i += 1;
                        Addr2::Multiple(self.number())
                    }
                    _ => match self.address()? {
                        Some(Addr::Zero) => return self.err("invalid usage of line address 0"),
                        Some(a) => Addr2::A(a),
                        None => return self.err("unexpected `,'"),
                    },
                });
            }
            if matches!(a1, Some(Addr::Zero)) && !matches!(a2, Some(Addr2::A(Addr::Re(_)))) {
                return self.err("invalid usage of line address 0");
            }
            self.skip_ws();
            let mut neg = false;
            while self.peek() == Some('!') {
                neg = true;
                self.i += 1;
                self.skip_ws();
            }
            let Some(cmd) = self.bump() else { return self.err("missing command") };
            let kind = match cmd {
                '{' => {
                    self.blocks.push(self.cmds.len());
                    Kind::Block(0)
                }
                '}' => {
                    if a1.is_some() {
                        return self.err("} doesn't want any addresses");
                    }
                    let Some(open) = self.blocks.pop() else { return self.err("unexpected `}'") };
                    let here = self.cmds.len();
                    if let Kind::Block(t) = &mut self.cmds[open].kind {
                        *t = here + 1;
                    }
                    self.end_of_command()?;
                    Kind::EndBlock
                }
                '=' => {
                    self.end_of_command()?;
                    Kind::LineNo
                }
                'a' | 'i' | 'c' => {
                    let t = self.text_arg()?;
                    match cmd {
                        'a' => Kind::Append(t),
                        'i' => Kind::Insert(t),
                        _ => Kind::Change(t),
                    }
                }
                ':' => {
                    if a1.is_some() {
                        return self.err(": doesn't want any addresses");
                    }
                    let l = self.word_arg();
                    if l.is_empty() {
                        return self.err("\":\" lacks a label");
                    }
                    self.labels.insert(l, self.cmds.len());
                    Kind::Nop
                }
                'b' | 't' | 'T' => {
                    let l = self.word_arg();
                    let idx = self.cmds.len();
                    if !l.is_empty() {
                        self.pending.push(Pending::Label(idx, l));
                    }
                    // usize::MAX = end of script until resolved.
                    match cmd {
                        'b' => Kind::Branch(usize::MAX),
                        't' => Kind::BranchIf(usize::MAX),
                        _ => Kind::BranchIfNot(usize::MAX),
                    }
                }
                'd' => Kind::Delete,
                'D' => Kind::DeleteFirst,
                'g' => Kind::GetHold,
                'G' => Kind::GetHoldAppend,
                'h' => Kind::Hold,
                'H' => Kind::HoldAppend,
                'x' => Kind::Exchange,
                'n' => Kind::Next,
                'N' => Kind::NextAppend,
                'p' => Kind::Print,
                'P' => Kind::PrintFirst,
                'z' => Kind::Zap,
                'F' => Kind::FileName,
                'l' => {
                    self.skip_ws();
                    let n = self.number();
                    Kind::List(if n == 0 { 70 } else { n as usize })
                }
                'q' | 'Q' => {
                    self.skip_ws();
                    let n = self.number() as i32;
                    if cmd == 'q' {
                        Kind::Quit(n)
                    } else {
                        Kind::QuitSilent(n)
                    }
                }
                'r' => Kind::ReadFile(self.filename_arg()),
                'R' => {
                    let f = self.filename_arg();
                    self.rfiles.push(f);
                    Kind::ReadLine(self.rfiles.len() - 1)
                }
                'w' | 'W' => {
                    let f = self.filename_arg();
                    let i = self.wfile(f);
                    if cmd == 'w' {
                        Kind::WriteFile(i)
                    } else {
                        Kind::WriteFirst(i)
                    }
                }
                's' => {
                    let Some(delim) = self.bump().filter(|&d| d != '\n' && d != '\\') else { return self.err("unterminated `s' command") };
                    let pat = self.delimited(delim, true).map_err(|_| alloc::format!("-e expression #1, char {}: unterminated `s' command", self.i))?;
                    let repl = self.replacement(delim)?;
                    let mut s = Subst { re: None, repl, global: false, nth: 1, print: 0, wfile: None };
                    let mut icase = false;
                    let mut multi = false;
                    let mut nth_set = false;
                    loop {
                        match self.peek() {
                            Some('g') => s.global = true,
                            Some('p') => s.print += 1,
                            Some('i') | Some('I') => icase = true,
                            Some('m') | Some('M') => multi = true,
                            Some('e') => return self.err("the `e' flag is not supported"),
                            Some(c) if c.is_ascii_digit() => {
                                if nth_set {
                                    return self.err("multiple number options to `s' command");
                                }
                                let n = self.number();
                                if n == 0 {
                                    return self.err("number option to `s' command may not be zero");
                                }
                                s.nth = n as usize;
                                nth_set = true;
                                continue;
                            }
                            Some('w') => {
                                self.i += 1;
                                let f = self.filename_arg();
                                s.wfile = Some(self.wfile(f));
                                break;
                            }
                            _ => break,
                        }
                        self.i += 1;
                    }
                    s.re = self.regex(&pat, icase, multi)?;
                    self.end_of_command()?;
                    Kind::Subst(s)
                }
                'y' => {
                    let Some(delim) = self.bump().filter(|&d| d != '\n' && d != '\\') else { return self.err("unterminated `y' command") };
                    let src = self.delimited(delim, false)?;
                    let dst = self.delimited(delim, false)?;
                    let un = |s: &str| -> Vec<char> {
                        let mut v = Vec::new();
                        let mut it = s.chars();
                        while let Some(c) = it.next() {
                            if c == '\\' {
                                match it.next() {
                                    Some('n') => v.push('\n'),
                                    Some('t') => v.push('\t'),
                                    Some('\\') => v.push('\\'),
                                    Some(o) => v.push(o),
                                    None => v.push('\\'),
                                }
                            } else {
                                v.push(c);
                            }
                        }
                        v
                    };
                    let (a, b) = (un(&src), un(&dst));
                    if a.len() != b.len() {
                        return self.err("strings for `y' command are different lengths");
                    }
                    self.end_of_command()?;
                    Kind::Translit(a.into_iter().zip(b).collect())
                }
                '#' => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.i += 1;
                    }
                    Kind::Nop
                }
                other => return self.err(&alloc::format!("unknown command: `{other}'")),
            };
            // Commands that take no argument must end here.
            if matches!(cmd, 'd' | 'D' | 'g' | 'G' | 'h' | 'H' | 'x' | 'n' | 'N' | 'p' | 'P' | 'z' | 'F' | 'l' | 'q' | 'Q') {
                self.end_of_command()?;
            }
            self.cmds.push(Cmd { a1, a2, neg, kind });
        }
        if !self.blocks.is_empty() {
            return self.err("unmatched `{'");
        }
        let end = self.cmds.len();
        for p in core::mem::take(&mut self.pending) {
            let Pending::Label(idx, name) = p;
            let Some(&target) = self.labels.get(&name) else {
                return Err(alloc::format!("-e expression #1, char {}: can't find label for jump to `{name}'", self.i));
            };
            match &mut self.cmds[idx].kind {
                Kind::Branch(t) | Kind::BranchIf(t) | Kind::BranchIfNot(t) => *t = target,
                _ => {}
            }
        }
        for c in &mut self.cmds {
            match &mut c.kind {
                Kind::Branch(t) | Kind::BranchIf(t) | Kind::BranchIfNot(t) if *t == usize::MAX => *t = end,
                _ => {}
            }
        }
        Ok(())
    }
}

// ── input ──────────────────────────────────────────────────────────────────

struct Line {
    text: Vec<u8>,
    newline: bool,
}

/// Line reader over the input files with one line of lookahead (for `$`).
struct Input {
    files: Vec<String>,
    next_file: usize,
    cur: Option<Arc<dyn File>>,
    cur_name: String,
    buf: Vec<u8>,
    eof: bool,
    eol: u8,
    separate: bool,
    ahead: Option<(Line, String)>,
    errors: bool,
}

impl Input {
    fn open_next(&mut self, ctx: &mut Ctx) -> bool {
        while self.next_file < self.files.len() {
            let name = self.files[self.next_file].clone();
            self.next_file += 1;
            match ctx.open_input(&name) {
                Ok(f) => {
                    self.cur = Some(f);
                    self.cur_name = name;
                    self.buf.clear();
                    self.eof = false;
                    return true;
                }
                Err(e) => {
                    let n = ctx.name().to_string();
                    let msg = if e == Errno::EISDIR { alloc::format!("{n}: couldn't edit {name}: not a regular file\n") } else { alloc::format!("{n}: can't read {name}: {e}\n") };
                    ctx.eprint(&msg);
                    self.errors = true;
                }
            }
        }
        false
    }

    /// Raw next line from the current file (None at its end).
    fn raw_line(&mut self, ctx: &mut Ctx) -> Option<Line> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == self.eol) {
                let mut text: Vec<u8> = self.buf.drain(..=pos).collect();
                text.pop();
                return Some(Line { text, newline: true });
            }
            if self.eof {
                if self.buf.is_empty() {
                    return None;
                }
                return Some(Line { text: core::mem::take(&mut self.buf), newline: false });
            }
            let f = self.cur.clone()?;
            let mut chunk = alloc::vec![0u8; 16 * 1024];
            match f.read(&mut chunk) {
                Ok(0) => self.eof = true,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(_) => self.eof = true,
            }
            if ctx.should_stop() {
                self.eof = true;
                self.buf.clear();
            }
        }
    }

    /// Next line across files (or within the current file if `separate`).
    fn fetch(&mut self, ctx: &mut Ctx, cross_files: bool) -> Option<(Line, String)> {
        loop {
            if self.cur.is_none() && !self.open_next(ctx) {
                return None;
            }
            if let Some(l) = self.raw_line(ctx) {
                return Some((l, self.cur_name.clone()));
            }
            self.cur = None;
            if !cross_files {
                return None;
            }
        }
    }

    fn next(&mut self, ctx: &mut Ctx) -> Option<(Line, String)> {
        if let Some(a) = self.ahead.take() {
            return Some(a);
        }
        let sep = self.separate;
        self.fetch(ctx, !sep)
    }

    /// Is the line just returned the last one?
    fn at_last(&mut self, ctx: &mut Ctx) -> bool {
        if self.ahead.is_none() {
            let sep = self.separate;
            self.ahead = self.fetch(ctx, !sep);
        }
        self.ahead.is_none()
    }
}

// ── execution ──────────────────────────────────────────────────────────────

struct Exec<'a> {
    ctx: &'a mut Ctx,
    cmds: &'a [Cmd],
    quiet: bool,
    /// `-i`: output goes into this buffer instead of stdout.
    sink: Option<Vec<u8>>,
    missing_newline: bool,
    ps: Vec<u8>,
    hs: Vec<u8>,
    ps_newline: bool,
    line_no: u64,
    append: VecDeque<Vec<u8>>,
    range_active: Vec<bool>,
    range_end: Vec<u64>,
    last_re: Option<Regex>,
    replaced: bool,
    wfiles: &'a mut Vec<(String, Option<Arc<dyn File>>)>,
    rfiles: Vec<(String, Option<Arc<dyn File>>, Vec<u8>)>,
    exit: Option<i32>,
    file_name: String,
}

enum Flow {
    /// End the cycle; `bool`: print the pattern space.
    EndCycle(bool),
    /// `D` with a newline: restart without reading.
    Restart,
    Quit(bool),
}

impl Exec<'_> {
    fn out(&mut self, data: &[u8]) {
        match &mut self.sink {
            Some(v) => v.extend_from_slice(data),
            None => self.ctx.write(data),
        }
    }

    /// Emit text that ends with a newline (after any owed newline).
    fn out_line(&mut self, data: &[u8]) {
        if self.missing_newline {
            self.out(b"\n");
            self.missing_newline = false;
        }
        self.out(data);
        self.out(b"\n");
    }

    fn print_ps(&mut self, upto_nl: bool) {
        if self.missing_newline {
            self.out(b"\n");
            self.missing_newline = false;
        }
        let ps = core::mem::take(&mut self.ps);
        let text: &[u8] = if upto_nl { ps.split(|&b| b == b'\n').next().unwrap_or(&[]) } else { &ps };
        self.out(text);
        if self.ps_newline || upto_nl {
            self.out(b"\n");
        } else {
            self.missing_newline = true;
        }
        self.ps = ps;
    }

    fn matches(&mut self, a: &Addr, last: bool) -> bool {
        match a {
            Addr::Line(n) => self.line_no == *n,
            Addr::Last => last,
            Addr::Zero => false,
            Addr::Step(first, step) => {
                if *step == 0 {
                    self.line_no == *first
                } else {
                    self.line_no >= *first && (self.line_no - first) % step == 0
                }
            }
            Addr::Re(r) => {
                let re = match r {
                    Some(r) => {
                        self.last_re = Some(r.clone());
                        r.clone()
                    }
                    None => match &self.last_re {
                        Some(r) => r.clone(),
                        None => return false,
                    },
                };
                re.is_match(&self.ps)
            }
        }
    }

    fn selected(&mut self, i: usize, input: &mut Input) -> bool {
        let c = &self.cmds[i];
        let Some(a1) = c.a1.clone() else { return !c.neg };
        let need_last = matches!(a1, Addr::Last) || matches!(c.a2, Some(Addr2::A(Addr::Last)));
        let last = need_last && input.at_last(self.ctx);
        let hit = match c.a2.clone() {
            None => self.matches(&a1, last),
            Some(a2) => {
                if self.range_active[i] {
                    let end = match &a2 {
                        Addr2::A(Addr::Line(n)) => self.line_no >= *n,
                        Addr2::A(a) => {
                            let a = a.clone();
                            self.matches(&a, last)
                        }
                        Addr2::Plus(_) => self.line_no >= self.range_end[i],
                        Addr2::Multiple(m) => *m == 0 || self.line_no % m == 0,
                    };
                    if end {
                        self.range_active[i] = false;
                    }
                    true
                } else if matches!(a1, Addr::Zero) {
                    // `0,/re/`: the range is active before line 1, so /re/
                    // may already end it on line 1.
                    if self.line_no != 1 {
                        return c.neg;
                    }
                    self.range_active[i] = true;
                    if let Addr2::A(a) = &a2 {
                        let a = a.clone();
                        if self.matches(&a, last) {
                            self.range_active[i] = false;
                        }
                    }
                    true
                } else {
                    let start = self.matches(&a1, last);
                    if start {
                        // Does the range end on this very line?
                        let single = match &a2 {
                            Addr2::A(Addr::Line(n)) => *n <= self.line_no,
                            Addr2::Plus(n) => {
                                self.range_end[i] = self.line_no + n;
                                *n == 0
                            }
                            Addr2::Multiple(m) => *m == 0 || self.line_no % m == 0,
                            _ => false,
                        };
                        self.range_active[i] = !single;
                    }
                    start
                }
            }
        };
        hit != c.neg
    }

    fn substitute(&mut self, s: &Subst) -> bool {
        let re = match &s.re {
            Some(r) => {
                self.last_re = Some(r.clone());
                r.clone()
            }
            None => match &self.last_re {
                Some(r) => r.clone(),
                None => {
                    self.ctx.fail("no previous regular expression");
                    self.exit = Some(1);
                    return false;
                }
            },
        };
        let mut out: Vec<u8> = Vec::with_capacity(self.ps.len() + 16);
        let mut last = 0;
        let mut count = 0;
        let mut did = false;
        let mut pos = 0;
        let ps = core::mem::take(&mut self.ps);
        while pos <= ps.len() {
            let Some(caps) = re.captures_at(&ps, pos) else { break };
            let m = caps.get(0).expect("group 0");
            count += 1;
            if count >= s.nth {
                out.extend_from_slice(&ps[last..m.start()]);
                expand_repl(&s.repl, &caps, &mut out);
                last = m.end();
                did = true;
                if !s.global {
                    break;
                }
            }
            // Empty matches advance by one character.
            pos = if m.end() == m.start() {
                let step = ps[m.end()..].first().map(|&b| utf8_len(b)).unwrap_or(1);
                if count >= s.nth && m.end() < ps.len() {
                    out.extend_from_slice(&ps[m.end()..m.end() + step]);
                    last = m.end() + step;
                }
                m.end() + step
            } else {
                m.end()
            };
        }
        if !did {
            self.ps = ps;
            return false;
        }
        out.extend_from_slice(&ps[last.min(ps.len())..]);
        self.ps = out;
        true
    }

    fn write_to(&mut self, idx: usize, data: &[u8]) {
        let name = self.wfiles[idx].0.clone();
        match name.as_str() {
            "/dev/stdout" => {
                self.out(data);
                self.out(b"\n");
            }
            "/dev/stderr" => {
                let mut v = data.to_vec();
                v.push(b'\n');
                self.ctx.eprint(&String::from_utf8_lossy(&v));
            }
            _ => {
                if let Some(f) = &self.wfiles[idx].1 {
                    let mut v = data.to_vec();
                    v.push(b'\n');
                    let _ = f.write_all(&v);
                }
            }
        }
    }

    fn list(&mut self, width: usize) {
        let mut o = String::new();
        let mut col = 0;
        let ps = self.ps.clone();
        for &b in &ps {
            let piece = match b {
                b'\\' => String::from("\\\\"),
                0x07 => String::from("\\a"),
                0x08 => String::from("\\b"),
                0x0c => String::from("\\f"),
                b'\n' => String::from("\\n"),
                b'\r' => String::from("\\r"),
                b'\t' => String::from("\\t"),
                0x0b => String::from("\\v"),
                0x20..=0x7e => (b as char).to_string(),
                _ => alloc::format!("\\{:03o}", b),
            };
            if width > 1 && col + piece.len() > width - 1 {
                o.push_str("\\\n");
                col = 0;
            }
            col += piece.len();
            o.push_str(&piece);
        }
        o.push('$');
        self.out_line(o.as_bytes());
    }

    fn run_cycle(&mut self, input: &mut Input) -> Flow {
        let mut pc = 0;
        self.replaced = false;
        while pc < self.cmds.len() {
            if self.exit.is_some() {
                return Flow::Quit(false);
            }
            let i = pc;
            pc += 1;
            if !self.selected(i, input) {
                if let Kind::Block(end) = self.cmds[i].kind {
                    pc = end;
                }
                continue;
            }
            match &self.cmds[i].kind {
                Kind::Block(_) | Kind::EndBlock | Kind::Nop => {}
                Kind::LineNo => {
                    let s = self.line_no.to_string();
                    self.out_line(s.as_bytes());
                }
                Kind::Append(t) => {
                    let t = t.clone().into_bytes();
                    self.append.push_back(t);
                }
                Kind::Insert(t) => {
                    let t = t.clone();
                    self.out_line(t.as_bytes());
                }
                Kind::Change(t) => {
                    // In a range, the text replaces the whole range (printed at its end).
                    let t = t.clone();
                    let in_range = self.cmds[i].a2.is_some() && !self.cmds[i].neg;
                    if !in_range || !self.range_active[i] {
                        self.out_line(t.as_bytes());
                    }
                    return Flow::EndCycle(false);
                }
                Kind::Branch(t) => pc = *t,
                Kind::BranchIf(t) => {
                    if self.replaced {
                        self.replaced = false;
                        pc = *t;
                    }
                }
                Kind::BranchIfNot(t) => {
                    if !self.replaced {
                        pc = *t;
                    } else {
                        self.replaced = false;
                    }
                }
                Kind::Delete => return Flow::EndCycle(false),
                Kind::DeleteFirst => match self.ps.iter().position(|&b| b == b'\n') {
                    Some(p) => {
                        self.ps.drain(..=p);
                        return Flow::Restart;
                    }
                    None => return Flow::EndCycle(false),
                },
                Kind::GetHold => self.ps = self.hs.clone(),
                Kind::GetHoldAppend => {
                    self.ps.push(b'\n');
                    let h = self.hs.clone();
                    self.ps.extend_from_slice(&h);
                }
                Kind::Hold => self.hs = self.ps.clone(),
                Kind::HoldAppend => {
                    self.hs.push(b'\n');
                    let p = self.ps.clone();
                    self.hs.extend_from_slice(&p);
                }
                Kind::Exchange => core::mem::swap(&mut self.ps, &mut self.hs),
                Kind::List(w) => {
                    let w = *w;
                    self.list(w);
                }
                Kind::Next => {
                    if input.at_last(self.ctx) {
                        // GNU: at end of input `n` ends the script (autoprint included).
                        return Flow::Quit(true);
                    }
                    if !self.quiet {
                        self.print_ps(false);
                    }
                    self.flush_append();
                    let Some((l, name)) = input.next(self.ctx) else { return Flow::Quit(false) };
                    self.load(l, name);
                }
                Kind::NextAppend => {
                    if input.at_last(self.ctx) {
                        return Flow::Quit(true);
                    }
                    self.flush_append();
                    let Some((l, name)) = input.next(self.ctx) else { return Flow::Quit(true) };
                    self.ps.push(b'\n');
                    self.ps.extend_from_slice(&l.text);
                    self.ps_newline = l.newline;
                    self.line_no += 1;
                    self.file_name = name;
                }
                Kind::Print => self.print_ps(false),
                Kind::PrintFirst => self.print_ps(true),
                Kind::Quit(code) => {
                    self.exit = Some(*code);
                    return Flow::Quit(true);
                }
                Kind::QuitSilent(code) => {
                    self.exit = Some(*code);
                    return Flow::Quit(false);
                }
                Kind::ReadFile(f) => {
                    let f = f.clone();
                    let data = if f == "/dev/stdin" { self.ctx.read_input("-").ok() } else { ops::read_file(&self.ctx.fs(), &f).ok() };
                    if let Some(mut d) = data {
                        if d.last() == Some(&b'\n') {
                            d.pop();
                        }
                        if !d.is_empty() {
                            self.append.push_back(d);
                        }
                    }
                }
                Kind::ReadLine(idx) => {
                    let idx = *idx;
                    if let Some(l) = self.read_rline(idx) {
                        self.append.push_back(l);
                    }
                }
                Kind::WriteFile(idx) => {
                    let (idx, d) = (*idx, self.ps.clone());
                    self.write_to(idx, &d);
                }
                Kind::WriteFirst(idx) => {
                    let idx = *idx;
                    let d: Vec<u8> = self.ps.split(|&b| b == b'\n').next().unwrap_or(&[]).to_vec();
                    self.write_to(idx, &d);
                }
                Kind::Subst(s) => {
                    if self.substitute(s) {
                        self.replaced = true;
                        for _ in 0..s.print {
                            self.print_ps(false);
                        }
                        if let Some(w) = s.wfile {
                            let d = self.ps.clone();
                            self.write_to(w, &d);
                        }
                    }
                }
                Kind::Translit(map) => {
                    let text = String::from_utf8_lossy(&self.ps).into_owned();
                    let t: String = text.chars().map(|c| map.iter().find(|(a, _)| *a == c).map(|(_, b)| *b).unwrap_or(c)).collect();
                    self.ps = t.into_bytes();
                }
                Kind::Zap => self.ps.clear(),
                Kind::FileName => {
                    let n = self.file_name.clone();
                    self.out_line(n.as_bytes());
                }
            }
        }
        Flow::EndCycle(true)
    }

    fn read_rline(&mut self, idx: usize) -> Option<Vec<u8>> {
        let (name, file, buf) = &mut self.rfiles[idx];
        if file.is_none() {
            *file = ops::open(&self.ctx.fs(), name, flags::O_RDONLY, 0).ok();
        }
        let f = file.clone()?;
        loop {
            if let Some(p) = buf.iter().position(|&b| b == b'\n') {
                let mut l: Vec<u8> = buf.drain(..=p).collect();
                l.pop();
                return Some(l);
            }
            let mut chunk = [0u8; 4096];
            match f.read(&mut chunk) {
                Ok(0) | Err(_) => {
                    if buf.is_empty() {
                        return None;
                    }
                    return Some(core::mem::take(buf));
                }
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn flush_append(&mut self) {
        while let Some(t) = self.append.pop_front() {
            self.out_line(&t);
        }
    }

    fn load(&mut self, l: Line, name: String) {
        self.ps = l.text;
        self.ps_newline = l.newline;
        self.line_no += 1;
        self.file_name = name;
    }

    /// Process the whole input. Returns false when a `q`/`Q` ended it.
    fn run(&mut self, input: &mut Input) -> bool {
        let mut restart = false;
        loop {
            if !restart {
                let Some((l, name)) = input.next(self.ctx) else { return true };
                self.load(l, name);
            }
            restart = false;
            let flow = self.run_cycle(input);
            let (print, quit) = match flow {
                Flow::EndCycle(p) => (p, false),
                Flow::Restart => {
                    // `D`: no autoprint; the next cycle runs on the rest.
                    self.flush_append();
                    restart = true;
                    continue;
                }
                Flow::Quit(p) => (p, true),
            };
            if print && !self.quiet {
                self.print_ps(false);
            }
            self.flush_append();
            if quit {
                return false;
            }
            if self.ctx.should_stop() {
                return false;
            }
        }
    }
}

fn utf8_len(b: u8) -> usize {
    match b {
        0xF0..=0xFF => 4,
        0xE0..=0xEF => 3,
        0xC0..=0xDF => 2,
        _ => 1,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    None,
    Upper,
    Lower,
}

fn expand_repl(parts: &[Repl], caps: &regex::bytes::Captures, out: &mut Vec<u8>) {
    let mut case = Case::None;
    let mut one: Case = Case::None;
    let push = |out: &mut Vec<u8>, bytes: &[u8], case: Case, one: &mut Case| {
        if case == Case::None && *one == Case::None {
            out.extend_from_slice(bytes);
            return;
        }
        let s = String::from_utf8_lossy(bytes);
        for c in s.chars() {
            let mapped: String = match (*one, case) {
                (Case::Upper, _) => {
                    *one = Case::None;
                    c.to_uppercase().collect()
                }
                (Case::Lower, _) => {
                    *one = Case::None;
                    c.to_lowercase().collect()
                }
                (_, Case::Upper) => c.to_uppercase().collect(),
                (_, Case::Lower) => c.to_lowercase().collect(),
                _ => c.to_string(),
            };
            out.extend_from_slice(mapped.as_bytes());
        }
    };
    for p in parts {
        match p {
            Repl::Lit(b) => push(out, b, case, &mut one),
            Repl::Group(g) => {
                if let Some(m) = caps.get(*g) {
                    push(out, m.as_bytes(), case, &mut one);
                }
            }
            Repl::Upper => {
                case = Case::Upper;
                one = Case::None;
            }
            Repl::Lower => {
                case = Case::Lower;
                one = Case::None;
            }
            Repl::OneUpper => one = Case::Upper,
            Repl::OneLower => one = Case::Lower,
            Repl::End => {
                case = Case::None;
                one = Case::None;
            }
        }
    }
}

const USAGE: &str = "Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...

  -n, --quiet, --silent
                 suppress automatic printing of pattern space
  -e script, --expression=script
                 add the script to the commands to be executed
  -f script-file, --file=script-file
                 add the contents of script-file to the commands to be executed
  -i[SUFFIX], --in-place[=SUFFIX]
                 edit files in place (makes backup if SUFFIX supplied)
  -E, -r, --regexp-extended
                 use extended regular expressions in the script
  -s, --separate
                 consider files as separate rather than as a single
                 continuous long stream.
  -z, --null-data
                 separate lines by NUL characters
";

pub fn sed(ctx: &mut Ctx) -> i32 {
    let args = ctx.args.clone();
    let mut quiet = false;
    let mut ere = false;
    let mut separate = false;
    let mut null_data = false;
    let mut in_place: Option<String> = None;
    let mut script_parts: Vec<String> = Vec::new();
    let mut files: Vec<String> = Vec::new();
    let mut i = 1;
    let mut only_files = false;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if only_files || a == "-" || !a.starts_with('-') {
            files.push(a.clone());
            continue;
        }
        match a.as_str() {
            "--" => only_files = true,
            "-n" | "--quiet" | "--silent" => quiet = true,
            "-E" | "-r" | "--regexp-extended" => ere = true,
            "-s" | "--separate" => separate = true,
            "-z" | "--null-data" => null_data = true,
            "-u" | "--unbuffered" | "--posix" | "--debug" | "--sandbox" | "--follow-symlinks" => {}
            "--help" => {
                ctx.print(USAGE);
                return 0;
            }
            "--version" => {
                ctx.print("sed (FastROS) 1.0\n");
                return 0;
            }
            "-e" | "--expression" | "-f" | "--file" => {
                let Some(v) = args.get(i).cloned() else {
                    ctx.fail(alloc::format!("option requires an argument -- '{}'", &a[1..2]));
                    ctx.eprint(USAGE);
                    return 1;
                };
                i += 1;
                if a.ends_with('e') || a == "--expression" {
                    script_parts.push(v);
                } else {
                    match ctx.read_input(&v) {
                        Ok(d) => {
                            let mut t = String::from_utf8_lossy(&d).into_owned();
                            if t.ends_with('\n') {
                                t.pop();
                            }
                            script_parts.push(t);
                        }
                        Err(e) => {
                            ctx.fail(alloc::format!("couldn't open file {v}: {e}"));
                            return 1;
                        }
                    }
                }
            }
            s if s.starts_with("--expression=") => script_parts.push(s["--expression=".len()..].to_string()),
            s if s.starts_with("--in-place") => in_place = Some(s.strip_prefix("--in-place=").unwrap_or("").to_string()),
            s if s.starts_with("-i") => {
                // -i may be combined only as -iSUFFIX (GNU); -in is suffix "n".
                in_place = Some(s[2..].to_string());
            }
            s if s.starts_with("-e") => script_parts.push(s[2..].to_string()),
            s if s.starts_with("-") && s.len() > 2 && !s.starts_with("--") => {
                // Combined short flags like -nE.
                let mut ok = true;
                for c in s[1..].chars() {
                    match c {
                        'n' => quiet = true,
                        'E' | 'r' => ere = true,
                        's' => separate = true,
                        'z' => null_data = true,
                        'u' => {}
                        _ => ok = false,
                    }
                }
                if !ok {
                    ctx.fail(alloc::format!("invalid option -- '{}'", &s[1..]));
                    ctx.eprint(USAGE);
                    return 1;
                }
            }
            s => {
                ctx.fail(alloc::format!("unknown option -- '{}'", s.trim_start_matches('-')));
                ctx.eprint(USAGE);
                return 1;
            }
        }
    }
    if script_parts.is_empty() {
        if files.is_empty() {
            ctx.eprint(USAGE);
            return 1;
        }
        script_parts.push(files.remove(0));
    }
    let script = script_parts.join("\n");
    if script.starts_with("#n\n") || script == "#n" {
        quiet = true;
    }
    let mut wfiles: Vec<(String, Option<Arc<dyn File>>)> = Vec::new();
    let mut rfile_names: Vec<String> = Vec::new();
    let cmds = {
        let mut c = Compiler { s: script.chars().collect(), i: 0, ere, cmds: Vec::new(), labels: BTreeMap::new(), pending: Vec::new(), blocks: Vec::new(), wfiles: &mut wfiles, rfiles: &mut rfile_names };
        if let Err(m) = c.compile() {
            ctx.fail(m);
            return 1;
        }
        c.cmds
    };
    // `w` files are created (truncated) before any input is read.
    let fsctx = ctx.fs();
    for (name, f) in wfiles.iter_mut() {
        if name == "/dev/stdout" || name == "/dev/stderr" {
            continue;
        }
        match ops::open(&fsctx, name, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC, 0o666) {
            Ok(h) => *f = Some(h),
            Err(e) => {
                let n = name.clone();
                ctx.fail(alloc::format!("couldn't open file {n}: {e}"));
                return 4;
            }
        }
    }
    if files.is_empty() {
        if in_place.is_some() {
            ctx.fail("no input files");
            return 1;
        }
        files.push(String::from("-"));
    }
    let eol = if null_data { 0 } else { b'\n' };
    let n = cmds.len();
    let mut ex = Exec {
        ctx,
        cmds: &cmds,
        quiet,
        sink: None,
        missing_newline: false,
        ps: Vec::new(),
        hs: Vec::new(),
        ps_newline: true,
        line_no: 0,
        append: VecDeque::new(),
        range_active: alloc::vec![false; n],
        range_end: alloc::vec![0; n],
        last_re: None,
        replaced: false,
        wfiles: &mut wfiles,
        rfiles: rfile_names.into_iter().map(|n| (n, None, Vec::new())).collect(),
        exit: None,
        file_name: String::new(),
    };
    let mut status = 0;
    match in_place {
        None => {
            let mut input = Input { files, next_file: 0, cur: None, cur_name: String::new(), buf: Vec::new(), eof: false, eol, separate, ahead: None, errors: false };
            ex.run(&mut input);
            if input.errors {
                status = 2;
            }
        }
        Some(suffix) => {
            for f in files {
                let fsctx = ex.ctx.fs();
                let meta = match ops::stat(&fsctx, &f, true) {
                    Ok(m) if m.kind == crate::fs::FileType::Regular => m,
                    Ok(_) => {
                        ex.ctx.fail(alloc::format!("couldn't edit {f}: not a regular file"));
                        status = 4;
                        continue;
                    }
                    Err(e) => {
                        ex.ctx.fail(alloc::format!("can't read {f}: {e}"));
                        status = 2;
                        continue;
                    }
                };
                ex.sink = Some(Vec::new());
                ex.missing_newline = false;
                ex.line_no = 0;
                ex.range_active.iter_mut().for_each(|r| *r = false);
                let mut input = Input { files: alloc::vec![f.clone()], next_file: 0, cur: None, cur_name: String::new(), buf: Vec::new(), eof: false, eol, separate: true, ahead: None, errors: false };
                let finished = ex.run(&mut input);
                let data = ex.sink.take().unwrap_or_default();
                if input.errors {
                    status = 2;
                    continue;
                }
                let dir = match f.rfind('/') {
                    Some(p) => f[..=p].to_string(),
                    None => String::new(),
                };
                let base = f.rsplit('/').next().unwrap_or(&f).to_string();
                let tmp = alloc::format!("{dir}.sed{}.tmp", crate::crypto::rng::u64() % 1_000_000);
                if let Err(e) = ops::write_file(&fsctx, &tmp, &data, meta.perm & 0o7777) {
                    ex.ctx.fail(alloc::format!("couldn't open temporary file {tmp}: {e}"));
                    return 4;
                }
                let _ = ops::chmod(&fsctx, &tmp, meta.perm & 0o7777, true);
                if !suffix.is_empty() {
                    let backup = if suffix.contains('*') { alloc::format!("{dir}{}", suffix.replace('*', &base)) } else { alloc::format!("{f}{suffix}") };
                    if let Err(e) = ops::rename(&fsctx, &f, &backup) {
                        ex.ctx.fail(alloc::format!("cannot rename {f}: {e}"));
                        let _ = ops::unlink(&fsctx, &tmp);
                        return 4;
                    }
                }
                if let Err(e) = ops::rename(&fsctx, &tmp, &f) {
                    ex.ctx.fail(alloc::format!("cannot rename {tmp}: {e}"));
                    let _ = ops::unlink(&fsctx, &tmp);
                    return 4;
                }
                if !finished {
                    break;
                }
            }
        }
    }
    if let Some(code) = ex.exit {
        return code;
    }
    status
}
