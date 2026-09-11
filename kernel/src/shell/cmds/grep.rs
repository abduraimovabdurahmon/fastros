//! `grep`, `egrep`, `fgrep`: GNU-compatible line search.
//!
//! Input is streamed (so `yes | grep -m1 y` and `tail -f | grep` work),
//! with before/after context kept in a small ring. Output — separators,
//! `--` group lines, colours (`GREP_COLORS` defaults), binary-file notices
//! and exit codes — matches GNU grep 3.x.

use super::posixre::{self, Flags, Syntax};
use crate::errno::Errno;
use crate::fs::file::File;
use crate::fs::{ops, FileType};
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use regex::bytes::Regex;

const C_MATCH: &str = "01;31";
const C_FILE: &str = "35";
const C_LINE: &str = "32";
const C_SEP: &str = "36";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ListMode {
    None,
    Matching,
    NonMatching,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Binary {
    /// Print "binary file matches" instead of lines (default).
    Notice,
    /// `-a`: treat as text.
    Text,
    /// `-I`: skip binary files.
    Skip,
}

struct Opts {
    re: Regex,
    invert: bool,
    count: bool,
    list: ListMode,
    line_numbers: bool,
    byte_offset: bool,
    with_name: bool,
    only_matching: bool,
    quiet: bool,
    no_messages: bool,
    max_count: Option<u64>,
    before: usize,
    after: usize,
    color: bool,
    null_name: bool,
    null_data: bool,
    binary: Binary,
    recursive: bool,
    follow_all: bool,
    include: Vec<String>,
    exclude: Vec<String>,
    exclude_dir: Vec<String>,
    label: String,
}

/// Mutable state across all files of one invocation.
struct Run {
    matched_any: bool,
    error: bool,
    /// A `--` is due before the next context group (GNU prints it only
    /// between groups, across files too).
    printed_group: bool,
    stop_all: bool,
}

pub fn egrep(ctx: &mut Ctx) -> i32 {
    grep_with(ctx, Syntax::Extended)
}

pub fn fgrep(ctx: &mut Ctx) -> i32 {
    grep_with(ctx, Syntax::Fixed)
}

pub fn grep(ctx: &mut Ctx) -> i32 {
    grep_with(ctx, Syntax::Basic)
}

fn usage_error(ctx: &mut Ctx, msg: &str) -> i32 {
    if !msg.is_empty() {
        ctx.fail(msg);
    }
    ctx.eprint("Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n");
    2
}

fn grep_with(ctx: &mut Ctx, default_syntax: Syntax) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "EFGPivywxclLnbhHoqsrRaIzZUT",
        values: "efmABCd",
        long: &[
            ("extended-regexp", 'E', false),
            ("fixed-strings", 'F', false),
            ("basic-regexp", 'G', false),
            ("perl-regexp", 'P', false),
            ("regexp", 'e', true),
            ("file", 'f', true),
            ("ignore-case", 'i', false),
            ("no-ignore-case", '\u{1}', false),
            ("invert-match", 'v', false),
            ("word-regexp", 'w', false),
            ("line-regexp", 'x', false),
            ("count", 'c', false),
            ("files-with-matches", 'l', false),
            ("files-without-match", 'L', false),
            ("line-number", 'n', false),
            ("byte-offset", 'b', false),
            ("no-filename", 'h', false),
            ("with-filename", 'H', false),
            ("only-matching", 'o', false),
            ("quiet", 'q', false),
            ("silent", 'q', false),
            ("no-messages", 's', false),
            ("recursive", 'r', false),
            ("dereference-recursive", 'R', false),
            ("text", 'a', false),
            ("null", 'Z', false),
            ("null-data", 'z', false),
            ("max-count", 'm', true),
            ("after-context", 'A', true),
            ("before-context", 'B', true),
            ("context", 'C', true),
            ("color", '\u{2}', true),
            ("colour", '\u{2}', true),
            ("include", '\u{3}', true),
            ("exclude", '\u{4}', true),
            ("exclude-dir", '\u{5}', true),
            ("label", '\u{6}', true),
            ("line-buffered", '\u{7}', false),
            ("binary-files", '\u{8}', true),
            ("directories", 'd', true),
            ("help", '\u{9}', false),
        ],
    };
    // `--color` alone means auto; `-NUM` means `-C NUM`.
    let mut args: Vec<String> = Vec::with_capacity(ctx.args.len());
    let mut only_operands = false;
    for (i, a) in ctx.args.iter().enumerate() {
        if i == 0 || only_operands {
            args.push(a.clone());
            continue;
        }
        if a == "--" {
            only_operands = true;
            args.push(a.clone());
        } else if a == "--color" || a == "--colour" {
            args.push(String::from("--color=auto"));
        } else if a.len() > 1 && a.starts_with('-') && a[1..].bytes().all(|b| b.is_ascii_digit()) {
            args.push(String::from("-C"));
            args.push(a[1..].to_string());
        } else {
            args.push(a.clone());
        }
    }
    let p = match parse_opts(&args, &SPEC) {
        Ok(p) => p,
        Err(m) => return usage_error(ctx, &m),
    };
    if p.has('\u{9}') {
        ctx.print(HELP);
        return 0;
    }
    // The last syntax option wins, like GNU.
    let mut syntax = default_syntax;
    for a in &args[1..] {
        match a.as_str() {
            "-E" | "--extended-regexp" => syntax = Syntax::Extended,
            "-F" | "--fixed-strings" => syntax = Syntax::Fixed,
            "-G" | "--basic-regexp" => syntax = Syntax::Basic,
            "-P" | "--perl-regexp" => syntax = Syntax::Perl,
            s if s.starts_with('-') && !s.starts_with("--") && s.len() > 2 => {
                for ch in s[1..].chars() {
                    match ch {
                        'E' => syntax = Syntax::Extended,
                        'F' => syntax = Syntax::Fixed,
                        'G' => syntax = Syntax::Basic,
                        'P' => syntax = Syntax::Perl,
                        _ => {}
                    }
                    if SPEC.values.contains(ch) {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    let mut operands = p.operands.clone();
    let mut patterns: Vec<String> = Vec::new();
    let mut have_patterns = false;
    for e in p.values('e') {
        have_patterns = true;
        patterns.extend(split_patterns(e));
    }
    for f in p.values('f').to_vec() {
        have_patterns = true;
        match ctx.read_input(&f) {
            Ok(data) => {
                let text = String::from_utf8_lossy(&data);
                let body = text.strip_suffix('\n').unwrap_or(&text);
                if !data.is_empty() {
                    patterns.extend(body.split('\n').map(|s| s.to_string()));
                }
            }
            Err(e) => {
                ctx.fail(alloc::format!("{f}: {e}"));
                return 2;
            }
        }
    }
    if !have_patterns {
        if operands.is_empty() {
            return usage_error(ctx, "");
        }
        patterns.extend(split_patterns(&operands.remove(0)));
    }
    let icase = (p.has('i') || p.has('y')) && !p.has('\u{1}');
    let re = match posixre::compile_bytes(&patterns, syntax, Flags { icase, word: p.has('w'), line: p.has('x'), multiline: false, dot_nl: false }) {
        Ok(r) => r,
        Err(m) => {
            ctx.fail(m);
            return 2;
        }
    };
    let num = |ctx: &mut Ctx, c: char, what: &str| -> Result<Option<u64>, i32> {
        match p.value(c) {
            None => Ok(None),
            Some(v) => match v.parse::<u64>() {
                Ok(n) => Ok(Some(n)),
                Err(_) => {
                    ctx.fail(alloc::format!("{v}: invalid {what} argument"));
                    Err(2)
                }
            },
        }
    };
    let ctx_len = match num(ctx, 'C', "context length") {
        Ok(v) => v.unwrap_or(0) as usize,
        Err(c) => return c,
    };
    let before = match num(ctx, 'B', "context length") {
        Ok(v) => v.map(|v| v as usize).unwrap_or(ctx_len),
        Err(c) => return c,
    };
    let after = match num(ctx, 'A', "context length") {
        Ok(v) => v.map(|v| v as usize).unwrap_or(ctx_len),
        Err(c) => return c,
    };
    let max_count = match num(ctx, 'm', "max count") {
        Ok(v) => v,
        Err(c) => return c,
    };
    let tty = ctx.stdout_tty().is_some();
    let color = match p.value('\u{2}') {
        None => false,
        Some("always") | Some("yes") | Some("force") => true,
        Some("never") | Some("no") | Some("none") => false,
        Some("auto") | Some("tty") | Some("if-tty") => tty && ctx.env("TERM").is_none_or(|t| t != "dumb"),
        Some(other) => {
            let o = other.to_string();
            ctx.fail(alloc::format!("invalid argument '{o}' for '--color'"));
            return usage_error(ctx, "");
        }
    };
    let binary = match p.value('\u{8}') {
        None if p.has('a') => Binary::Text,
        None if p.has('I') => Binary::Skip,
        None | Some("binary") => Binary::Notice,
        Some("text") => Binary::Text,
        Some("without-match") => Binary::Skip,
        Some(other) => {
            let o = other.to_string();
            ctx.fail(alloc::format!("invalid argument '{o}' for '--binary-files'"));
            return 2;
        }
    };
    let recursive = p.has('r') || p.has('R') || p.value('d') == Some("recurse");
    if let Some(d) = p.value('d') {
        if !matches!(d, "read" | "skip" | "recurse") {
            let d = d.to_string();
            ctx.fail(alloc::format!("invalid argument '{d}' for '--directories'"));
            return 2;
        }
    }
    let skip_dirs = p.value('d') == Some("skip");
    let implicit_dot = operands.is_empty() && recursive;
    if operands.is_empty() {
        operands.push(if recursive { String::from(".") } else { String::from("-") });
    }
    let with_name = if p.has('h') {
        false
    } else {
        p.has('H') || operands.len() > 1 || recursive
    };
    let list = if p.has('l') {
        ListMode::Matching
    } else if p.has('L') {
        ListMode::NonMatching
    } else {
        ListMode::None
    };
    let o = Opts {
        re,
        invert: p.has('v'),
        count: p.has('c'),
        list,
        line_numbers: p.has('n'),
        byte_offset: p.has('b'),
        with_name,
        only_matching: p.has('o'),
        quiet: p.has('q'),
        no_messages: p.has('s'),
        max_count,
        before,
        after,
        color,
        null_name: p.has('Z'),
        null_data: p.has('z'),
        binary,
        recursive,
        follow_all: p.has('R'),
        include: p.values('\u{3}').to_vec(),
        exclude: p.values('\u{4}').to_vec(),
        exclude_dir: p.values('\u{5}').to_vec(),
        label: p.value('\u{6}').unwrap_or("(standard input)").to_string(),
    };
    let mut run = Run { matched_any: false, error: false, printed_group: false, stop_all: false };
    let fsctx = ctx.fs();
    for op in &operands {
        if run.stop_all || ctx.should_stop() {
            break;
        }
        if op == "-" {
            let f = ctx.stdin();
            let label = o.label.clone();
            search_file(ctx, &o, &mut run, &f, &label);
            continue;
        }
        let meta = match ops::stat(&fsctx, op, true) {
            Ok(m) => m,
            Err(e) => {
                if !o.no_messages {
                    ctx.fail(alloc::format!("{op}: {e}"));
                }
                run.error = true;
                continue;
            }
        };
        if meta.kind == FileType::Directory {
            if o.recursive {
                let display_prefix = if implicit_dot { String::new() } else { op.clone() };
                walk(ctx, &o, &mut run, op, &display_prefix, &mut Vec::new());
            } else if !skip_dirs {
                if !o.no_messages {
                    ctx.fail(alloc::format!("{op}: Is a directory"));
                }
                run.error = true;
            }
            continue;
        }
        if !o.include.is_empty() || !o.exclude.is_empty() {
            let base = op.rsplit('/').next().unwrap_or(op);
            if !name_selected(&o, base, op) {
                continue;
            }
        }
        open_and_search(ctx, &o, &mut run, op, op);
    }
    ctx.flush();
    if run.error && !(o.quiet && run.matched_any) {
        2
    } else if run.matched_any {
        0
    } else {
        1
    }
}

/// `-e 'a\nb'` is two patterns.
fn split_patterns(s: &str) -> Vec<String> {
    s.split('\n').map(|x| x.to_string()).collect()
}

fn name_selected(o: &Opts, base: &str, _full: &str) -> bool {
    if !o.include.is_empty() && !o.include.iter().any(|g| fastros_sh::pattern::matches(g, base)) {
        return false;
    }
    !o.exclude.iter().any(|g| fastros_sh::pattern::matches(g, base))
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else if dir.ends_with('/') {
        alloc::format!("{dir}{name}")
    } else {
        alloc::format!("{dir}/{name}")
    }
}

/// Recursive search. `display` is the name prefix printed for matches
/// (empty for the implicit `.` of `grep -r pat`).
fn walk(ctx: &mut Ctx, o: &Opts, run: &mut Run, path: &str, display: &str, seen: &mut Vec<(u64, u64)>) {
    let fsctx = ctx.fs();
    if let Ok(m) = ops::stat(&fsctx, path, true) {
        if seen.contains(&(m.dev, m.ino)) {
            if !o.no_messages {
                ctx.fail(alloc::format!("{path}: warning: recursive directory loop"));
            }
            return;
        }
        seen.push((m.dev, m.ino));
    }
    let entries = match ops::list_dir(&fsctx, path) {
        Ok(v) => v,
        Err(e) => {
            if !o.no_messages {
                ctx.fail(alloc::format!("{path}: {e}"));
            }
            run.error = true;
            seen.pop();
            return;
        }
    };
    let mut names: Vec<(String, FileType)> = entries.into_iter().filter(|e| e.name != "." && e.name != "..").map(|e| (e.name, e.kind)).collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, kind) in names {
        if run.stop_all || ctx.should_stop() {
            break;
        }
        let full = join(path, &name);
        let shown = join(display, &name);
        let mut kind = kind;
        if kind == FileType::Symlink {
            if !o.follow_all {
                continue;
            }
            match ops::stat(&fsctx, &full, true) {
                Ok(m) => kind = m.kind,
                Err(e) => {
                    if !o.no_messages {
                        ctx.fail(alloc::format!("{shown}: {e}"));
                    }
                    run.error = true;
                    continue;
                }
            }
        }
        match kind {
            FileType::Directory => {
                if o.exclude_dir.iter().any(|g| fastros_sh::pattern::matches(g, &name)) {
                    continue;
                }
                walk(ctx, o, run, &full, &shown, seen);
            }
            FileType::Regular => {
                if name_selected(o, &name, &shown) {
                    open_and_search(ctx, o, run, &full, &shown);
                }
            }
            // Devices, FIFOs and sockets are skipped in recursive mode.
            _ => {}
        }
    }
    seen.pop();
}

fn open_and_search(ctx: &mut Ctx, o: &Opts, run: &mut Run, path: &str, shown: &str) {
    match ctx.open_input(path) {
        Ok(f) => search_file(ctx, o, run, &f, shown),
        Err(e) => {
            if !o.no_messages {
                ctx.fail(alloc::format!("{shown}: {e}"));
            }
            run.error = true;
        }
    }
}

fn paint(out: &mut Vec<u8>, color: bool, code: &str, text: &[u8]) {
    if color {
        out.extend_from_slice(b"\x1b[");
        out.extend_from_slice(code.as_bytes());
        out.extend_from_slice(b"m\x1b[K");
        out.extend_from_slice(text);
        out.extend_from_slice(b"\x1b[m\x1b[K");
    } else {
        out.extend_from_slice(text);
    }
}

/// Per-file search state.
struct Scan<'a> {
    o: &'a Opts,
    name: &'a str,
    eol: u8,
    line_no: u64,
    offset: u64,
    selected: u64,
    /// Line number of the last line printed (for `--` separators).
    last_printed: Option<u64>,
    /// Remaining after-context lines to print.
    after_left: usize,
    /// Before-context ring: (line number, byte offset, text).
    ring: VecDeque<(u64, u64, Vec<u8>)>,
    binary: bool,
    done: bool,
}

impl Scan<'_> {
    fn prefix(&self, out: &mut Vec<u8>, line_no: u64, offset: u64, sep: u8) {
        let o = self.o;
        let s = [sep];
        if o.with_name {
            paint(out, o.color, C_FILE, self.name.as_bytes());
            if o.null_name {
                out.push(0);
            } else {
                paint(out, o.color, C_SEP, &s);
            }
        }
        if o.line_numbers {
            paint(out, o.color, C_LINE, line_no.to_string().as_bytes());
            paint(out, o.color, C_SEP, &s);
        }
        if o.byte_offset {
            paint(out, o.color, C_LINE, offset.to_string().as_bytes());
            paint(out, o.color, C_SEP, &s);
        }
    }

    fn group_separator(&mut self, ctx: &mut Ctx, run: &mut Run, line_no: u64) {
        let o = self.o;
        if o.before == 0 && o.after == 0 {
            return;
        }
        let gap = match self.last_printed {
            Some(l) => line_no > l + 1,
            None => run.printed_group,
        };
        if gap {
            let mut out = Vec::new();
            paint(&mut out, o.color, C_SEP, b"--");
            out.push(b'\n');
            ctx.write(&out);
        }
    }

    fn emit_line(&mut self, ctx: &mut Ctx, run: &mut Run, line_no: u64, offset: u64, text: &[u8], selected: bool) {
        let o = self.o;
        self.group_separator(ctx, run, line_no);
        run.printed_group = true;
        self.last_printed = Some(line_no);
        let mut out = Vec::with_capacity(text.len() + 32);
        if o.only_matching {
            if !selected || o.invert {
                return;
            }
            for m in o.re.find_iter(text) {
                if m.start() == m.end() {
                    continue;
                }
                self.prefix(&mut out, line_no, offset + m.start() as u64, b':');
                paint(&mut out, o.color, C_MATCH, m.as_bytes());
                out.push(self.eol);
            }
            ctx.write(&out);
            return;
        }
        self.prefix(&mut out, line_no, offset, if selected { b':' } else { b'-' });
        // Highlight matches in selected lines (and in context lines of -v).
        if o.color && (selected != o.invert) {
            let mut last = 0;
            for m in o.re.find_iter(text) {
                if m.start() == m.end() {
                    continue;
                }
                out.extend_from_slice(&text[last..m.start()]);
                paint(&mut out, true, C_MATCH, m.as_bytes());
                last = m.end();
            }
            out.extend_from_slice(&text[last..]);
        } else {
            out.extend_from_slice(text);
        }
        out.push(self.eol);
        ctx.write(&out);
    }

    /// Handle one complete line (without its terminator).
    fn line(&mut self, ctx: &mut Ctx, run: &mut Run, text: &[u8]) {
        let o = self.o;
        self.line_no += 1;
        let line_no = self.line_no;
        let offset = self.offset;
        self.offset += text.len() as u64 + 1;
        let is_match = o.re.is_match(text);
        let selected = is_match != o.invert;
        let limit_reached = o.max_count.is_some_and(|m| self.selected >= m);
        if selected && !limit_reached {
            self.selected += 1;
            run.matched_any = true;
            if o.quiet {
                self.done = true;
                run.stop_all = true;
                return;
            }
            if o.list != ListMode::None {
                self.done = true;
                return;
            }
            if o.count {
                if o.max_count.is_some_and(|m| self.selected >= m) {
                    self.done = true;
                }
                return;
            }
            if self.binary {
                self.done = true;
                return;
            }
            let ring: Vec<_> = self.ring.drain(..).collect();
            for (n, off, t) in ring {
                self.emit_line(ctx, run, n, off, &t, false);
            }
            self.emit_line(ctx, run, line_no, offset, text, true);
            self.after_left = o.after;
            return;
        }
        if limit_reached && self.after_left == 0 {
            self.done = true;
            return;
        }
        if o.count || o.list != ListMode::None || o.quiet || self.binary {
            return;
        }
        if self.after_left > 0 {
            self.after_left -= 1;
            self.emit_line(ctx, run, line_no, offset, text, false);
            if limit_reached && self.after_left == 0 {
                self.done = true;
            }
            return;
        }
        if o.before > 0 {
            if self.ring.len() == o.before {
                self.ring.pop_front();
            }
            self.ring.push_back((line_no, offset, text.to_vec()));
        }
    }
}

fn search_file(ctx: &mut Ctx, o: &Opts, run: &mut Run, f: &Arc<dyn File>, name: &str) {
    let mut sc = Scan {
        o,
        name,
        eol: if o.null_data { 0 } else { b'\n' },
        line_no: 0,
        offset: 0,
        selected: 0,
        last_printed: None,
        after_left: 0,
        ring: VecDeque::new(),
        binary: false,
        done: false,
    };
    let mut buf = alloc::vec![0u8; 32 * 1024];
    let mut pending: Vec<u8> = Vec::new();
    let mut first = true;
    ctx.flush();
    loop {
        if sc.done || ctx.should_stop() {
            break;
        }
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(Errno::EINTR) => break,
            Err(e) => {
                if !o.no_messages {
                    ctx.fail(alloc::format!("{name}: {e}"));
                }
                run.error = true;
                return;
            }
        };
        if first {
            first = false;
            if !o.null_data && o.binary != Binary::Text && buf[..n].contains(&0) {
                if o.binary == Binary::Skip {
                    return;
                }
                sc.binary = true;
            }
        }
        pending.extend_from_slice(&buf[..n]);
        let mut start = 0;
        while let Some(pos) = pending[start..].iter().position(|&b| b == sc.eol) {
            let end = start + pos;
            let line = pending[start..end].to_vec();
            start = end + 1;
            sc.line(ctx, run, &line);
            if sc.done {
                break;
            }
        }
        pending.drain(..start);
        // Interactive streams: push out what we have.
        ctx.flush();
    }
    if !sc.done && !pending.is_empty() {
        let line = core::mem::take(&mut pending);
        sc.line(ctx, run, &line);
    }
    if o.quiet {
        return;
    }
    let mut out = Vec::new();
    if o.count {
        if o.with_name {
            paint(&mut out, o.color, C_FILE, name.as_bytes());
            if o.null_name {
                out.push(0);
            } else {
                paint(&mut out, o.color, C_SEP, b":");
            }
        }
        out.extend_from_slice(sc.selected.to_string().as_bytes());
        out.push(b'\n');
    }
    let listed = match o.list {
        ListMode::Matching => sc.selected > 0,
        ListMode::NonMatching => sc.selected == 0,
        ListMode::None => false,
    };
    if listed {
        paint(&mut out, o.color, C_FILE, name.as_bytes());
        out.push(if o.null_name { 0 } else { b'\n' });
    }
    ctx.write(&out);
    if sc.binary && sc.selected > 0 && o.list == ListMode::None && !o.count {
        ctx.flush();
        let n = ctx.name().to_string();
        ctx.eprint(&alloc::format!("{n}: {name}: binary file matches\n"));
    }
}

const HELP: &str = "Usage: grep [OPTION]... PATTERNS [FILE]...
Search for PATTERNS in each FILE.

Pattern selection and interpretation:
  -E, --extended-regexp     PATTERNS are extended regular expressions
  -F, --fixed-strings       PATTERNS are strings
  -G, --basic-regexp        PATTERNS are basic regular expressions
  -P, --perl-regexp         PATTERNS are Perl-style regular expressions
  -e, --regexp=PATTERNS     use PATTERNS for matching
  -f, --file=FILE           take PATTERNS from FILE
  -i, --ignore-case         ignore case distinctions in patterns and data
  -w, --word-regexp         match only whole words
  -x, --line-regexp         match only whole lines

Output control:
  -m, --max-count=NUM       stop after NUM selected lines
  -b, --byte-offset         print the byte offset with output lines
  -n, --line-number         print line number with output lines
  -H, --with-filename       print file name with output lines
  -h, --no-filename         suppress the file name prefix on output
      --label=LABEL         use LABEL as the standard input file name prefix
  -o, --only-matching       show only nonempty parts of lines that match
  -q, --quiet, --silent     suppress all normal output
  -s, --no-messages         suppress error messages
  -a, --text                equivalent to --binary-files=text
  -I                        equivalent to --binary-files=without-match
  -r, --recursive           search directories recursively
  -R, --dereference-recursive  likewise, but follow all symlinks
      --include=GLOB        search only files that match GLOB
      --exclude=GLOB        skip files that match GLOB
      --exclude-dir=GLOB    skip directories that match GLOB
  -L, --files-without-match  print only names of FILEs with no selected lines
  -l, --files-with-matches  print only names of FILEs with selected lines
  -c, --count               print only a count of selected lines per FILE
  -Z, --null                print 0 byte after FILE name
  -z, --null-data           a data line ends in 0 byte, not newline

Context control:
  -B, --before-context=NUM  print NUM lines of leading context
  -A, --after-context=NUM   print NUM lines of trailing context
  -C, --context=NUM         print NUM lines of output context
  -NUM                      same as --context=NUM
      --color[=WHEN]        use markers to highlight the matching strings;
                            WHEN is 'always', 'never', or 'auto'
  -v, --invert-match        select non-matching lines

Exit status is 0 if any line is selected, 1 otherwise;
if any error occurs and -q is not given, the exit status is 2.
";
