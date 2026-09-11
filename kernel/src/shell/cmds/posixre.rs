//! POSIX regular expressions (BRE / ERE, with the GNU extensions) translated
//! into `regex` crate syntax, shared by `grep`, `sed`, `find -regex`, `less`.
//!
//! The translation is exact for everything the `regex` engine can express:
//! bracket expressions (`[]a-z[:alpha:]]`, where `\` is literal), intervals
//! (`\{m,n\}` / `{m,n}`), GNU `\+ \? \|`, word anchors `\< \> \b \B`, and
//! the context rules that make `*`, `^`, `$` literal in BRE. Back-references
//! inside a pattern are rejected with a clear error (the engine is
//! automaton-based, which is also what guarantees linear-time matching).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syntax {
    /// POSIX basic (`grep`, `sed` default).
    Basic,
    /// POSIX extended (`grep -E`, `sed -E`).
    Extended,
    /// Fixed string (`grep -F`).
    Fixed,
    /// The engine's own Perl-like syntax (`grep -P`).
    Perl,
}

/// Options applied around the translated pattern.
#[derive(Clone, Copy, Debug, Default)]
pub struct Flags {
    pub icase: bool,
    /// Match whole words only (`grep -w`).
    pub word: bool,
    /// Match whole lines only (`grep -x`).
    pub line: bool,
    /// `^`/`$` also match around embedded newlines (`sed` `M` flag).
    pub multiline: bool,
    /// `.` matches a newline too (GNU `sed` pattern space semantics).
    pub dot_nl: bool,
}

fn lit(out: &mut String, c: char) {
    if c.is_ascii_alphanumeric() || c == ' ' || c == '_' || !c.is_ascii() {
        out.push(c);
    } else {
        let _ = write!(out, "\\x{{{:x}}}", c as u32);
    }
}

/// Translate one POSIX pattern into `regex` syntax.
pub fn translate(pat: &str, syn: Syntax) -> Result<String, String> {
    match syn {
        Syntax::Fixed => {
            let mut o = String::new();
            for c in pat.chars() {
                lit(&mut o, c);
            }
            Ok(o)
        }
        Syntax::Perl => Ok(pat.to_string()),
        Syntax::Basic | Syntax::Extended => Translator { p: pat.chars().collect(), i: 0, ere: syn == Syntax::Extended, out: String::new(), depth: 0 }.run(),
    }
}

struct Translator {
    p: Vec<char>,
    i: usize,
    ere: bool,
    out: String,
    depth: usize,
}

impl Translator {
    fn peek(&self, k: usize) -> Option<char> {
        self.p.get(self.i + k).copied()
    }

    fn run(mut self) -> Result<String, String> {
        // `at_start`: a position where `*` is literal and BRE `^` anchors.
        let mut at_start = true;
        // Can a repetition operator apply to what was emitted last?
        let mut repeatable = false;
        let mut last_was_repeat = false;
        while self.i < self.p.len() {
            let c = self.p[self.i];
            self.i += 1;
            let mut next_start = false;
            let mut now_repeatable = true;
            let mut is_repeat = false;
            match c {
                '\\' => {
                    let Some(e) = self.peek(0) else { return Err("trailing backslash (\\)".to_string()) };
                    self.i += 1;
                    match e {
                        '(' if !self.ere => {
                            self.out.push('(');
                            self.depth += 1;
                            next_start = true;
                            now_repeatable = false;
                        }
                        ')' if !self.ere => {
                            if self.depth == 0 {
                                return Err("Unmatched ) or \\)".to_string());
                            }
                            self.depth -= 1;
                            self.out.push(')');
                        }
                        '|' if !self.ere => {
                            self.out.push('|');
                            next_start = true;
                            now_repeatable = false;
                        }
                        '{' if !self.ere => {
                            if at_start || !repeatable {
                                lit(&mut self.out, '{');
                            } else {
                                self.interval(true)?;
                                is_repeat = true;
                            }
                        }
                        '}' if !self.ere => lit(&mut self.out, '}'),
                        '+' | '?' if !self.ere => {
                            if at_start || !repeatable {
                                lit(&mut self.out, e);
                            } else if !last_was_repeat {
                                self.out.push(e);
                                is_repeat = true;
                            } else {
                                is_repeat = true;
                            }
                        }
                        '1'..='9' => return Err("back-references are not supported (the regex engine is linear-time)".to_string()),
                        '<' => {
                            self.out.push_str("\\b{start}");
                            now_repeatable = false;
                        }
                        '>' => {
                            self.out.push_str("\\b{end}");
                            now_repeatable = false;
                        }
                        'b' | 'B' => {
                            self.out.push('\\');
                            self.out.push(e);
                            now_repeatable = false;
                        }
                        'w' | 'W' | 's' | 'S' => {
                            self.out.push('\\');
                            self.out.push(e);
                        }
                        '`' => {
                            self.out.push_str("\\A");
                            now_repeatable = false;
                        }
                        '\'' => {
                            self.out.push_str("\\z");
                            now_repeatable = false;
                        }
                        'n' => self.out.push_str("\\n"),
                        't' => self.out.push_str("\\t"),
                        other => lit(&mut self.out, other),
                    }
                }
                '[' => self.bracket()?,
                '.' => self.out.push('.'),
                '*' => {
                    if at_start || !repeatable {
                        lit(&mut self.out, '*');
                    } else {
                        if !last_was_repeat {
                            self.out.push('*');
                        }
                        is_repeat = true;
                    }
                }
                '^' => {
                    if self.ere || at_start {
                        self.out.push('^');
                        next_start = !self.ere || at_start;
                        now_repeatable = false;
                    } else {
                        lit(&mut self.out, '^');
                    }
                }
                '$' => {
                    let at_end = self.i >= self.p.len() || (!self.ere && self.peek(0) == Some('\\') && matches!(self.peek(1), Some(')') | Some('|')));
                    if self.ere || at_end {
                        self.out.push('$');
                        now_repeatable = false;
                    } else {
                        lit(&mut self.out, '$');
                    }
                }
                '(' if self.ere => {
                    self.out.push('(');
                    self.depth += 1;
                    next_start = true;
                    now_repeatable = false;
                }
                ')' if self.ere => {
                    if self.depth == 0 {
                        // POSIX leaves a lone `)` undefined; GNU treats it literally.
                        lit(&mut self.out, ')');
                    } else {
                        self.depth -= 1;
                        self.out.push(')');
                    }
                }
                '|' if self.ere => {
                    self.out.push('|');
                    next_start = true;
                    now_repeatable = false;
                }
                '+' | '?' if self.ere => {
                    if at_start || !repeatable {
                        lit(&mut self.out, c);
                    } else {
                        if !last_was_repeat {
                            self.out.push(c);
                        }
                        is_repeat = true;
                    }
                }
                '{' if self.ere => {
                    if !at_start && repeatable && self.valid_interval() {
                        self.interval(false)?;
                        is_repeat = true;
                    } else {
                        lit(&mut self.out, '{');
                    }
                }
                other => lit(&mut self.out, other),
            }
            if is_repeat {
                // A repeated atom stays repeatable (GNU allows `a**`).
                repeatable = true;
                last_was_repeat = true;
                at_start = false;
            } else {
                last_was_repeat = false;
                repeatable = now_repeatable;
                at_start = next_start;
            }
        }
        if self.depth > 0 {
            return Err("Unmatched ( or \\(".to_string());
        }
        Ok(self.out)
    }

    /// ERE: is the `{` just consumed the start of a well-formed interval?
    fn valid_interval(&self) -> bool {
        let mut j = self.i;
        let mut digits = 0;
        while j < self.p.len() && self.p[j].is_ascii_digit() {
            j += 1;
            digits += 1;
        }
        if j < self.p.len() && self.p[j] == ',' {
            j += 1;
            while j < self.p.len() && self.p[j].is_ascii_digit() {
                j += 1;
                digits += 1;
            }
        }
        digits > 0 && j < self.p.len() && self.p[j] == '}'
    }

    /// Parse `m`, `m,`, `m,n`, `,n` up to `}` (BRE: `\}`) and emit `{..}`.
    fn interval(&mut self, bre: bool) -> Result<(), String> {
        let mut min = String::new();
        let mut max = String::new();
        let mut comma = false;
        loop {
            let Some(c) = self.peek(0) else { return Err("Unmatched \\{".to_string()) };
            self.i += 1;
            match c {
                '0'..='9' if !comma => min.push(c),
                '0'..='9' => max.push(c),
                ',' if !comma => comma = true,
                '\\' if bre && self.peek(0) == Some('}') => {
                    self.i += 1;
                    break;
                }
                '}' if !bre => break,
                _ => return Err("Invalid content of \\{\\}".to_string()),
            }
        }
        let lo: u32 = if min.is_empty() { 0 } else { min.parse().map_err(|_| "Regular expression too big".to_string())? };
        if !comma {
            if min.is_empty() {
                return Err("Invalid content of \\{\\}".to_string());
            }
            let _ = write!(self.out, "{{{lo}}}");
            return Ok(());
        }
        if max.is_empty() {
            let _ = write!(self.out, "{{{lo},}}");
        } else {
            let hi: u32 = max.parse().map_err(|_| "Regular expression too big".to_string())?;
            if hi < lo {
                return Err("Invalid content of \\{\\}".to_string());
            }
            let _ = write!(self.out, "{{{lo},{hi}}}");
        }
        Ok(())
    }

    /// A POSIX bracket expression; `[` already consumed.
    fn bracket(&mut self) -> Result<(), String> {
        const UNMATCHED: &str = "Unmatched [, [^, [:, [., or [=";
        let mut o = String::from("[");
        if self.peek(0) == Some('^') {
            o.push('^');
            self.i += 1;
        }
        let mut first = true;
        loop {
            let Some(c) = self.peek(0) else { return Err(UNMATCHED.to_string()) };
            if c == ']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            // The start of an item: a class, an equivalence/collating
            // element, or a single character (maybe starting a range).
            let lo: char = if c == '[' && matches!(self.peek(1), Some(':') | Some('=') | Some('.')) {
                let kind = self.peek(1).expect("checked");
                let start = self.i + 2;
                let end = (start..self.p.len().saturating_sub(1)).find(|&j| self.p[j] == kind && self.p[j + 1] == ']').ok_or_else(|| UNMATCHED.to_string())?;
                let name: String = self.p[start..end].iter().collect();
                self.i = end + 2;
                if kind == ':' {
                    const CLASSES: [&str; 12] = ["alpha", "digit", "alnum", "upper", "lower", "space", "blank", "punct", "xdigit", "cntrl", "print", "graph"];
                    if !CLASSES.contains(&name.as_str()) {
                        return Err("Invalid character class name".to_string());
                    }
                    let _ = write!(o, "[:{name}:]");
                    continue;
                }
                let mut it = name.chars();
                match (it.next(), it.next()) {
                    (Some(ch), None) => ch,
                    _ => return Err("Invalid collation character".to_string()),
                }
            } else {
                self.i += 1;
                c
            };
            // A range `lo-hi` (a `-` right before `]` is literal).
            if self.peek(0) == Some('-') && self.peek(1).is_some_and(|x| x != ']') {
                self.i += 1;
                let hi = if self.peek(0) == Some('[') && self.peek(1) == Some('.') {
                    let start = self.i + 2;
                    let end = (start..self.p.len().saturating_sub(1)).find(|&j| self.p[j] == '.' && self.p[j + 1] == ']').ok_or_else(|| UNMATCHED.to_string())?;
                    let ch = self.p[start];
                    self.i = end + 2;
                    ch
                } else {
                    let ch = self.p[self.i];
                    self.i += 1;
                    ch
                };
                if hi < lo {
                    return Err("Invalid range end".to_string());
                }
                let _ = write!(o, "\\x{{{:x}}}-\\x{{{:x}}}", lo as u32, hi as u32);
            } else {
                let _ = write!(o, "\\x{{{:x}}}", lo as u32);
            }
        }
        o.push(']');
        self.out.push_str(&o);
        Ok(())
    }
}

/// Combine patterns (an empty list matches nothing, an empty pattern
/// matches everything) and apply the flags; returns engine syntax.
pub fn combine(patterns: &[String], syn: Syntax, f: Flags) -> Result<String, String> {
    let mut alts = Vec::with_capacity(patterns.len());
    for p in patterns {
        alts.push(translate(p, syn)?);
    }
    let body = if alts.is_empty() {
        // Nothing can match: an empty character class.
        String::from("[^\\x{0}-\\x{10FFFF}]")
    } else if alts.len() == 1 {
        alts.pop().expect("one")
    } else {
        let mut s = String::new();
        for (i, a) in alts.iter().enumerate() {
            if i > 0 {
                s.push('|');
            }
            let _ = write!(s, "(?:{a})");
        }
        s
    };
    let mut re = String::new();
    if f.icase || f.multiline || f.dot_nl {
        re.push_str("(?");
        if f.icase {
            re.push('i');
        }
        if f.multiline {
            re.push('m');
        }
        if f.dot_nl {
            re.push('s');
        }
        re.push(')');
    }
    if f.line {
        let _ = write!(re, "^(?:{body})$");
    } else if f.word {
        let _ = write!(re, "\\b{{start-half}}(?:{body})\\b{{end-half}}");
    } else {
        re.push_str(&body);
    }
    Ok(re)
}

/// Compile for byte haystacks (lines of arbitrary files).
pub fn compile_bytes(patterns: &[String], syn: Syntax, f: Flags) -> Result<regex::bytes::Regex, String> {
    let src = combine(patterns, syn, f)?;
    regex::bytes::RegexBuilder::new(&src).size_limit(64 << 20).dfa_size_limit(16 << 20).build().map_err(|e| clean_error(&e.to_string()))
}

/// The engine's multi-line error text reduced to its last line.
fn clean_error(e: &str) -> String {
    e.lines().rev().find(|l| l.starts_with("error:")).map(|l| l.trim_start_matches("error:").trim().to_string()).unwrap_or_else(|| e.lines().last().unwrap_or(e).trim().to_string())
}
