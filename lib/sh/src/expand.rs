//! Word expansion, in POSIX order: tilde, parameter, command substitution
//! and arithmetic (left to right), then field splitting on `IFS`, pathname
//! expansion, and quote removal.

use crate::arith;
use crate::ast::{Param, ParamOp, Word, WordPart};
use crate::pattern;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// What expansion needs from the shell.
pub trait Env {
    fn var(&self, name: &str) -> Option<String>;
    fn set_var(&mut self, name: &str, value: &str) -> Result<(), String>;
    /// `$?`, `$$`, `$!`, `$#`, `$-`, `$0`.
    fn special(&self, name: &str) -> Option<String>;
    /// `$1`, `$2`, ...
    fn positional(&self) -> Vec<String>;
    /// Run `$(...)`; returns its standard output.
    fn command_output(&mut self, src: &str) -> Result<String, String>;
    fn home(&self, user: &str) -> Option<String>;
    fn list_dir(&mut self, dir: &str) -> Option<Vec<String>>;
    /// `set -u`
    fn nounset(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandError {
    /// `${x:?msg}` or `set -u` on an unset variable: (name, message).
    Unset(String, String),
    Arith(String),
    Command(String),
    Bad(String),
}

impl ExpandError {
    pub fn message(&self) -> String {
        match self {
            ExpandError::Unset(n, m) => alloc::format!("{n}: {m}"),
            ExpandError::Arith(m) | ExpandError::Command(m) | ExpandError::Bad(m) => m.clone(),
        }
    }
}

type R<T> = Result<T, ExpandError>;

/// A character with its quoting (quoted chars are never split or globbed).
#[derive(Clone, Copy)]
struct Ch {
    c: char,
    quoted: bool,
    /// Came from an unquoted expansion (subject to field splitting).
    split: bool,
}

/// One word in progress: a list of fields (a quoted `"$@"` can produce
/// several), each a list of characters.
struct Fields {
    fields: Vec<Vec<Ch>>,
    /// Whether the current field was touched by anything quoted (so `""`
    /// yields an empty field instead of nothing).
    has_quoted: Vec<bool>,
}

impl Fields {
    fn new() -> Fields {
        Fields { fields: alloc::vec![Vec::new()], has_quoted: alloc::vec![false] }
    }
    fn push_str(&mut self, s: &str, quoted: bool, split: bool) {
        let f = self.fields.last_mut().expect("at least one field");
        f.extend(s.chars().map(|c| Ch { c, quoted, split }));
        if quoted {
            *self.has_quoted.last_mut().expect("parallel") = true;
        }
    }
    fn mark_quoted(&mut self) {
        *self.has_quoted.last_mut().expect("parallel") = true;
    }
    fn break_field(&mut self) {
        self.fields.push(Vec::new());
        self.has_quoted.push(false);
    }
}

fn ifs(env: &dyn Env) -> String {
    env.var("IFS").unwrap_or_else(|| String::from(" \t\n"))
}

fn param_value(p: &str, env: &dyn Env) -> Option<String> {
    match p {
        "@" | "*" => {
            let args = env.positional();
            if args.is_empty() {
                None
            } else {
                let sep = ifs(env).chars().next().map(|c| c.to_string()).unwrap_or_default();
                Some(args.join(if p == "*" { &sep } else { " " }))
            }
        }
        "?" | "$" | "!" | "#" | "-" | "0" => env.special(p),
        n if n.chars().all(|c| c.is_ascii_digit()) => {
            let i: usize = n.parse().ok()?;
            env.positional().get(i.checked_sub(1)?).cloned()
        }
        n => env.var(n),
    }
}

/// Expand `word` to one string: no field splitting, no globbing.
pub fn expand_string(word: &Word, env: &mut dyn Env) -> R<String> {
    let mut f = Fields::new();
    // Unquoted parts stay unquoted; nothing is split here anyway.
    expand_parts(&word.0, env, &mut f, false)?;
    let mut out = String::new();
    for (i, field) in f.fields.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.extend(field.iter().map(|c| c.c));
    }
    Ok(out)
}

/// Expand `word` to a pattern: quoted characters are escaped so they match
/// literally (`case`, `${x#pat}`).
pub fn expand_pattern(word: &Word, env: &mut dyn Env) -> R<String> {
    let mut f = Fields::new();
    expand_parts(&word.0, env, &mut f, false)?;
    let mut out = String::new();
    for field in &f.fields {
        for ch in field {
            if ch.quoted && matches!(ch.c, '*' | '?' | '[' | ']' | '\\') {
                out.push('\\');
            }
            out.push(ch.c);
        }
    }
    Ok(out)
}

/// Full expansion of a command's words into argument strings.
pub fn expand_fields(words: &[Word], env: &mut dyn Env) -> R<Vec<String>> {
    let mut out = Vec::new();
    for w in words {
        let mut f = Fields::new();
        expand_parts(&w.0, env, &mut f, false)?;
        let ifs = ifs(env);
        for (field, quoted) in f.fields.into_iter().zip(f.has_quoted) {
            for piece in split_field(&field, &ifs, quoted) {
                glob_field(&piece, env, &mut out);
            }
        }
    }
    Ok(out)
}

fn expand_parts(parts: &[WordPart], env: &mut dyn Env, f: &mut Fields, in_quotes: bool) -> R<()> {
    for part in parts {
        match part {
            WordPart::Lit(s) => f.push_str(s, in_quotes, false),
            WordPart::Quoted(s) => f.push_str(s, true, false),
            WordPart::Double(inner) => {
                f.mark_quoted();
                // "$@": one field per positional parameter.
                for p in inner {
                    if let WordPart::Param(Param { name, op: ParamOp::Plain }) = p {
                        if name == "@" {
                            let args = env.positional();
                            for (i, a) in args.iter().enumerate() {
                                if i > 0 {
                                    f.break_field();
                                    f.mark_quoted();
                                }
                                f.push_str(a, true, false);
                            }
                            continue;
                        }
                    }
                    expand_parts(core::slice::from_ref(p), env, f, true)?;
                }
            }
            WordPart::Tilde(user) => {
                let home = if user.is_empty() { env.var("HOME") } else { env.home(user) };
                match home {
                    Some(h) => f.push_str(&h, true, false),
                    None => {
                        f.push_str("~", true, false);
                        f.push_str(user, true, false);
                    }
                }
            }
            WordPart::Param(p) => {
                if !in_quotes && p.op == ParamOp::Plain && p.name == "@" {
                    for (i, a) in env.positional().iter().enumerate() {
                        if i > 0 {
                            f.break_field();
                        }
                        f.push_str(a, false, true);
                    }
                    continue;
                }
                let v = expand_param(p, env)?;
                f.push_str(&v, in_quotes, !in_quotes);
            }
            WordPart::Command(src) => {
                let mut out = env.command_output(src).map_err(ExpandError::Command)?;
                while out.ends_with('\n') {
                    out.pop();
                }
                f.push_str(&out, in_quotes, !in_quotes);
            }
            WordPart::Arith(src) => {
                // The expression itself undergoes parameter expansion first.
                let text = expand_string(&crate::parser::parse_heredoc(src), env)?;
                let mut vars = ArithVars { env };
                let v = arith::eval(&text, &mut vars).map_err(ExpandError::Arith)?;
                f.push_str(&v.to_string(), in_quotes, !in_quotes);
            }
        }
    }
    Ok(())
}

struct ArithVars<'a> {
    env: &'a mut dyn Env,
}

impl arith::Vars for ArithVars<'_> {
    fn get(&self, name: &str) -> Option<String> {
        self.env.var(name)
    }
    fn set(&mut self, name: &str, value: &str) {
        let _ = self.env.set_var(name, value);
    }
}

fn expand_param(p: &Param, env: &mut dyn Env) -> R<String> {
    let val = param_value(&p.name, env);
    let is_set = val.is_some();
    let non_empty = val.as_ref().is_some_and(|v| !v.is_empty());
    let unset_err = |env: &dyn Env| -> R<()> {
        if env.nounset() && !is_set && !matches!(p.name.as_str(), "@" | "*") {
            return Err(ExpandError::Unset(p.name.clone(), "unbound variable".into()));
        }
        Ok(())
    };
    Ok(match &p.op {
        ParamOp::Plain => {
            unset_err(env)?;
            val.unwrap_or_default()
        }
        ParamOp::Length => {
            unset_err(env)?;
            if p.name == "@" || p.name == "*" || p.name == "#" && val.is_none() {
                env.positional().len().to_string()
            } else {
                val.unwrap_or_default().chars().count().to_string()
            }
        }
        ParamOp::Default { word, colon } => {
            if (*colon && !non_empty) || (!*colon && !is_set) {
                expand_string(word, env)?
            } else {
                val.unwrap_or_default()
            }
        }
        ParamOp::Assign { word, colon } => {
            if (*colon && !non_empty) || (!*colon && !is_set) {
                let v = expand_string(word, env)?;
                env.set_var(&p.name, &v).map_err(ExpandError::Bad)?;
                v
            } else {
                val.unwrap_or_default()
            }
        }
        ParamOp::Error { word, colon } => {
            if (*colon && !non_empty) || (!*colon && !is_set) {
                let m = expand_string(word, env)?;
                let m = if m.is_empty() { String::from("parameter null or not set") } else { m };
                return Err(ExpandError::Unset(p.name.clone(), m));
            }
            val.unwrap_or_default()
        }
        ParamOp::Alternate { word, colon } => {
            if (*colon && non_empty) || (!*colon && is_set) {
                expand_string(word, env)?
            } else {
                String::new()
            }
        }
        ParamOp::TrimPrefix { pattern: w, longest } => {
            let v = val.unwrap_or_default();
            let pat = expand_pattern(w, env)?;
            let chars: Vec<char> = v.chars().collect();
            let cuts: Vec<usize> = (0..=chars.len()).collect();
            let found = if *longest { cuts.iter().rev().copied().find(|&i| pattern::matches(&pat, &chars[..i].iter().collect::<String>())) } else { cuts.iter().copied().find(|&i| pattern::matches(&pat, &chars[..i].iter().collect::<String>())) };
            match found {
                Some(i) => chars[i..].iter().collect(),
                None => v,
            }
        }
        ParamOp::TrimSuffix { pattern: w, longest } => {
            let v = val.unwrap_or_default();
            let pat = expand_pattern(w, env)?;
            let chars: Vec<char> = v.chars().collect();
            let cuts: Vec<usize> = (0..=chars.len()).collect();
            let found = if *longest { cuts.iter().copied().find(|&i| pattern::matches(&pat, &chars[i..].iter().collect::<String>())) } else { cuts.iter().rev().copied().find(|&i| pattern::matches(&pat, &chars[i..].iter().collect::<String>())) };
            match found {
                Some(i) => chars[..i].iter().collect(),
                None => v,
            }
        }
        ParamOp::Replace { pattern: w, replacement, all } => {
            let v = val.unwrap_or_default();
            let pat = expand_pattern(w, env)?;
            let rep = expand_string(replacement, env)?;
            replace(&v, &pat, &rep, *all)
        }
        ParamOp::Substring { offset, length } => {
            let v: Vec<char> = val.unwrap_or_default().chars().collect();
            let mut vars = ArithVars { env };
            let off = arith::eval(offset, &mut vars).map_err(ExpandError::Arith)?;
            let len = match length {
                Some(l) => Some(arith::eval(l, &mut vars).map_err(ExpandError::Arith)?),
                None => None,
            };
            let n = v.len() as i64;
            let start = if off < 0 { (n + off).max(0) } else { off.min(n) };
            let end = match len {
                Some(l) if l < 0 => (n + l).max(start),
                Some(l) => (start + l).min(n),
                None => n,
            };
            v[start as usize..end as usize].iter().collect()
        }
        ParamOp::Case { upper, all } => {
            let v = val.unwrap_or_default();
            let conv = |c: char| if *upper { c.to_uppercase().collect::<String>() } else { c.to_lowercase().collect::<String>() };
            if *all {
                v.chars().map(conv).collect()
            } else {
                let mut it = v.chars();
                match it.next() {
                    Some(c) => conv(c) + &it.collect::<String>(),
                    None => v,
                }
            }
        }
    })
}

fn replace(v: &str, pat: &str, rep: &str, all: bool) -> String {
    let chars: Vec<char> = v.chars().collect();
    let anchored_start = pat.starts_with('#');
    let anchored_end = pat.starts_with('%');
    let pat = if anchored_start || anchored_end { &pat[1..] } else { pat };
    let mut out = String::new();
    let mut i = 0;
    let mut replaced = false;
    while i <= chars.len() {
        if (!replaced || all) && (!anchored_start || i == 0) {
            // Longest match starting at i.
            let mut hit = None;
            for j in (i..=chars.len()).rev() {
                if anchored_end && j != chars.len() {
                    continue;
                }
                let s: String = chars[i..j].iter().collect();
                if (j > i || pat.is_empty()) && pattern::matches(pat, &s) {
                    hit = Some(j);
                    break;
                }
            }
            if let Some(j) = hit {
                if j > i {
                    out.push_str(rep);
                    i = j;
                    replaced = true;
                    continue;
                }
            }
        }
        if i < chars.len() {
            out.push(chars[i]);
        }
        i += 1;
    }
    out
}

/// Split one field on IFS; `quoted` means something quoted was part of it.
fn split_field(field: &[Ch], ifs: &str, quoted: bool) -> Vec<Vec<Ch>> {
    let is_ws = |c: char| ifs.contains(c) && (c == ' ' || c == '\t' || c == '\n');
    let is_ifs = |ch: &Ch| ch.split && ifs.contains(ch.c);
    let mut out: Vec<Vec<Ch>> = Vec::new();
    let mut cur: Vec<Ch> = Vec::new();
    let mut cur_real = false; // current field has content (or quotes)
    let mut i = 0;
    while i < field.len() {
        let ch = field[i];
        if is_ifs(&ch) {
            if is_ws(ch.c) {
                // Whitespace IFS: collapse runs; delimit only if content precedes.
                if cur_real || !cur.is_empty() {
                    out.push(core::mem::take(&mut cur));
                    cur_real = false;
                }
                while i + 1 < field.len() && is_ifs(&field[i + 1]) && is_ws(field[i + 1].c) {
                    i += 1;
                }
            } else {
                out.push(core::mem::take(&mut cur));
                cur_real = false;
            }
        } else {
            cur.push(ch);
            cur_real = true;
        }
        i += 1;
    }
    if !cur.is_empty() || cur_real {
        out.push(cur);
    }
    if out.is_empty() && quoted {
        out.push(Vec::new());
    }
    out
}

fn glob_field(field: &[Ch], env: &mut dyn Env, out: &mut Vec<String>) {
    let magic = field.iter().any(|c| !c.quoted && matches!(c.c, '*' | '?' | '['));
    let plain: String = field.iter().map(|c| c.c).collect();
    if !magic {
        out.push(plain);
        return;
    }
    let mut pat = String::new();
    for ch in field {
        if ch.quoted && matches!(ch.c, '*' | '?' | '[' | ']' | '\\') {
            pat.push('\\');
        }
        pat.push(ch.c);
    }
    let matches = pattern::glob(&pat, &mut |d| env.list_dir(d));
    if matches.is_empty() {
        out.push(plain);
    } else {
        out.extend(matches);
    }
}
