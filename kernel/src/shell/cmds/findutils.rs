//! `find` (GNU findutils semantics), `xargs`, `locate` and `updatedb`.
//!
//! `find` parses its expression into a tree once, then walks each start
//! point depth-first in directory order (like GNU find, it does not sort).
//! `-exec ... +` batches arguments per expression node.
//!
//! `locate`'s database is readable by root only; `locate` itself reads it
//! with kernel authority and prints an entry only if the *caller* can
//! currently reach it (search permission on every ancestor and read
//! permission on the containing directory). Unlike mlocate's snapshot of
//! directory modes, the check is live, so neither files that were deleted
//! nor directories that were locked down after `updatedb` leak names.

use super::fmtutil::{self, NameCache};
use super::posixre::{self, Flags, Syntax};
use crate::errno::Errno;
use crate::fs::perm::{self, Cred, MAY_EXEC, MAY_READ, MAY_WRITE};
use crate::fs::{ops, FileType, Metadata, Timespec};
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use crate::time::civil;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ── expression tree ────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Lt,
    Eq,
    Gt,
}

impl Cmp {
    fn test(self, v: u64, n: u64) -> bool {
        match self {
            Cmp::Lt => v < n,
            Cmp::Eq => v == n,
            Cmp::Gt => v > n,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TimeField {
    Access,
    Modify,
    Change,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PermHow {
    Exact,
    All,
    Any,
}

enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Comma(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Const(bool),
    Name { pat: String, icase: bool },
    Path { pat: String, icase: bool },
    Regex(regex::bytes::Regex),
    Type(Vec<FileType>),
    Size { cmp: Cmp, n: u64, unit: u64 },
    Age { field: TimeField, cmp: Cmp, n: u64, unit: u64 },
    Newer { field: TimeField, than: Timespec },
    Uid(u32),
    Gid(u32),
    NoUser,
    NoGroup,
    Perm { mode: u16, how: PermHow },
    Empty,
    Links(Cmp, u64),
    Inum(Cmp, u64),
    Access(u32),
    Print { nul: bool },
    Printf(Vec<Fmt>),
    Ls,
    Exec { argv: Vec<String>, batch: Option<usize>, in_dir: bool, ask: bool },
    Delete,
    Prune,
    Quit,
}

/// `-printf` pieces.
enum Fmt {
    Lit(String),
    Dir { spec: char, time: Option<char>, width: Option<usize>, left: bool },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Follow {
    Never,
    CommandLine,
    Always,
}

struct Globals {
    follow: Follow,
    maxdepth: Option<usize>,
    mindepth: usize,
    depth_first: bool,
    xdev: bool,
}

struct Parser<'a> {
    toks: &'a [String],
    i: usize,
    g: Globals,
    has_action: bool,
    batches: usize,
    ctx: &'a Ctx,
    now: i64,
}

type PResult<T> = Result<T, String>;

fn parse_num(s: &str) -> Option<(Cmp, u64)> {
    let (cmp, rest) = match s.as_bytes().first()? {
        b'+' => (Cmp::Gt, &s[1..]),
        b'-' => (Cmp::Lt, &s[1..]),
        _ => (Cmp::Eq, s),
    };
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((cmp, rest.parse().ok()?))
}

impl Parser<'_> {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.i).map(|s| s.as_str())
    }

    fn arg(&mut self, opt: &str) -> PResult<String> {
        let v = self.toks.get(self.i).cloned().ok_or_else(|| alloc::format!("missing argument to '{opt}'"))?;
        self.i += 1;
        Ok(v)
    }

    fn parse(&mut self) -> PResult<Option<Expr>> {
        if self.peek().is_none() {
            return Ok(None);
        }
        let e = self.comma()?;
        if let Some(t) = self.peek() {
            return Err(if t == ")" { String::from("invalid expression; you have too many ')'") } else { alloc::format!("paths must precede expression: '{t}'") });
        }
        Ok(Some(e))
    }

    fn comma(&mut self) -> PResult<Expr> {
        let mut l = self.or()?;
        while self.peek() == Some(",") {
            self.i += 1;
            let r = self.or()?;
            l = Expr::Comma(Box::new(l), Box::new(r));
        }
        Ok(l)
    }

    fn or(&mut self) -> PResult<Expr> {
        let mut l = self.and()?;
        while matches!(self.peek(), Some("-o") | Some("-or")) {
            let op = self.peek().unwrap_or("").to_string();
            self.i += 1;
            if matches!(self.peek(), None | Some(")") | Some(",") | Some("-o") | Some("-or") | Some("-a") | Some("-and")) {
                return Err(alloc::format!("invalid expression; you have used a binary operator '{op}' with nothing after it."));
            }
            let r = self.and()?;
            l = Expr::Or(Box::new(l), Box::new(r));
        }
        Ok(l)
    }

    fn and(&mut self) -> PResult<Expr> {
        let mut l = self.unary()?;
        loop {
            match self.peek() {
                None | Some(")") | Some(",") | Some("-o") | Some("-or") => return Ok(l),
                Some("-a") | Some("-and") => {
                    let op = self.peek().unwrap_or("").to_string();
                    self.i += 1;
                    if matches!(self.peek(), None | Some(")") | Some(",") | Some("-o") | Some("-or")) {
                        return Err(alloc::format!("invalid expression; you have used a binary operator '{op}' with nothing after it."));
                    }
                }
                _ => {}
            }
            let r = self.unary()?;
            l = Expr::And(Box::new(l), Box::new(r));
        }
    }

    fn unary(&mut self) -> PResult<Expr> {
        match self.peek() {
            Some("!") | Some("-not") => {
                self.i += 1;
                if self.peek().is_none() {
                    return Err(String::from("invalid expression; '!' or '-not' with nothing after it"));
                }
                Ok(Expr::Not(Box::new(self.unary()?)))
            }
            Some("(") => {
                self.i += 1;
                if self.peek() == Some(")") {
                    return Err(String::from("invalid expression; empty parentheses are not allowed."));
                }
                let e = self.comma()?;
                if self.peek() != Some(")") {
                    return Err(String::from("invalid expression; I was expecting to find a ')' somewhere but did not see one."));
                }
                self.i += 1;
                Ok(e)
            }
            Some(_) => self.primary(),
            None => Err(String::from("invalid expression")),
        }
    }

    fn user_id(&self, v: &str) -> PResult<u32> {
        if let Some(u) = crate::users::by_name(v) {
            return Ok(u.uid);
        }
        v.parse().map_err(|_| alloc::format!("'{v}' is not the name of a known user"))
    }

    fn group_id(&self, v: &str) -> PResult<u32> {
        if let Some(g) = crate::users::group_by_name(v) {
            return Ok(g.gid);
        }
        v.parse().map_err(|_| alloc::format!("'{v}' is not the name of an existing group"))
    }

    fn primary(&mut self) -> PResult<Expr> {
        let t = self.toks[self.i].clone();
        self.i += 1;
        let e = match t.as_str() {
            "-true" => Expr::Const(true),
            "-false" => Expr::Const(false),
            // Global options: always true, affect the walk.
            "-maxdepth" | "-mindepth" => {
                let v = self.arg(&t)?;
                let n: usize = v.parse().map_err(|_| alloc::format!("Expected a positive decimal integer argument to {t}, but got '{v}'"))?;
                if t == "-maxdepth" {
                    self.g.maxdepth = Some(n);
                } else {
                    self.g.mindepth = n;
                }
                Expr::Const(true)
            }
            "-depth" | "-d" => {
                self.g.depth_first = true;
                Expr::Const(true)
            }
            "-xdev" | "-mount" => {
                self.g.xdev = true;
                Expr::Const(true)
            }
            "-follow" => {
                self.g.follow = Follow::Always;
                Expr::Const(true)
            }
            "-noleaf" | "-ignore_readdir_race" | "-noignore_readdir_race" | "-nowarn" | "-warn" => Expr::Const(true),
            "-name" | "-iname" => Expr::Name { pat: self.arg(&t)?, icase: t == "-iname" },
            "-path" | "-wholename" | "-ipath" | "-iwholename" => Expr::Path { pat: self.arg(&t)?, icase: t.starts_with("-i") },
            "-regex" | "-iregex" => {
                let v = self.arg(&t)?;
                let re = posixre::compile_bytes(&[v], Syntax::Extended, Flags { icase: t == "-iregex", line: true, dot_nl: true, ..Default::default() })?;
                Expr::Regex(re)
            }
            "-type" | "-xtype" => {
                let v = self.arg(&t)?;
                let mut kinds = Vec::new();
                for part in v.split(',') {
                    kinds.push(match part {
                        "f" => FileType::Regular,
                        "d" => FileType::Directory,
                        "l" => FileType::Symlink,
                        "p" => FileType::Fifo,
                        "s" => FileType::Socket,
                        "c" => FileType::CharDevice,
                        "b" => FileType::BlockDevice,
                        _ => return Err(alloc::format!("Unknown argument to {t}: {part}")),
                    });
                }
                Expr::Type(kinds)
            }
            "-size" => {
                let v = self.arg(&t)?;
                let (body, unit) = match v.chars().last() {
                    Some('c') => (&v[..v.len() - 1], 1),
                    Some('w') => (&v[..v.len() - 1], 2),
                    Some('b') => (&v[..v.len() - 1], 512),
                    Some('k') => (&v[..v.len() - 1], 1024),
                    Some('M') => (&v[..v.len() - 1], 1 << 20),
                    Some('G') => (&v[..v.len() - 1], 1 << 30),
                    _ => (v.as_str(), 512),
                };
                let (cmp, n) = parse_num(body).ok_or_else(|| alloc::format!("invalid -size type in '{v}'"))?;
                Expr::Size { cmp, n, unit }
            }
            "-mtime" | "-atime" | "-ctime" | "-mmin" | "-amin" | "-cmin" => {
                let v = self.arg(&t)?;
                let (cmp, n) = parse_num(&v).ok_or_else(|| alloc::format!("invalid argument '{v}' to '{t}'"))?;
                let field = match &t[1..2] {
                    "a" => TimeField::Access,
                    "c" => TimeField::Change,
                    _ => TimeField::Modify,
                };
                Expr::Age { field, cmp, n, unit: if t.ends_with("min") { 60 } else { 86400 } }
            }
            "-newer" | "-anewer" | "-cnewer" => {
                let v = self.arg(&t)?;
                let fsctx = self.ctx.fs();
                let m = ops::stat(&fsctx, &v, true).map_err(|e| alloc::format!("'{v}': {e}"))?;
                let field = match t.as_str() {
                    "-anewer" => TimeField::Access,
                    "-cnewer" => TimeField::Change,
                    _ => TimeField::Modify,
                };
                Expr::Newer { field, than: m.mtime }
            }
            "-user" => {
                let v = self.arg(&t)?;
                Expr::Uid(self.user_id(&v)?)
            }
            "-group" => {
                let v = self.arg(&t)?;
                Expr::Gid(self.group_id(&v)?)
            }
            "-uid" | "-gid" => {
                let v = self.arg(&t)?;
                let n: u32 = v.parse().map_err(|_| alloc::format!("invalid argument '{v}' to '{t}'"))?;
                if t == "-uid" {
                    Expr::Uid(n)
                } else {
                    Expr::Gid(n)
                }
            }
            "-nouser" => Expr::NoUser,
            "-nogroup" => Expr::NoGroup,
            "-perm" => {
                let v = self.arg(&t)?;
                let (how, spec) = match v.as_bytes().first() {
                    Some(b'-') => (PermHow::All, &v[1..]),
                    Some(b'/') => (PermHow::Any, &v[1..]),
                    _ => (PermHow::Exact, v.as_str()),
                };
                let mode = super::fileops::parse_mode(spec, 0, false).ok_or_else(|| alloc::format!("invalid mode '{v}'"))?;
                Expr::Perm { mode: mode & 0o7777, how }
            }
            "-empty" => Expr::Empty,
            "-links" | "-inum" => {
                let v = self.arg(&t)?;
                let (cmp, n) = parse_num(&v).ok_or_else(|| alloc::format!("invalid argument '{v}' to '{t}'"))?;
                if t == "-links" {
                    Expr::Links(cmp, n)
                } else {
                    Expr::Inum(cmp, n)
                }
            }
            "-readable" => Expr::Access(MAY_READ),
            "-writable" => Expr::Access(MAY_WRITE),
            "-executable" => Expr::Access(MAY_EXEC),
            "-print" | "-print0" => {
                self.has_action = true;
                Expr::Print { nul: t == "-print0" }
            }
            "-printf" => {
                self.has_action = true;
                let v = self.arg(&t)?;
                Expr::Printf(parse_printf(&v)?)
            }
            "-ls" => {
                self.has_action = true;
                Expr::Ls
            }
            "-delete" => {
                self.has_action = true;
                self.g.depth_first = true;
                Expr::Delete
            }
            "-prune" => Expr::Prune,
            "-quit" => Expr::Quit,
            "-exec" | "-execdir" | "-ok" | "-okdir" => {
                self.has_action = true;
                let mut argv = Vec::new();
                let mut plus = false;
                loop {
                    let Some(a) = self.toks.get(self.i).cloned() else {
                        return Err(alloc::format!("missing argument to '{t}'"));
                    };
                    self.i += 1;
                    if a == ";" {
                        break;
                    }
                    if a == "+" && argv.last().is_some_and(|l: &String| l == "{}") && !t.starts_with("-ok") {
                        plus = true;
                        argv.pop();
                        break;
                    }
                    argv.push(a);
                }
                if argv.is_empty() {
                    return Err(alloc::format!("missing argument to '{t}'"));
                }
                if plus && argv.iter().any(|a| a.contains("{}")) {
                    return Err(String::from("only one instance of {} is supported with -exec ... +"));
                }
                let batch = if plus {
                    self.batches += 1;
                    Some(self.batches - 1)
                } else {
                    None
                };
                Expr::Exec { argv, batch, in_dir: t.ends_with("dir"), ask: t.starts_with("-ok") }
            }
            "-daystart" => {
                // Measure ages from the start of today (UTC).
                self.now = self.now - self.now.rem_euclid(86400) + 86400;
                Expr::Const(true)
            }
            other if other.starts_with('-') => return Err(alloc::format!("unknown predicate '{other}'")),
            other => return Err(alloc::format!("paths must precede expression: '{other}'")),
        };
        Ok(e)
    }
}

fn parse_printf(s: &str) -> PResult<Vec<Fmt>> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut lit = String::new();
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '\\' if i + 1 < c.len() => {
                i += 1;
                match c[i] {
                    'n' => lit.push('\n'),
                    't' => lit.push('\t'),
                    'r' => lit.push('\r'),
                    '0' => lit.push('\0'),
                    'a' => lit.push('\x07'),
                    'b' => lit.push('\x08'),
                    'f' => lit.push('\x0c'),
                    'v' => lit.push('\x0b'),
                    '\\' => lit.push('\\'),
                    'c' => {
                        out.push(Fmt::Lit(core::mem::take(&mut lit)));
                        return Ok(out);
                    }
                    o => {
                        lit.push('\\');
                        lit.push(o);
                    }
                }
                i += 1;
            }
            '%' if i + 1 < c.len() => {
                i += 1;
                if c[i] == '%' {
                    lit.push('%');
                    i += 1;
                    continue;
                }
                let mut left = false;
                while i < c.len() && matches!(c[i], '-' | '+' | ' ' | '#' | '0') {
                    if c[i] == '-' {
                        left = true;
                    }
                    i += 1;
                }
                let mut w = String::new();
                while i < c.len() && c[i].is_ascii_digit() {
                    w.push(c[i]);
                    i += 1;
                }
                let Some(&spec) = c.get(i) else { return Err(String::from("error: format directive incomplete")) };
                i += 1;
                let time = if matches!(spec, 'A' | 'C' | 'T') {
                    let t = *c.get(i).ok_or_else(|| String::from("error: format directive incomplete"))?;
                    i += 1;
                    Some(t)
                } else {
                    None
                };
                if !lit.is_empty() {
                    out.push(Fmt::Lit(core::mem::take(&mut lit)));
                }
                out.push(Fmt::Dir { spec, time, width: w.parse().ok(), left });
            }
            ch => {
                lit.push(ch);
                i += 1;
            }
        }
    }
    if !lit.is_empty() {
        out.push(Fmt::Lit(lit));
    }
    Ok(out)
}

// ── evaluation ─────────────────────────────────────────────────────────────

struct Node<'a> {
    path: &'a str,
    /// Path relative to the start point (`%P`).
    rel: &'a str,
    /// Start point this node was reached from (`%H`).
    start: &'a str,
    name: &'a str,
    meta: &'a Metadata,
    depth: usize,
}

struct Walker<'a> {
    ctx: &'a mut Ctx,
    g: &'a Globals,
    now: i64,
    names: NameCache,
    batches: Vec<(Vec<String>, Vec<String>)>,
    status: i32,
    prune: bool,
    quit: bool,
}

fn time_of(m: &Metadata, f: TimeField) -> Timespec {
    match f {
        TimeField::Access => m.atime,
        TimeField::Modify => m.mtime,
        TimeField::Change => m.ctime,
    }
}

fn basename(path: &str) -> &str {
    let t = path.trim_end_matches('/');
    if t.is_empty() {
        return if path.is_empty() { "" } else { "/" };
    }
    t.rsplit('/').next().unwrap_or(t)
}

fn dirname(path: &str) -> &str {
    let t = path.trim_end_matches('/');
    match t.rfind('/') {
        Some(0) => "/",
        Some(i) => &t[..i],
        None => ".",
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        alloc::format!("{dir}{name}")
    } else {
        alloc::format!("{dir}/{name}")
    }
}

impl Walker<'_> {
    fn eval(&mut self, e: &Expr, n: &Node) -> bool {
        if self.quit {
            return false;
        }
        match e {
            Expr::And(a, b) => self.eval(a, n) && self.eval(b, n),
            Expr::Or(a, b) => self.eval(a, n) || self.eval(b, n),
            Expr::Comma(a, b) => {
                self.eval(a, n);
                self.eval(b, n)
            }
            Expr::Not(a) => !self.eval(a, n),
            Expr::Const(v) => *v,
            Expr::Name { pat, icase } => {
                if *icase {
                    fastros_sh::pattern::matches(&pat.to_lowercase(), &n.name.to_lowercase())
                } else {
                    fastros_sh::pattern::matches(pat, n.name)
                }
            }
            Expr::Path { pat, icase } => {
                if *icase {
                    fastros_sh::pattern::matches(&pat.to_lowercase(), &n.path.to_lowercase())
                } else {
                    fastros_sh::pattern::matches(pat, n.path)
                }
            }
            Expr::Regex(re) => re.is_match(n.path.as_bytes()),
            Expr::Type(kinds) => kinds.contains(&n.meta.kind),
            Expr::Size { cmp, n: want, unit } => {
                let units = n.meta.size.div_ceil(*unit);
                cmp.test(units, *want)
            }
            Expr::Age { field, cmp, n: want, unit } => {
                let t = time_of(n.meta, *field).sec;
                let age = self.now - t;
                // Ages in the future count as 0 units old... less than zero.
                let units = if age < 0 { -1i64 } else { age / *unit as i64 };
                match cmp {
                    Cmp::Lt => units < *want as i64,
                    Cmp::Eq => units == *want as i64,
                    Cmp::Gt => units > *want as i64,
                }
            }
            Expr::Newer { field, than } => time_of(n.meta, *field) > *than,
            Expr::Uid(u) => n.meta.uid == *u,
            Expr::Gid(g) => n.meta.gid == *g,
            Expr::NoUser => crate::users::by_uid(n.meta.uid).is_none(),
            Expr::NoGroup => crate::users::group_by_gid(n.meta.gid).is_none(),
            Expr::Perm { mode, how } => {
                let p = n.meta.perm & 0o7777;
                match how {
                    PermHow::Exact => p == *mode,
                    PermHow::All => p & mode == *mode,
                    PermHow::Any => *mode == 0 || p & mode != 0,
                }
            }
            Expr::Empty => match n.meta.kind {
                FileType::Regular => n.meta.size == 0,
                FileType::Directory => ops::list_dir(&self.ctx.fs(), n.path).map(|v| v.is_empty()).unwrap_or(false),
                _ => false,
            },
            Expr::Links(cmp, want) => cmp.test(n.meta.nlink as u64, *want),
            Expr::Inum(cmp, want) => cmp.test(n.meta.ino, *want),
            Expr::Access(mask) => ops::access(&self.ctx.fs(), n.path, *mask).is_ok(),
            Expr::Print { nul } => {
                self.ctx.print(n.path);
                self.ctx.write(if *nul { b"\0" } else { b"\n" });
                true
            }
            Expr::Printf(f) => {
                let s = self.format(f, n);
                self.ctx.print(&s);
                true
            }
            Expr::Ls => {
                let line = self.ls_line(n);
                self.ctx.print(&line);
                true
            }
            Expr::Delete => {
                // `find . -delete` never removes the start point `.`.
                if n.path == "." {
                    return true;
                }
                let fsctx = self.ctx.fs();
                let r = if n.meta.kind == FileType::Directory { ops::rmdir(&fsctx, n.path) } else { ops::unlink(&fsctx, n.path) };
                match r {
                    Ok(()) => true,
                    Err(e) => {
                        let p = n.path.to_string();
                        self.ctx.fail(alloc::format!("cannot delete '{p}': {e}"));
                        self.status = 1;
                        false
                    }
                }
            }
            Expr::Prune => {
                self.prune = true;
                true
            }
            Expr::Quit => {
                self.quit = true;
                true
            }
            Expr::Exec { argv, batch, in_dir, ask } => {
                if let Some(b) = batch {
                    let item = if *in_dir { alloc::format!("./{}", n.name) } else { n.path.to_string() };
                    if self.batches[*b].0.is_empty() {
                        self.batches[*b].0 = argv.clone();
                    }
                    self.batches[*b].1.push(item);
                    if self.batches[*b].1.len() >= 512 {
                        self.flush_batch(*b);
                    }
                    return true;
                }
                let subst = if *in_dir { alloc::format!("./{}", n.name) } else { n.path.to_string() };
                let cmd: Vec<String> = argv.iter().map(|a| a.replace("{}", &subst)).collect();
                if *ask {
                    let q = alloc::format!("< {} ... {} > ? ", cmd[0], subst);
                    self.ctx.eprint(&q);
                    if !read_yes(self.ctx) {
                        return false;
                    }
                }
                let dir = if *in_dir { Some(dirname(n.path).to_string()) } else { None };
                self.run(cmd, dir.as_deref()) == 0
            }
        }
    }

    /// Run a command as a child of find, optionally in another directory.
    fn run(&mut self, argv: Vec<String>, dir: Option<&str>) -> i32 {
        self.ctx.flush();
        let proc = self.ctx.proc.clone();
        let saved = dir.map(|_| proc.fs.lock().cwd.clone());
        if let Some(d) = dir {
            if let Err(e) = ops::chdir(&proc, d) {
                self.ctx.fail(alloc::format!("{d}: {e}"));
                return 1;
            }
        }
        let st = crate::shell::run_argv(&proc, argv, None, None);
        if let Some(cwd) = saved {
            proc.fs.lock().cwd = cwd;
        }
        st
    }

    fn flush_batch(&mut self, b: usize) {
        let (argv, items) = core::mem::take(&mut self.batches[b]);
        if items.is_empty() {
            self.batches[b].0 = argv;
            return;
        }
        let mut cmd = argv.clone();
        cmd.extend(items);
        if self.run(cmd, None) != 0 {
            self.status = 1;
        }
        self.batches[b].0 = argv;
    }

    fn format(&self, f: &[Fmt], n: &Node) -> String {
        let mut s = String::new();
        for piece in f {
            match piece {
                Fmt::Lit(l) => s.push_str(l),
                Fmt::Dir { spec, time, width, left } => {
                    let v = self.directive(*spec, *time, n);
                    let pad = width.unwrap_or(0).saturating_sub(fmtutil::width(&v));
                    if *left {
                        s.push_str(&v);
                        s.extend(core::iter::repeat_n(' ', pad));
                    } else {
                        s.extend(core::iter::repeat_n(' ', pad));
                        s.push_str(&v);
                    }
                }
            }
        }
        s
    }

    fn directive(&self, spec: char, time: Option<char>, n: &Node) -> String {
        let m = n.meta;
        match spec {
            'p' => n.path.to_string(),
            'f' => n.name.to_string(),
            'h' => {
                let d = dirname(n.path);
                if n.path.contains('/') { d.to_string() } else { String::from(".") }
            }
            'P' => n.rel.to_string(),
            'H' => n.start.to_string(),
            'd' => n.depth.to_string(),
            's' => m.size.to_string(),
            'b' => m.blocks.to_string(),
            'k' => m.blocks.div_ceil(2).to_string(),
            'm' => alloc::format!("{:o}", m.perm & 0o7777),
            'M' => fmtutil::mode_string(m),
            'u' => self.names.user(m.uid),
            'U' => m.uid.to_string(),
            'g' => self.names.group(m.gid),
            'G' => m.gid.to_string(),
            'i' => m.ino.to_string(),
            'n' => m.nlink.to_string(),
            'D' => m.dev.to_string(),
            'y' => m.kind.letter().to_string().replace('-', "f"),
            'l' => {
                if m.kind == FileType::Symlink {
                    ops::readlink(&self.ctx.fs(), n.path).unwrap_or_default()
                } else {
                    String::new()
                }
            }
            'a' | 't' | 'c' => ctime(time_of(m, field_for(spec))),
            'A' | 'T' | 'C' => {
                let ts = time_of(m, field_for(spec));
                let tm = civil::from_unix(ts.sec);
                match time.unwrap_or('+') {
                    '@' => alloc::format!("{}.{:09}0", ts.sec, ts.nsec),
                    'Y' => alloc::format!("{:04}", tm.year),
                    'm' => alloc::format!("{:02}", tm.month),
                    'd' => alloc::format!("{:02}", tm.day),
                    'H' => alloc::format!("{:02}", tm.hour),
                    'M' => alloc::format!("{:02}", tm.min),
                    'S' => alloc::format!("{:02}.{:09}0", tm.sec, ts.nsec),
                    'F' => alloc::format!("{:04}-{:02}-{:02}", tm.year, tm.month, tm.day),
                    'T' => alloc::format!("{:02}:{:02}:{:02}.{:09}0", tm.hour, tm.min, tm.sec, ts.nsec),
                    '+' => alloc::format!("{:04}-{:02}-{:02}+{:02}:{:02}:{:02}.{:09}0", tm.year, tm.month, tm.day, tm.hour, tm.min, tm.sec, ts.nsec),
                    'b' | 'h' => civil::MONTHS[(tm.month - 1) as usize].to_string(),
                    'a' => civil::WEEKDAYS[tm.weekday as usize].to_string(),
                    'j' => alloc::format!("{:03}", tm.yday + 1),
                    _ => String::new(),
                }
            }
            _ => String::new(),
        }
    }

    /// `-ls`: `%9i %6k %M %3n %-8u %-8g %8s <time> <path> [-> target]`.
    fn ls_line(&self, n: &Node) -> String {
        let m = n.meta;
        let size = if matches!(m.kind, FileType::CharDevice | FileType::BlockDevice) {
            alloc::format!("{:>3}, {:>3}", crate::fs::major(m.rdev), crate::fs::minor(m.rdev))
        } else {
            m.size.to_string()
        };
        let mut s = alloc::format!(
            "{:>9} {:>6} {} {:>3} {} {} {:>8} {} {}",
            m.ino,
            m.blocks.div_ceil(2),
            fmtutil::mode_string(m),
            m.nlink,
            fmtutil::pad_right(&self.names.user(m.uid), 8),
            fmtutil::pad_right(&self.names.group(m.gid), 8),
            size,
            fmtutil::ls_time(m.mtime.sec),
            n.path
        );
        if m.kind == FileType::Symlink {
            if let Ok(t) = ops::readlink(&self.ctx.fs(), n.path) {
                s.push_str(" -> ");
                s.push_str(&t);
            }
        }
        s.push('\n');
        s
    }

    /// Visit `path` (and, for directories, everything below).
    fn visit(&mut self, e: &Expr, path: &str, start: &str, depth: usize, root_dev: u64, ancestors: &mut Vec<(u64, u64)>) {
        if self.quit || self.ctx.should_stop() {
            self.quit = true;
            return;
        }
        let fsctx = self.ctx.fs();
        let follow = match self.g.follow {
            Follow::Always => true,
            Follow::CommandLine => depth == 0,
            Follow::Never => false,
        };
        let meta = match ops::stat(&fsctx, path, follow) {
            Ok(m) => m,
            // A dangling symlink under -L is reported as the link itself.
            Err(Errno::ENOENT) if follow => match ops::stat(&fsctx, path, false) {
                Ok(m) => m,
                Err(e) => {
                    self.error(path, e);
                    return;
                }
            },
            Err(e) => {
                self.error(path, e);
                return;
            }
        };
        let rel = if depth == 0 {
            ""
        } else {
            let r = &path[start.len()..];
            r.trim_start_matches('/')
        };
        let name = basename(path).to_string();
        let is_dir = meta.kind == FileType::Directory;
        if is_dir && follow && ancestors.contains(&(meta.dev, meta.ino)) {
            let p = path.to_string();
            self.ctx.fail(alloc::format!("File system loop detected; '{p}' is part of the same file system loop as an ancestor."));
            self.status = 1;
            return;
        }
        let node = Node { path, rel, start, name: &name, meta: &meta, depth };
        let eval_here = depth >= self.g.mindepth;
        self.prune = false;
        if eval_here && !self.g.depth_first {
            self.eval(e, &node);
        }
        let descend = is_dir && !self.prune && self.g.maxdepth.is_none_or(|m| depth < m) && !(self.g.xdev && depth > 0 && meta.dev != root_dev);
        if descend && !self.quit {
            match ops::list_dir(&fsctx, path) {
                Ok(entries) => {
                    ancestors.push((meta.dev, meta.ino));
                    for ent in entries {
                        if self.quit {
                            break;
                        }
                        let child = join(path, &ent.name);
                        self.visit(e, &child, start, depth + 1, root_dev, ancestors);
                    }
                    ancestors.pop();
                }
                Err(err) => self.error(path, err),
            }
        }
        if eval_here && self.g.depth_first && !self.quit {
            self.eval(e, &node);
        }
    }

    fn error(&mut self, path: &str, e: Errno) {
        let p = path.to_string();
        self.ctx.fail(alloc::format!("'{p}': {e}"));
        self.status = 1;
    }
}

fn field_for(spec: char) -> TimeField {
    match spec {
        'a' | 'A' => TimeField::Access,
        'c' | 'C' => TimeField::Change,
        _ => TimeField::Modify,
    }
}

/// `ctime(3)`-style time with nanoseconds, as `%t` prints it.
fn ctime(ts: Timespec) -> String {
    let tm = civil::from_unix(ts.sec);
    alloc::format!(
        "{} {} {:>2} {:02}:{:02}:{:02}.{:09}0 {}",
        civil::WEEKDAYS[tm.weekday as usize],
        civil::MONTHS[(tm.month - 1) as usize],
        tm.day,
        tm.hour,
        tm.min,
        tm.sec,
        ts.nsec,
        tm.year
    )
}

fn read_yes(ctx: &mut Ctx) -> bool {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match ctx.read_stdin(&mut b) {
            Ok(1) if b[0] != b'\n' => line.push(b[0]),
            _ => break,
        }
    }
    matches!(line.first(), Some(b'y') | Some(b'Y'))
}

pub fn find(ctx: &mut Ctx) -> i32 {
    let args = ctx.args.clone();
    let mut i = 1;
    let mut follow = Follow::Never;
    while i < args.len() {
        match args[i].as_str() {
            "-P" => follow = Follow::Never,
            "-L" => follow = Follow::Always,
            "-H" => follow = Follow::CommandLine,
            "--help" => {
                ctx.print("Usage: find [-H] [-L] [-P] [path...] [expression]\n");
                return 0;
            }
            _ => break,
        }
        i += 1;
    }
    let mut paths = Vec::new();
    while i < args.len() {
        let a = &args[i];
        if (a.starts_with('-') && a.len() > 1) || a == "!" || a == "(" || a == ")" || a == "," {
            break;
        }
        paths.push(a.clone());
        i += 1;
    }
    if paths.is_empty() {
        paths.push(String::from("."));
    }
    let now = crate::time::unix_now() as i64;
    let toks = &args[i..];
    let (expr, g, has_action, batches, now) = {
        let mut p = Parser {
            toks,
            i: 0,
            g: Globals { follow, maxdepth: None, mindepth: 0, depth_first: false, xdev: false },
            has_action: false,
            batches: 0,
            ctx,
            now,
        };
        let e = match p.parse() {
            Ok(e) => e,
            Err(m) => {
                return ctx.fail(m);
            }
        };
        (e, p.g, p.has_action, p.batches, p.now)
    };
    // No action: `( expr ) -print`.
    let expr = match expr {
        None => Expr::Print { nul: false },
        Some(e) if !has_action => Expr::And(Box::new(e), Box::new(Expr::Print { nul: false })),
        Some(e) => e,
    };
    let mut w = Walker { ctx, g: &g, now, names: NameCache::new(), batches: (0..batches).map(|_| (Vec::new(), Vec::new())).collect(), status: 0, prune: false, quit: false };
    for p in &paths {
        if w.quit {
            break;
        }
        if p.is_empty() {
            w.ctx.fail("'': No such file or directory");
            w.status = 1;
            continue;
        }
        let dev = ops::stat(&w.ctx.fs(), p, true).map(|m| m.dev).unwrap_or(0);
        w.visit(&expr, p, p, 0, dev, &mut Vec::new());
    }
    for b in 0..w.batches.len() {
        w.flush_batch(b);
    }
    if w.ctx.should_stop() {
        return 130;
    }
    w.status
}

// ── xargs ──────────────────────────────────────────────────────────────────

/// Split input into items the way xargs does: blanks separate, quotes and
/// backslashes escape; a line of `-L`/`-I` input is one logical record.
fn xargs_items(data: &[u8], delim: Option<u8>, per_line: bool) -> Result<Vec<Vec<String>>, String> {
    let text = String::from_utf8_lossy(data);
    if let Some(d) = delim {
        let mut v: Vec<Vec<String>> = text.split(d as char).map(|s| alloc::vec![s.to_string()]).collect();
        // A trailing delimiter does not start another item.
        if v.last().is_some_and(|l| l[0].is_empty()) {
            v.pop();
        }
        return Ok(v);
    }
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut cur_rec: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some(q) if q == c => break,
                        Some('\n') | None => {
                            return Err(alloc::format!("unmatched {} quote; by default quotes are special to xargs unless you use the -0 option", if c == '\'' { "single" } else { "double" }));
                        }
                        Some(ch) => word.push(ch),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(n) = chars.next() {
                    word.push(n);
                }
            }
            ' ' | '\t' | '\n' => {
                if in_word {
                    cur_rec.push(core::mem::take(&mut word));
                    in_word = false;
                }
                // `-L`: a line ending in a blank continues on the next line.
                if c == '\n' && per_line && !cur_rec.is_empty() {
                    records.push(core::mem::take(&mut cur_rec));
                }
                if !per_line && !cur_rec.is_empty() {
                    records.push(core::mem::take(&mut cur_rec));
                }
            }
            ch => {
                in_word = true;
                word.push(ch);
            }
        }
    }
    if in_word {
        cur_rec.push(word);
    }
    if !cur_rec.is_empty() {
        if per_line {
            records.push(cur_rec);
        } else {
            for w in cur_rec {
                records.push(alloc::vec![w]);
            }
        }
    }
    Ok(records)
}

pub fn xargs(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "0rtpx",
        values: "nILd:sPaE",
        long: &[
            ("null", '0', false),
            ("no-run-if-empty", 'r', false),
            ("verbose", 't', false),
            ("interactive", 'p', false),
            ("max-args", 'n', true),
            ("max-lines", 'L', true),
            ("replace", 'I', true),
            ("delimiter", 'd', true),
            ("max-chars", 's', true),
            ("max-procs", 'P', true),
            ("arg-file", 'a', true),
            ("exit", 'x', false),
        ],
    };
    // Options stop at the first operand (the command).
    let mut split = 1;
    while split < ctx.args.len() {
        let a = &ctx.args[split];
        if a == "--" {
            split += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        let takes = a.len() == 2 && "nILdsPaE".contains(&a[1..]);
        split += if takes { 2 } else { 1 };
    }
    let split = split.min(ctx.args.len());
    let opt_args: Vec<String> = ctx.args[..split].to_vec();
    let p = match parse_opts(&opt_args, &SPEC) {
        Ok(p) => p,
        Err(m) => {
            ctx.fail(m);
            return 1;
        }
    };
    let mut cmd: Vec<String> = ctx.args[split..].to_vec();
    if cmd.is_empty() {
        cmd.push(String::from("echo"));
    }
    let num = |c: char| -> Result<Option<usize>, String> {
        match p.value(c) {
            None => Ok(None),
            Some(v) => v.parse::<usize>().ok().filter(|&n| n > 0).map(Some).ok_or_else(|| alloc::format!("invalid number \"{v}\" for -{c} option")),
        }
    };
    let (max_args, max_lines, max_chars) = match (num('n'), num('L'), num('s')) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c.unwrap_or(128 * 1024)),
        (Err(m), _, _) | (_, Err(m), _) | (_, _, Err(m)) => {
            ctx.fail(m);
            return 1;
        }
    };
    let replace = p.value('I').map(|s| s.to_string());
    let delim: Option<u8> = if p.has('0') {
        Some(0)
    } else if let Some(d) = p.value('d') {
        let (s, _) = fmtutil::unescape(d);
        s.bytes().next()
    } else if replace.is_some() {
        Some(b'\n')
    } else {
        None
    };
    let input = match p.value('a') {
        Some(f) => {
            let f = f.to_string();
            ctx.read_input(&f)
        }
        None => ctx.read_input("-"),
    };
    let data = match input {
        Ok(d) => d,
        Err(e) => {
            ctx.fail(e);
            return 1;
        }
    };
    let records = match xargs_items(&data, delim, max_lines.is_some()) {
        Ok(r) => r,
        Err(m) => {
            ctx.fail(m);
            return 1;
        }
    };
    // Group items into command lines.
    let mut lines: Vec<Vec<String>> = Vec::new();
    if let Some(r) = &replace {
        for rec in records {
            let item = rec.join(" ");
            let item = item.trim_start_matches([' ', '\t']).to_string();
            lines.push(cmd.iter().map(|a| a.replace(r.as_str(), &item)).collect());
        }
    } else {
        let base_len: usize = cmd.iter().map(|a| a.len() + 1).sum();
        let mut cur: Vec<String> = Vec::new();
        let mut cur_len = base_len;
        let mut cur_recs = 0;
        for rec in records {
            let rec_len: usize = rec.iter().map(|a| a.len() + 1).sum();
            let too_many = max_args.is_some_and(|m| cur.len() + rec.len() > m && !cur.is_empty());
            let too_long = cur_len + rec_len > max_chars && !cur.is_empty();
            let lines_full = max_lines.is_some_and(|m| cur_recs >= m);
            if too_many || too_long || lines_full {
                let mut l = cmd.clone();
                l.append(&mut cur);
                lines.push(l);
                cur_len = base_len;
                cur_recs = 0;
            }
            if base_len + rec_len > max_chars && p.has('x') {
                ctx.fail("argument line too long");
                return 1;
            }
            for a in rec {
                cur_len += a.len() + 1;
                cur.push(a);
                if let Some(m) = max_args {
                    if cur.len() >= m && max_lines.is_none() {
                        let mut l = cmd.clone();
                        l.append(&mut cur);
                        lines.push(l);
                        cur_len = base_len;
                    }
                }
            }
            cur_recs += 1;
        }
        if !cur.is_empty() || (lines.is_empty() && !p.has('r')) {
            let mut l = cmd.clone();
            l.append(&mut cur);
            lines.push(l);
        }
    }
    let mut status = 0;
    for argv in lines {
        if ctx.should_stop() {
            return 125;
        }
        if p.has('t') || p.has('p') {
            let shown = alloc::format!("{}{}", argv.join(" "), if p.has('p') { " ?..." } else { "\n" });
            ctx.eprint(&shown);
            if p.has('p') {
                let yes = match ctx.stdin_tty().or_else(|| ctx.proc.ctty.lock().clone()) {
                    Some(t) => {
                        let mut ans = [0u8; 64];
                        let n = t.read(&mut ans, false).unwrap_or(0);
                        matches!(ans[..n].first(), Some(b'y') | Some(b'Y'))
                    }
                    None => false,
                };
                if !yes {
                    continue;
                }
            }
        }
        ctx.flush();
        let st = crate::shell::run_argv(&ctx.proc, argv, None, None);
        match st {
            0 => {}
            255 => {
                let c = ctx.args.get(split).cloned().unwrap_or_else(|| String::from("echo"));
                ctx.fail(alloc::format!("{c}: exited with status 255; aborting"));
                return 124;
            }
            126 | 127 => return st,
            s if s > 128 => return 125,
            _ => status = 123,
        }
    }
    status
}

// ── updatedb / locate ──────────────────────────────────────────────────────

const LOCATE_DB: &str = "/var/lib/locate/db";
const LOCATE_MAGIC: &str = "FASTROS-LOCATE 1";
/// Pseudo and volatile filesystems are never indexed.
const PRUNE_PATHS: [&str; 7] = ["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/var/cache"];

/// A context with the caller's namespace but full authority, for reading
/// and writing the database.
fn privileged(ctx: &Ctx) -> ops::Ctx {
    ops::Ctx { fs: ctx.fs().fs, cred: Cred::root() }
}

fn escape_path(p: &str, out: &mut String) {
    for c in p.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('\n');
}

fn unescape_path(l: &str) -> String {
    let mut o = String::with_capacity(l.len());
    let mut esc = false;
    for c in l.chars() {
        if esc {
            o.push(if c == 'n' { '\n' } else { c });
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else {
            o.push(c);
        }
    }
    o
}

pub fn updatedb(ctx: &mut Ctx) -> i32 {
    if !ctx.cred().is_root() {
        return ctx.fail("permission denied: only root can build the locate database");
    }
    let verbose = ctx.args.iter().any(|a| a == "-v" || a == "--verbose");
    let fsctx = privileged(ctx);
    let mut out = String::from(LOCATE_MAGIC);
    out.push('\n');
    let mut stack: Vec<String> = alloc::vec![String::from("/")];
    let mut count = 0u64;
    while let Some(dir) = stack.pop() {
        if ctx.should_stop() {
            return 130;
        }
        let Ok(mut entries) = ops::list_dir(&fsctx, &dir) else { continue };
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut subdirs = Vec::new();
        for e in entries {
            let full = join(&dir, &e.name);
            if PRUNE_PATHS.contains(&full.as_str()) {
                continue;
            }
            escape_path(&full, &mut out);
            count += 1;
            if verbose {
                crate::outln!(ctx, "{}", full);
            }
            if let Ok(m) = ops::stat(&fsctx, &full, false) {
                if m.kind == FileType::Directory {
                    subdirs.push(full);
                }
            }
            crate::sched::cond_resched();
        }
        subdirs.reverse();
        stack.extend(subdirs);
    }
    if let Err(e) = ops::mkdir_all(&fsctx, "/var/lib/locate", 0o755) {
        return ctx.fail_errno("/var/lib/locate", e);
    }
    let tmp = alloc::format!("{LOCATE_DB}.tmp");
    if let Err(e) = ops::write_file(&fsctx, &tmp, out.as_bytes(), 0o600) {
        return ctx.fail_errno(&tmp, e);
    }
    let _ = ops::chmod(&fsctx, &tmp, 0o600, true);
    if let Err(e) = ops::rename(&fsctx, &tmp, LOCATE_DB) {
        return ctx.fail_errno(LOCATE_DB, e);
    }
    if verbose {
        crate::outln!(ctx, "updatedb: {} entries", count);
    }
    0
}

/// May `cred` see `path`: every ancestor searchable, the parent readable?
fn visible(user: &ops::Ctx, path: &str) -> bool {
    if ops::stat(user, path, false).is_err() {
        return false;
    }
    let parent = dirname(path);
    match ops::stat(user, parent, true) {
        Ok(m) => perm::check(&user.cred, &m, MAY_READ).is_ok(),
        Err(_) => false,
    }
}

pub fn locate(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "icbeA0qS",
        values: "ld",
        long: &[
            ("ignore-case", 'i', false),
            ("count", 'c', false),
            ("basename", 'b', false),
            ("existing", 'e', false),
            ("all", 'A', false),
            ("null", '0', false),
            ("quiet", 'q', false),
            ("limit", 'l', true),
            ("database", 'd', true),
            ("regex", '\u{1}', false),
            ("regexp", '\u{1}', false),
            ("statistics", 'S', false),
        ],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let limit: Option<u64> = match p.value('l') {
        Some(v) => match v.parse() {
            Ok(n) => Some(n),
            Err(_) => return ctx.fail(alloc::format!("invalid value '{v}' of --limit")),
        },
        None => None,
    };
    if p.operands.is_empty() && !p.has('S') {
        return ctx.fail("no pattern to search for specified");
    }
    let db_path = p.value('d').unwrap_or(LOCATE_DB).to_string();
    // A non-default database is read with the caller's own rights.
    let reader = if db_path == LOCATE_DB { privileged(ctx) } else { ctx.fs() };
    let data = match ops::read_file(&reader, &db_path) {
        Ok(d) => d,
        Err(e) => {
            if !p.has('q') {
                ctx.fail(alloc::format!("can not stat () '{db_path}': {e}"));
                if e == Errno::ENOENT {
                    ctx.eprint("locate: run 'updatedb' as root to build the database\n");
                }
            }
            return 1;
        }
    };
    let text = String::from_utf8_lossy(&data);
    let mut lines = text.lines();
    if lines.next() != Some(LOCATE_MAGIC) {
        return ctx.fail(alloc::format!("{db_path}: not a FastROS locate database"));
    }
    let user = ctx.fs();
    if p.has('S') {
        let n = lines.count();
        crate::outln!(ctx, "Database {}:\n\t{} entries", db_path, n);
        return 0;
    }
    let icase = p.has('i');
    enum Pat {
        Glob(String),
        Sub(String),
        Re(regex::bytes::Regex),
    }
    let mut pats = Vec::new();
    for o in &p.operands {
        if p.has('\u{1}') {
            match posixre::compile_bytes(core::slice::from_ref(o), Syntax::Basic, Flags { icase, ..Default::default() }) {
                Ok(r) => pats.push(Pat::Re(r)),
                Err(m) => return ctx.fail(m),
            }
        } else if fastros_sh::pattern::has_magic(o) {
            pats.push(Pat::Glob(if icase { o.to_lowercase() } else { o.clone() }));
        } else {
            pats.push(Pat::Sub(if icase { o.to_lowercase() } else { o.clone() }));
        }
    }
    let mut found = 0u64;
    for raw in lines {
        if ctx.should_stop() || limit.is_some_and(|l| found >= l) {
            break;
        }
        let path = unescape_path(raw);
        let subject_full = if icase { path.to_lowercase() } else { path.clone() };
        let subject = if p.has('b') { basename(&subject_full).to_string() } else { subject_full };
        let hit = |pat: &Pat| match pat {
            // Globs without a slash-free anchor match the whole name, like mlocate.
            Pat::Glob(g) => fastros_sh::pattern::matches(g, &subject) || fastros_sh::pattern::matches(g, basename(&subject)),
            Pat::Sub(s) => subject.contains(s.as_str()),
            Pat::Re(r) => r.is_match(subject.as_bytes()),
        };
        let ok = if p.has('A') { pats.iter().all(hit) } else { pats.iter().any(hit) };
        if !ok || !visible(&user, &path) {
            continue;
        }
        found += 1;
        if !p.has('c') {
            ctx.print(&path);
            ctx.write(if p.has('0') { b"\0" } else { b"\n" });
        }
    }
    if p.has('c') {
        crate::outln!(ctx, "{}", found);
    }
    if found > 0 {
        0
    } else {
        1
    }
}
