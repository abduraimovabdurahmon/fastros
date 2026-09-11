//! The environment a native command runs in: arguments, standard streams
//! (with buffered output), the process context, and option parsing.

use crate::errno::{Errno, KResult};
use crate::fs::file::{flags, File};
use crate::fs::ops;
use crate::proc::Process;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

/// A native command's entry point.
pub type Main = fn(&mut Ctx) -> i32;

pub struct CommandDef {
    pub name: &'static str,
    pub main: Main,
    /// One-line description (`help`, `whatis`).
    pub about: &'static str,
    /// Usage line after the name, e.g. `[-l] [FILE]...`.
    pub usage: &'static str,
}

pub struct Ctx {
    pub args: Vec<String>,
    pub proc: Arc<Process>,
    stdin: Arc<dyn File>,
    stdout: Arc<dyn File>,
    stderr: Arc<dyn File>,
    out: Vec<u8>,
    broken: bool,
}

const OUT_BUF: usize = 16 * 1024;

impl Ctx {
    pub fn new(proc: Arc<Process>, args: Vec<String>) -> Ctx {
        let fds = proc.fds.lock();
        let null = || -> Arc<dyn File> {
            crate::device::open_char(crate::fs::makedev(1, 3), flags::O_RDWR).expect("/dev/null always opens")
        };
        let stdin = fds.get(0).unwrap_or_else(|_| null());
        let stdout = fds.get(1).unwrap_or_else(|_| null());
        let stderr = fds.get(2).unwrap_or_else(|_| null());
        drop(fds);
        Ctx { args, proc, stdin, stdout, stderr, out: Vec::with_capacity(1024), broken: false }
    }

    pub fn name(&self) -> &str {
        self.args.first().map(|s| s.as_str()).unwrap_or("?")
    }

    // ── output ──────────────────────────────────────────────────────────

    pub fn write(&mut self, b: &[u8]) {
        if self.broken {
            return;
        }
        self.out.extend_from_slice(b);
        if self.out.len() >= OUT_BUF {
            self.flush();
        }
    }
    pub fn print(&mut self, s: &str) {
        self.write(s.as_bytes());
    }
    pub fn println(&mut self, s: &str) {
        self.write(s.as_bytes());
        self.write(b"\n");
    }
    pub fn fmt(&mut self, args: fmt::Arguments) {
        let mut s = String::new();
        let _ = fmt::write(&mut s, args);
        self.print(&s);
    }

    /// Push buffered output to stdout. False once stdout is gone (EPIPE).
    pub fn flush(&mut self) -> bool {
        if self.out.is_empty() || self.broken {
            self.out.clear();
            return !self.broken;
        }
        let r = self.stdout.write_all(&self.out);
        self.out.clear();
        if r.is_err() {
            self.broken = true;
        }
        !self.broken
    }

    /// Output can no longer be delivered, or a signal asked us to stop.
    pub fn should_stop(&self) -> bool {
        self.broken || crate::proc::interrupted()
    }

    pub fn eprint(&mut self, s: &str) {
        self.flush();
        let _ = self.stderr.write_all(s.as_bytes());
    }

    /// Print `name: msg` on stderr and return 1.
    pub fn fail(&mut self, msg: impl fmt::Display) -> i32 {
        let s = alloc::format!("{}: {}\n", self.name(), msg);
        self.eprint(&s);
        1
    }

    /// Print `name: what: strerror` on stderr and return 1.
    pub fn fail_errno(&mut self, what: &str, e: Errno) -> i32 {
        self.fail(alloc::format!("{what}: {e}"))
    }

    /// Usage error: prints the usage line, returns 2.
    pub fn usage(&mut self, def: &CommandDef, msg: &str) -> i32 {
        if !msg.is_empty() {
            let m = alloc::format!("{}: {}\n", self.name(), msg);
            self.eprint(&m);
        }
        let u = alloc::format!("Usage: {} {}\n", def.name, def.usage);
        self.eprint(&u);
        2
    }

    // ── input ───────────────────────────────────────────────────────────

    pub fn stdin(&self) -> Arc<dyn File> {
        self.stdin.clone()
    }
    pub fn stdout(&self) -> Arc<dyn File> {
        self.stdout.clone()
    }

    pub fn read_stdin(&mut self, buf: &mut [u8]) -> KResult<usize> {
        self.flush();
        self.stdin.read(buf)
    }

    /// Open an input operand (`-` = stdin).
    pub fn open_input(&mut self, path: &str) -> KResult<Arc<dyn File>> {
        if path == "-" {
            return Ok(self.stdin.clone());
        }
        let f = ops::open(&self.fs(), path, flags::O_RDONLY, 0)?;
        if f.stat()?.kind == crate::fs::FileType::Directory {
            return Err(Errno::EISDIR);
        }
        Ok(f)
    }

    /// Read a whole input operand.
    pub fn read_input(&mut self, path: &str) -> KResult<Vec<u8>> {
        self.flush();
        let f = self.open_input(path)?;
        let mut v = Vec::new();
        let mut buf = alloc::vec![0u8; 16384];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            v.extend_from_slice(&buf[..n]);
            if crate::proc::interrupted() {
                return Err(Errno::EINTR);
            }
        }
        Ok(v)
    }

    // ── environment ─────────────────────────────────────────────────────

    pub fn fs(&self) -> ops::Ctx {
        ops::Ctx::of(&self.proc)
    }
    pub fn cwd(&self) -> String {
        self.proc.fs.lock().cwd.path()
    }
    pub fn cred(&self) -> crate::fs::perm::Cred {
        self.proc.cred()
    }
    pub fn env(&self, key: &str) -> Option<String> {
        self.proc.env_var(key)
    }
    pub fn stdout_tty(&self) -> Option<Arc<crate::tty::Tty>> {
        self.stdout.tty()
    }
    pub fn stdin_tty(&self) -> Option<Arc<crate::tty::Tty>> {
        self.stdin.tty()
    }
    /// Terminal size (columns, rows) of stdout, or 80x24.
    pub fn term_size(&self) -> (usize, usize) {
        let ws = self.stdout.tty().or_else(|| self.stdin.tty()).map(|t| t.winsize());
        match ws {
            Some(w) if w.cols > 0 && w.rows > 0 => (w.cols as usize, w.rows as usize),
            _ => {
                let cols = self.env("COLUMNS").and_then(|c| c.parse().ok()).unwrap_or(80);
                (cols, 24)
            }
        }
    }

    /// Sleep; false if interrupted by a signal.
    pub fn sleep_ms(&mut self, ms: u64) -> bool {
        self.flush();
        crate::sched::sleep_ms(ms)
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        self.flush();
    }
}

#[macro_export]
macro_rules! out {
    ($ctx:expr, $($a:tt)*) => { $ctx.fmt(format_args!($($a)*)) };
}
#[macro_export]
macro_rules! outln {
    ($ctx:expr) => { $ctx.print("\n") };
    ($ctx:expr, $($a:tt)*) => {{ $ctx.fmt(format_args!($($a)*)); $ctx.print("\n"); }};
}

// ── option parsing ─────────────────────────────────────────────────────────

/// Description of accepted options: short letters, whether they take a
/// value, and long names mapped onto them.
pub struct OptSpec {
    /// Short options without a value, e.g. "alh".
    pub flags: &'static str,
    /// Short options taking a value, e.g. "nC".
    pub values: &'static str,
    /// (long name, short letter it aliases, takes a value).
    pub long: &'static [(&'static str, char, bool)],
}

#[derive(Default, Debug)]
pub struct Parsed {
    set: BTreeSet<char>,
    counts: BTreeMap<char, usize>,
    vals: BTreeMap<char, Vec<String>>,
    pub operands: Vec<String>,
}

impl Parsed {
    pub fn has(&self, c: char) -> bool {
        self.set.contains(&c)
    }
    /// How many times a flag was given (`-vvv`).
    pub fn count(&self, c: char) -> usize {
        self.counts.get(&c).copied().unwrap_or(0)
    }
    pub fn value(&self, c: char) -> Option<&str> {
        self.vals.get(&c).and_then(|v| v.last()).map(|s| s.as_str())
    }
    pub fn values(&self, c: char) -> &[String] {
        self.vals.get(&c).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// `getopt_long`-style parsing of `args[1..]`. Options and operands may be
/// mixed; `--` ends option parsing; `-` alone is an operand.
pub fn parse_opts(args: &[String], spec: &OptSpec) -> Result<Parsed, String> {
    let mut p = Parsed::default();
    let mut i = 1;
    let mut only_operands = false;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if only_operands || a == "-" || !a.starts_with('-') {
            p.operands.push(a.clone());
            continue;
        }
        if a == "--" {
            only_operands = true;
            continue;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            let Some(&(_, c, takes)) = spec.long.iter().find(|(n, _, _)| *n == name) else {
                return Err(alloc::format!("unrecognized option '--{name}'"));
            };
            p.set.insert(c);
            *p.counts.entry(c).or_insert(0) += 1;
            if takes {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        let v = args.get(i).cloned().ok_or_else(|| alloc::format!("option '--{name}' requires an argument"))?;
                        i += 1;
                        v
                    }
                };
                p.vals.entry(c).or_default().push(v);
            } else if inline.is_some() {
                return Err(alloc::format!("option '--{name}' doesn't allow an argument"));
            }
            continue;
        }
        let chars: Vec<char> = a[1..].chars().collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            j += 1;
            if spec.values.contains(c) {
                let v = if j < chars.len() {
                    let v: String = chars[j..].iter().collect();
                    j = chars.len();
                    v
                } else {
                    let v = args.get(i).cloned().ok_or_else(|| alloc::format!("option requires an argument -- '{c}'"))?;
                    i += 1;
                    v
                };
                p.set.insert(c);
                *p.counts.entry(c).or_insert(0) += 1;
                p.vals.entry(c).or_default().push(v);
            } else if spec.flags.contains(c) {
                p.set.insert(c);
                *p.counts.entry(c).or_insert(0) += 1;
            } else {
                return Err(alloc::format!("invalid option -- '{c}'"));
            }
        }
    }
    Ok(p)
}

/// Human-readable size (`ls -h`, `df -h`, `du -h`): 1K, 234M, 1.5G.
pub fn human(bytes: u64) -> String {
    const U: [&str; 7] = ["", "K", "M", "G", "T", "P", "E"];
    if bytes < 1024 {
        return bytes.to_string();
    }
    let mut u = 0;
    let mut div: u128 = 1;
    while bytes as u128 >= div * 1024 && u < U.len() - 1 {
        div *= 1024;
        u += 1;
    }
    let b = bytes as u128;
    // Rounded up, like coreutils: one decimal below 10, whole numbers above.
    let tenths = (b * 10).div_ceil(div);
    if tenths < 100 {
        return alloc::format!("{}.{}{}", tenths / 10, tenths % 10, U[u]);
    }
    let whole = b.div_ceil(div);
    if whole >= 1024 && u + 1 < U.len() {
        return alloc::format!("1.0{}", U[u + 1]);
    }
    alloc::format!("{}{}", whole, U[u])
}
