//! Small core commands: echo, printf, test, true, false, pwd, uname,
//! clear, sleep, env, printenv.

use super::fmtutil;
use crate::fs::ops;
use crate::fs::FileType;
use crate::shell::ctx::Ctx;
use crate::outln;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub fn true_(_: &mut Ctx) -> i32 {
    0
}

pub fn false_(_: &mut Ctx) -> i32 {
    1
}

pub fn echo(ctx: &mut Ctx) -> i32 {
    let mut newline = true;
    let mut escapes = false;
    let mut i = 1;
    // Only a leading run of valid flag words counts (bash semantics).
    while i < ctx.args.len() {
        let a = &ctx.args[i];
        if a.len() < 2 || !a.starts_with('-') || !a[1..].chars().all(|c| matches!(c, 'n' | 'e' | 'E')) {
            break;
        }
        for c in a[1..].chars() {
            match c {
                'n' => newline = false,
                'e' => escapes = true,
                _ => escapes = false,
            }
        }
        i += 1;
    }
    let text = ctx.args[i..].join(" ");
    if escapes {
        let (s, stop) = fmtutil::unescape(&text);
        ctx.print(&s);
        if stop {
            return 0;
        }
    } else {
        ctx.print(&text);
    }
    if newline {
        ctx.print("\n");
    }
    0
}

pub fn pwd(ctx: &mut Ctx) -> i32 {
    let physical = ctx.args.iter().any(|a| a == "-P");
    let real = ctx.cwd();
    let p = if physical { real } else { ctx.env("PWD").filter(|p| p.starts_with('/')).unwrap_or(real) };
    outln!(ctx, "{p}");
    0
}

pub fn clear(ctx: &mut Ctx) -> i32 {
    ctx.print("\x1b[H\x1b[2J\x1b[3J");
    0
}

pub fn uname(ctx: &mut Ctx) -> i32 {
    let mut want = Vec::new();
    for a in &ctx.args[1..] {
        match a.as_str() {
            "--all" => want.push('a'),
            "--kernel-name" => want.push('s'),
            "--nodename" => want.push('n'),
            "--kernel-release" => want.push('r'),
            "--kernel-version" => want.push('v'),
            "--machine" => want.push('m'),
            "--operating-system" => want.push('o'),
            s if s.starts_with('-') && s.len() > 1 => {
                for c in s[1..].chars() {
                    if !"asnrvmpio".contains(c) {
                        return ctx.fail(alloc::format!("invalid option -- '{c}'"));
                    }
                    want.push(c);
                }
            }
            s => return ctx.fail(alloc::format!("extra operand '{s}'")),
        }
    }
    if want.is_empty() {
        want.push('s');
    }
    let all = want.contains(&'a');
    let host = ctx.proc.uts.hostname.lock().clone();
    let fields: [(char, String); 8] = [
        ('s', String::from("FastROS")),
        ('n', host),
        ('r', String::from(crate::VERSION)),
        ('v', String::from("#1 SMP PREEMPT_DYNAMIC")),
        ('m', String::from("x86_64")),
        ('p', String::from("x86_64")),
        ('i', String::from("x86_64")),
        ('o', String::from("FastROS")),
    ];
    let parts: Vec<&str> = fields
        .iter()
        .filter(|(c, _)| want.contains(c) || (all && !matches!(c, 'p' | 'i')))
        .map(|(_, v)| v.as_str())
        .collect();
    outln!(ctx, "{}", parts.join(" "));
    0
}

/// Parse `1`, `0.5`, `2m`, `1h`, `1d` into milliseconds.
fn duration_ms(s: &str) -> Option<u64> {
    let (num, mult) = match s.chars().last()? {
        's' => (&s[..s.len() - 1], 1000u64),
        'm' => (&s[..s.len() - 1], 60_000),
        'h' => (&s[..s.len() - 1], 3_600_000),
        'd' => (&s[..s.len() - 1], 86_400_000),
        _ => (s, 1000),
    };
    let (int, frac) = num.split_once('.').unwrap_or((num, ""));
    if int.is_empty() && frac.is_empty() {
        return None;
    }
    let i: u64 = if int.is_empty() { 0 } else { int.parse().ok()? };
    let mut f_ms = 0u64;
    let mut scale = mult / 10;
    for c in frac.chars().take(6) {
        f_ms += c.to_digit(10)? as u64 * scale;
        scale /= 10;
    }
    i.checked_mul(mult)?.checked_add(f_ms)
}

pub fn sleep(ctx: &mut Ctx) -> i32 {
    if ctx.args.len() < 2 {
        return ctx.fail("missing operand");
    }
    let mut total = 0u64;
    for a in ctx.args[1..].to_vec() {
        match duration_ms(&a) {
            Some(ms) => total = total.saturating_add(ms),
            None => return ctx.fail(alloc::format!("invalid time interval '{a}'")),
        }
    }
    if ctx.sleep_ms(total) {
        0
    } else {
        130
    }
}

pub fn printenv(ctx: &mut Ctx) -> i32 {
    let env = ctx.proc.env.lock().clone();
    if ctx.args.len() == 1 {
        for (k, v) in &env {
            outln!(ctx, "{k}={v}");
        }
        return 0;
    }
    let mut st = 0;
    for name in ctx.args[1..].to_vec() {
        match env.iter().find(|(k, _)| *k == name) {
            Some((_, v)) => outln!(ctx, "{v}"),
            None => st = 1,
        }
    }
    st
}

pub fn env(ctx: &mut Ctx) -> i32 {
    let mut env: Vec<(String, String)> = ctx.proc.env.lock().clone();
    let mut i = 1;
    while i < ctx.args.len() {
        let a = ctx.args[i].clone();
        if a == "-i" || a == "-" {
            env.clear();
        } else if let Some(name) = a.strip_prefix("-u") {
            let name = if name.is_empty() {
                i += 1;
                ctx.args.get(i).cloned().unwrap_or_default()
            } else {
                name.to_string()
            };
            env.retain(|(k, _)| *k != name);
        } else if let Some((k, v)) = a.split_once('=') {
            env.retain(|(ek, _)| ek != k);
            env.push((k.to_string(), v.to_string()));
        } else {
            break;
        }
        i += 1;
    }
    if i >= ctx.args.len() {
        for (k, v) in &env {
            outln!(ctx, "{k}={v}");
        }
        return 0;
    }
    let argv = ctx.args[i..].to_vec();
    ctx.flush();
    crate::shell::run_argv(&ctx.proc, argv, Some(env), None)
}

// ── printf ─────────────────────────────────────────────────────────────────

pub fn printf(ctx: &mut Ctx) -> i32 {
    if ctx.args.len() < 2 {
        return ctx.fail("usage: printf FORMAT [ARGUMENT]...");
    }
    let fmt: Vec<char> = ctx.args[1].chars().collect();
    let args: Vec<String> = ctx.args[2..].to_vec();
    let mut ai = 0;
    let mut status = 0;
    loop {
        let consumed_before = ai;
        let (out, stop) = format_once(&fmt, &args, &mut ai, &mut status);
        ctx.print(&out);
        if stop || ai >= args.len() || ai == consumed_before {
            break;
        }
    }
    if status != 0 {
        ctx.flush();
    }
    status
}

fn next_arg<'a>(args: &'a [String], ai: &mut usize) -> Option<&'a str> {
    let a = args.get(*ai).map(|s| s.as_str());
    if a.is_some() {
        *ai += 1;
    }
    a
}

fn arg_int(a: Option<&str>, status: &mut i32) -> i64 {
    let Some(s) = a else { return 0 };
    let t = s.trim();
    if let Some(c) = t.strip_prefix('\'').or_else(|| t.strip_prefix('"')) {
        return c.chars().next().map(|c| c as i64).unwrap_or(0);
    }
    let (neg, body) = match t.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let v = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        i64::from_str_radix(h, 16)
    } else if body.len() > 1 && body.starts_with('0') {
        i64::from_str_radix(&body[1..], 8)
    } else {
        body.parse::<i64>()
    };
    match v {
        Ok(v) => {
            if neg {
                -v
            } else {
                v
            }
        }
        Err(_) => {
            *status = 1;
            0
        }
    }
}

fn arg_float(a: Option<&str>, status: &mut i32) -> f64 {
    match a.map(|s| s.trim().parse::<f64>()) {
        None => 0.0,
        Some(Ok(v)) => v,
        Some(Err(_)) => {
            *status = 1;
            0.0
        }
    }
}

/// `%e` formatting (`1.234500e+03`), which core's `{:e}` does not match.
fn fmt_exp(v: f64, prec: usize, upper: bool) -> String {
    if v == 0.0 {
        let s = alloc::format!("{:.*}e+00", prec, 0.0);
        return if upper { s.to_uppercase() } else { s };
    }
    let mut exp = 0i32;
    let mut m = if v < 0.0 { -v } else { v };
    while m >= 10.0 {
        m /= 10.0;
        exp += 1;
    }
    while m < 1.0 {
        m *= 10.0;
        exp -= 1;
    }
    // Rounding may carry into a new digit (9.99 → 10.0).
    let mut mant = alloc::format!("{:.*}", prec, m);
    if mant.starts_with("10") {
        m /= 10.0;
        exp += 1;
        mant = alloc::format!("{:.*}", prec, m);
    }
    let sign = if v < 0.0 { "-" } else { "" };
    let s = alloc::format!("{sign}{mant}e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs());
    if upper {
        s.to_uppercase()
    } else {
        s
    }
}

fn format_once(fmt: &[char], args: &[String], ai: &mut usize, status: &mut i32) -> (String, bool) {
    let mut out = String::new();
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        if c == '\\' {
            let mut j = i + 1;
            let mut esc = String::from("\\");
            if j < fmt.len() {
                esc.push(fmt[j]);
                j += 1;
                // Numeric escapes take following digits.
                if matches!(fmt[i + 1], '0'..='7' | 'x') {
                    let max = if fmt[i + 1] == 'x' { 2 } else { 3 };
                    let mut n = if fmt[i + 1] == 'x' { 0 } else { 1 };
                    while j < fmt.len() && n < max && fmt[j].is_ascii_hexdigit() {
                        esc.push(fmt[j]);
                        j += 1;
                        n += 1;
                    }
                }
            }
            let esc = if esc.len() > 1 && esc.as_bytes()[1].is_ascii_digit() && esc.as_bytes()[1] != b'0' {
                alloc::format!("\\0{}", &esc[1..])
            } else {
                esc
            };
            let (s, stop) = fmtutil::unescape(&esc);
            out.push_str(&s);
            if stop {
                return (out, true);
            }
            i = j;
            continue;
        }
        if c != '%' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        if i < fmt.len() && fmt[i] == '%' {
            out.push('%');
            i += 1;
            continue;
        }
        let mut flags = String::new();
        while i < fmt.len() && "-+ 0#".contains(fmt[i]) {
            flags.push(fmt[i]);
            i += 1;
        }
        let mut width: Option<usize> = None;
        if i < fmt.len() && fmt[i] == '*' {
            width = Some(arg_int(next_arg(args, ai), status).unsigned_abs() as usize);
            i += 1;
        } else {
            let st = i;
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                i += 1;
            }
            if i > st {
                width = fmt[st..i].iter().collect::<String>().parse().ok();
            }
        }
        let mut prec: Option<usize> = None;
        if i < fmt.len() && fmt[i] == '.' {
            i += 1;
            if i < fmt.len() && fmt[i] == '*' {
                prec = Some(arg_int(next_arg(args, ai), status).max(0) as usize);
                i += 1;
            } else {
                let st = i;
                while i < fmt.len() && fmt[i].is_ascii_digit() {
                    i += 1;
                }
                prec = Some(fmt[st..i].iter().collect::<String>().parse().unwrap_or(0));
            }
        }
        // Length modifiers are accepted and ignored.
        while i < fmt.len() && "hlLqjzt".contains(fmt[i]) {
            i += 1;
        }
        let Some(&conv) = fmt.get(i) else {
            out.push('%');
            break;
        };
        i += 1;
        let left = flags.contains('-');
        let zero = flags.contains('0') && !left;
        let plus = flags.contains('+');
        let space = flags.contains(' ');
        let alt = flags.contains('#');
        let body: String = match conv {
            's' => {
                let mut s = next_arg(args, ai).unwrap_or("").to_string();
                if let Some(p) = prec {
                    s = s.chars().take(p).collect();
                }
                s
            }
            'b' => {
                let (s, stop) = fmtutil::unescape(next_arg(args, ai).unwrap_or(""));
                if stop {
                    out.push_str(&s);
                    return (out, true);
                }
                s
            }
            'q' => fastros_sh::quote(next_arg(args, ai).unwrap_or("")),
            'c' => next_arg(args, ai).and_then(|s| s.chars().next()).map(|c| c.to_string()).unwrap_or_default(),
            'd' | 'i' => {
                let v = arg_int(next_arg(args, ai), status);
                let mut s = v.unsigned_abs().to_string();
                if let Some(p) = prec {
                    while s.len() < p {
                        s.insert(0, '0');
                    }
                }
                let sign = if v < 0 {
                    "-"
                } else if plus {
                    "+"
                } else if space {
                    " "
                } else {
                    ""
                };
                if zero && prec.is_none() {
                    if let Some(w) = width {
                        while s.len() + sign.len() < w {
                            s.insert(0, '0');
                        }
                    }
                }
                alloc::format!("{sign}{s}")
            }
            'u' | 'o' | 'x' | 'X' => {
                let v = arg_int(next_arg(args, ai), status) as u64;
                let mut s = match conv {
                    'u' => v.to_string(),
                    'o' => alloc::format!("{v:o}"),
                    'x' => alloc::format!("{v:x}"),
                    _ => alloc::format!("{v:X}"),
                };
                if let Some(p) = prec {
                    while s.len() < p {
                        s.insert(0, '0');
                    }
                }
                let prefix = match (alt, conv) {
                    (true, 'o') if !s.starts_with('0') => "0",
                    (true, 'x') if v != 0 => "0x",
                    (true, 'X') if v != 0 => "0X",
                    _ => "",
                };
                if zero && prec.is_none() {
                    if let Some(w) = width {
                        while s.len() + prefix.len() < w {
                            s.insert(0, '0');
                        }
                    }
                }
                alloc::format!("{prefix}{s}")
            }
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' => {
                let v = arg_float(next_arg(args, ai), status);
                let p = prec.unwrap_or(6);
                let mut s = match conv {
                    'f' | 'F' => alloc::format!("{:.*}", p, v),
                    'e' | 'E' => fmt_exp(v, p, conv == 'E'),
                    _ => {
                        let p = if p == 0 { 1 } else { p };
                        let a = if v < 0.0 { -v } else { v };
                        let e = if a == 0.0 { 0 } else { fmt_exp(a, 0, false).split('e').nth(1).and_then(|x| x.parse::<i32>().ok()).unwrap_or(0) };
                        let mut t = if e < -4 || e >= p as i32 { fmt_exp(v, p - 1, conv == 'G') } else { alloc::format!("{:.*}", (p as i32 - 1 - e).max(0) as usize, v) };
                        if !alt && t.contains('.') {
                            let (m, ex) = match t.find(['e', 'E']) {
                                Some(k) => (t[..k].to_string(), t[k..].to_string()),
                                None => (t.clone(), String::new()),
                            };
                            let m = m.trim_end_matches('0').trim_end_matches('.').to_string();
                            t = m + &ex;
                        }
                        t
                    }
                };
                if v >= 0.0 && plus {
                    s.insert(0, '+');
                } else if v >= 0.0 && space {
                    s.insert(0, ' ');
                }
                if zero {
                    if let Some(w) = width {
                        let neg = s.starts_with('-') || s.starts_with('+');
                        while s.len() < w {
                            s.insert(if neg { 1 } else { 0 }, '0');
                        }
                    }
                }
                s
            }
            other => {
                *status = 1;
                alloc::format!("%{other}")
            }
        };
        let w = width.unwrap_or(0);
        let n = body.chars().count();
        if n < w {
            if left {
                out.push_str(&body);
                out.extend(core::iter::repeat_n(' ', w - n));
            } else {
                out.extend(core::iter::repeat_n(' ', w - n));
                out.push_str(&body);
            }
        } else {
            out.push_str(&body);
        }
    }
    (out, false)
}

// ── test / [ ───────────────────────────────────────────────────────────────

pub fn test(ctx: &mut Ctx) -> i32 {
    let mut args: Vec<String> = ctx.args[1..].to_vec();
    if ctx.args[0] == "[" {
        if args.last().map(|s| s.as_str()) != Some("]") {
            ctx.fail("missing `]'");
            return 2;
        }
        args.pop();
    }
    let mut p = TestParser { a: &args, i: 0, ctx };
    if p.a.is_empty() {
        return 1;
    }
    match p.or_expr() {
        Ok(v) if p.i == p.a.len() => (!v) as i32,
        Ok(_) => {
            let extra = p.a[p.i].clone();
            p.ctx.fail(alloc::format!("{extra}: unexpected argument"));
            2
        }
        Err(m) => {
            p.ctx.fail(m);
            2
        }
    }
}

struct TestParser<'a> {
    a: &'a [String],
    i: usize,
    ctx: &'a mut Ctx,
}

impl TestParser<'_> {
    fn peek(&self) -> Option<&str> {
        self.a.get(self.i).map(|s| s.as_str())
    }
    fn or_expr(&mut self) -> Result<bool, String> {
        let mut v = self.and_expr()?;
        while self.peek() == Some("-o") {
            self.i += 1;
            let r = self.and_expr()?;
            v = v || r;
        }
        Ok(v)
    }
    fn and_expr(&mut self) -> Result<bool, String> {
        let mut v = self.not_expr()?;
        while self.peek() == Some("-a") {
            self.i += 1;
            let r = self.not_expr()?;
            v = v && r;
        }
        Ok(v)
    }
    fn not_expr(&mut self) -> Result<bool, String> {
        if self.peek() == Some("!") && self.a.len() - self.i > 1 {
            self.i += 1;
            return Ok(!self.not_expr()?);
        }
        self.primary()
    }
    fn primary(&mut self) -> Result<bool, String> {
        let Some(tok) = self.peek().map(|s| s.to_string()) else { return Err("argument expected".into()) };
        if tok == "(" && self.a.len() - self.i >= 3 {
            self.i += 1;
            let v = self.or_expr()?;
            if self.peek() != Some(")") {
                return Err("')' expected".into());
            }
            self.i += 1;
            return Ok(v);
        }
        // Binary operators (look ahead one).
        if let Some(op) = self.a.get(self.i + 1).map(|s| s.as_str()) {
            if self.a.len() - self.i >= 3 || matches!(op, "=" | "!=") && self.a.len() - self.i >= 3 {
                if let Some(v) = self.binary(&tok, op, self.a.get(self.i + 2).map(|s| s.as_str()))? {
                    self.i += 3;
                    return Ok(v);
                }
            }
        }
        // Unary operators.
        if tok.len() == 2 && tok.starts_with('-') && self.a.len() - self.i >= 2 {
            let arg = self.a[self.i + 1].clone();
            if let Some(v) = self.unary(&tok, &arg)? {
                self.i += 2;
                return Ok(v);
            }
        }
        self.i += 1;
        Ok(!tok.is_empty())
    }
    fn unary(&mut self, op: &str, arg: &str) -> Result<Option<bool>, String> {
        let fsctx = self.ctx.fs();
        let st = |follow: bool| ops::stat(&fsctx, arg, follow).ok();
        let access = |mask: u32| ops::access(&fsctx, arg, mask).is_ok();
        Ok(Some(match op {
            "-z" => arg.is_empty(),
            "-n" => !arg.is_empty(),
            "-e" => st(true).is_some(),
            "-f" => st(true).is_some_and(|m| m.kind == FileType::Regular),
            "-d" => st(true).is_some_and(|m| m.kind == FileType::Directory),
            "-L" | "-h" => st(false).is_some_and(|m| m.kind == FileType::Symlink),
            "-p" => st(true).is_some_and(|m| m.kind == FileType::Fifo),
            "-S" => st(true).is_some_and(|m| m.kind == FileType::Socket),
            "-b" => st(true).is_some_and(|m| m.kind == FileType::BlockDevice),
            "-c" => st(true).is_some_and(|m| m.kind == FileType::CharDevice),
            "-s" => st(true).is_some_and(|m| m.size > 0),
            "-u" => st(true).is_some_and(|m| m.perm & 0o4000 != 0),
            "-g" => st(true).is_some_and(|m| m.perm & 0o2000 != 0),
            "-k" => st(true).is_some_and(|m| m.perm & 0o1000 != 0),
            "-r" => access(crate::fs::perm::MAY_READ),
            "-w" => access(crate::fs::perm::MAY_WRITE),
            "-x" => access(crate::fs::perm::MAY_EXEC),
            "-O" => st(true).is_some_and(|m| m.uid == self.ctx.cred().euid),
            "-G" => st(true).is_some_and(|m| m.gid == self.ctx.cred().egid),
            "-t" => {
                let fd: i32 = arg.parse().map_err(|_| alloc::format!("{arg}: integer expression expected"))?;
                self.ctx.proc.fds.lock().get(fd).is_ok_and(|f| f.tty().is_some())
            }
            _ => return Ok(None),
        }))
    }
    fn binary(&mut self, l: &str, op: &str, r: Option<&str>) -> Result<Option<bool>, String> {
        let Some(r) = r else { return Ok(None) };
        let int = |s: &str| s.trim().parse::<i64>().map_err(|_| alloc::format!("{s}: integer expression expected"));
        let fsctx = self.ctx.fs();
        let mtime = |p: &str| ops::stat(&fsctx, p, true).ok().map(|m| m.mtime);
        Ok(Some(match op {
            "=" | "==" => l == r,
            "!=" => l != r,
            "<" => l < r,
            ">" => l > r,
            "-eq" => int(l)? == int(r)?,
            "-ne" => int(l)? != int(r)?,
            "-lt" => int(l)? < int(r)?,
            "-le" => int(l)? <= int(r)?,
            "-gt" => int(l)? > int(r)?,
            "-ge" => int(l)? >= int(r)?,
            "-nt" => matches!((mtime(l), mtime(r)), (Some(a), Some(b)) if a > b) || (mtime(l).is_some() && mtime(r).is_none()),
            "-ot" => matches!((mtime(l), mtime(r)), (Some(a), Some(b)) if a < b) || (mtime(l).is_none() && mtime(r).is_some()),
            "-ef" => {
                let a = ops::stat(&fsctx, l, true).ok();
                let b = ops::stat(&fsctx, r, true).ok();
                matches!((a, b), (Some(a), Some(b)) if a.dev == b.dev && a.ino == b.ino)
            }
            _ => return Ok(None),
        }))
    }
}
