//! Line-oriented text tools: head, tail, wc, sort, uniq, cut, tr, tee,
//! seq, yes, rev, tac, nl, base64, sha256sum, hexdump.

use super::text::for_each_input;
use crate::errno::Errno;
use crate::fs::ops;
use crate::fs::FileType;
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use crate::{out, outln};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

fn q(s: &str) -> String {
    alloc::format!("'{s}'")
}

/// Read every input operand fully (stdin when none) as (name, bytes).
fn read_inputs(ctx: &mut Ctx, files: &[String]) -> (Vec<(String, Vec<u8>)>, bool) {
    let list: Vec<String> = if files.is_empty() { alloc::vec![String::from("-")] } else { files.to_vec() };
    let mut out = Vec::new();
    let mut ok = true;
    for f in list {
        match ctx.read_input(&f) {
            Ok(d) => out.push((f, d)),
            Err(Errno::EINTR) => return (out, false),
            Err(e) => {
                let n = ctx.name().to_string();
                ctx.eprint(&alloc::format!("{n}: {f}: {e}\n"));
                ok = false;
            }
        }
    }
    (out, ok)
}

/// Split into lines keeping track of whether the last one had a newline.
fn lines(data: &[u8]) -> Vec<&[u8]> {
    let mut v: Vec<&[u8]> = data.split(|&b| b == b'\n').collect();
    if data.ends_with(b"\n") || data.is_empty() {
        v.pop();
    }
    v
}

/// `-n 5`, `-n -5`, `-n +5`, `-5`: (count, sign) with sign '+', '-' or ' '.
fn parse_count(s: &str) -> Option<(u64, char)> {
    let (sign, num) = match s.chars().next()? {
        '+' => ('+', &s[1..]),
        '-' => ('-', &s[1..]),
        _ => (' ', s),
    };
    let n = super::fmtutil::parse_size(num)?;
    Some((n, sign))
}

/// Rewrite the historical `head -5` / `tail -5` form to `-n 5`.
fn legacy_count(args: &[String]) -> Vec<String> {
    args.iter()
        .enumerate()
        .flat_map(|(i, a)| {
            if i > 0 && a.len() > 1 && a.starts_with('-') && a[1..].bytes().all(|b| b.is_ascii_digit()) {
                alloc::vec![String::from("-n"), a[1..].to_string()]
            } else {
                alloc::vec![a.clone()]
            }
        })
        .collect()
}

// ── head ───────────────────────────────────────────────────────────────────

pub fn head(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "qv", values: "nc", long: &[("lines", 'n', true), ("bytes", 'c', true), ("quiet", 'q', false), ("silent", 'q', false), ("verbose", 'v', false)] };
    let args = legacy_count(&ctx.args);
    let p = match parse_opts(&args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let (count, sign, bytes) = if let Some(c) = p.value('c') {
        match parse_count(c) {
            Some((n, s)) => (n, s, true),
            None => return ctx.fail(alloc::format!("invalid number of bytes: {}", q(c))),
        }
    } else {
        match parse_count(p.value('n').unwrap_or("10")) {
            Some((n, s)) => (n, s, false),
            None => return ctx.fail(alloc::format!("invalid number of lines: {}", q(p.value('n').unwrap_or("")))),
        }
    };
    let files: Vec<String> = if p.operands.is_empty() { alloc::vec![String::from("-")] } else { p.operands.clone() };
    let headers = (files.len() > 1 && !p.has('q')) || p.has('v');
    let mut st = 0;
    for (i, f) in files.iter().enumerate() {
        let data = match ctx.read_input(f) {
            Ok(d) => d,
            Err(Errno::EINTR) => return 130,
            Err(e) => {
                ctx.eprint(&alloc::format!("head: cannot open {} for reading: {}\n", q(f), e));
                st = 1;
                continue;
            }
        };
        if headers {
            if i > 0 {
                ctx.print("\n");
            }
            outln!(ctx, "==> {} <==", if f == "-" { "standard input" } else { f });
        }
        if bytes {
            let n = if sign == '-' { data.len().saturating_sub(count as usize) } else { (count as usize).min(data.len()) };
            ctx.write(&data[..n]);
        } else {
            let mut end = 0;
            let mut seen = 0u64;
            let total_lines = data.iter().filter(|&&b| b == b'\n').count() as u64 + (!data.is_empty() && !data.ends_with(b"\n")) as u64;
            let want = if sign == '-' { total_lines.saturating_sub(count) } else { count };
            while seen < want && end < data.len() {
                match data[end..].iter().position(|&b| b == b'\n') {
                    Some(p) => end += p + 1,
                    None => end = data.len(),
                }
                seen += 1;
            }
            ctx.write(&data[..end]);
        }
    }
    st
}

// ── tail ───────────────────────────────────────────────────────────────────

pub fn tail(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "fFqv",
        values: "ncs",
        long: &[("lines", 'n', true), ("bytes", 'c', true), ("follow", 'f', false), ("quiet", 'q', false), ("verbose", 'v', false), ("sleep-interval", 's', true)],
    };
    let args = legacy_count(&ctx.args);
    let p = match parse_opts(&args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let (count, sign, bytes) = if let Some(c) = p.value('c') {
        match parse_count(c) {
            Some((n, s)) => (n, s, true),
            None => return ctx.fail(alloc::format!("invalid number of bytes: {}", q(c))),
        }
    } else {
        match parse_count(p.value('n').unwrap_or("10")) {
            Some((n, s)) => (n, s, false),
            None => return ctx.fail(alloc::format!("invalid number of lines: {}", q(p.value('n').unwrap_or("")))),
        }
    };
    let follow = p.has('f') || p.has('F');
    let files: Vec<String> = if p.operands.is_empty() { alloc::vec![String::from("-")] } else { p.operands.clone() };
    let headers = (files.len() > 1 && !p.has('q')) || p.has('v');
    let mut st = 0;
    let mut offsets: Vec<(String, u64)> = Vec::new();
    for (i, f) in files.iter().enumerate() {
        let data = match ctx.read_input(f) {
            Ok(d) => d,
            Err(Errno::EINTR) => return 130,
            Err(e) => {
                ctx.eprint(&alloc::format!("tail: cannot open {} for reading: {}\n", q(f), e));
                st = 1;
                continue;
            }
        };
        if headers {
            if i > 0 {
                ctx.print("\n");
            }
            outln!(ctx, "==> {} <==", if f == "-" { "standard input" } else { f });
        }
        let start = if bytes {
            if sign == '+' {
                (count.saturating_sub(1) as usize).min(data.len())
            } else {
                data.len().saturating_sub(count as usize)
            }
        } else if sign == '+' {
            let mut pos = 0;
            let mut line = 1;
            while line < count && pos < data.len() {
                match data[pos..].iter().position(|&b| b == b'\n') {
                    Some(k) => pos += k + 1,
                    None => pos = data.len(),
                }
                line += 1;
            }
            pos
        } else {
            let mut pos = data.len();
            // A final newline does not start another line.
            if pos > 0 && data[pos - 1] == b'\n' {
                pos -= 1;
            }
            let mut found = 0;
            while pos > 0 {
                if data[pos - 1] == b'\n' {
                    found += 1;
                    if found == count {
                        break;
                    }
                }
                pos -= 1;
            }
            if count == 0 {
                data.len()
            } else {
                pos
            }
        };
        ctx.write(&data[start..]);
        if f != "-" {
            offsets.push((f.clone(), data.len() as u64));
        }
    }
    if follow && !offsets.is_empty() {
        let fs = ctx.fs();
        let interval = p.value('s').and_then(|s| s.parse::<u64>().ok()).unwrap_or(1).max(1) * 1000;
        let mut last_shown = offsets.last().map(|o| o.0.clone()).unwrap_or_default();
        loop {
            ctx.flush();
            if !ctx.sleep_ms(interval.min(500)) || ctx.should_stop() {
                return 130;
            }
            for (f, off) in offsets.iter_mut() {
                let size = match ops::stat(&fs, f, true) {
                    Ok(m) => m.size,
                    Err(_) => continue,
                };
                if size < *off {
                    ctx.eprint(&alloc::format!("tail: {}: file truncated\n", f));
                    *off = 0;
                }
                if size > *off {
                    if let Ok(file) = ops::open(&fs, f, crate::fs::file::flags::O_RDONLY, 0) {
                        let mut buf = alloc::vec![0u8; (size - *off).min(1 << 20) as usize];
                        if let Ok(n) = file.pread(*off, &mut buf) {
                            if headers && *f != last_shown {
                                outln!(ctx, "\n==> {} <==", f);
                                last_shown = f.clone();
                            }
                            ctx.write(&buf[..n]);
                            *off += n as u64;
                        }
                    }
                }
            }
        }
    }
    st
}

// ── wc ─────────────────────────────────────────────────────────────────────

pub fn wc(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "lwcmL", values: "", long: &[("lines", 'l', false), ("words", 'w', false), ("bytes", 'c', false), ("chars", 'm', false), ("max-line-length", 'L', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let (mut l, mut w, mut c, m, big) = (p.has('l'), p.has('w'), p.has('c'), p.has('m'), p.has('L'));
    if !(l || w || c || m || big) {
        l = true;
        w = true;
        c = true;
    }
    let files: Vec<String> = if p.operands.is_empty() { alloc::vec![String::from("-")] } else { p.operands.clone() };
    let fs = ctx.fs();
    // Column width as GNU wc computes it (see compute_number_width).
    let fields = [l, w, m, c, big].iter().filter(|&&x| x).count();
    let width = if fields == 1 && files.len() == 1 {
        1
    } else {
        let mut min = 1;
        let mut total = 0u64;
        for f in &files {
            match ops::stat(&fs, f, true) {
                Ok(md) if f != "-" && md.kind == FileType::Regular => total += md.size,
                Ok(_) | Err(_) if f == "-" => min = 7,
                Ok(_) => min = 7,
                Err(_) => {}
            }
        }
        let mut wdt = 1;
        while total >= 10 {
            total /= 10;
            wdt += 1;
        }
        wdt.max(min)
    };
    let mut totals = [0u64; 5];
    let mut st = 0;
    let mut rows: Vec<([u64; 5], Option<String>)> = Vec::new();
    for f in &files {
        let data = match ctx.read_input(f) {
            Ok(d) => d,
            Err(Errno::EINTR) => return 130,
            Err(e) => {
                ctx.eprint(&alloc::format!("wc: {}: {}\n", f, e));
                st = 1;
                continue;
            }
        };
        let lines = data.iter().filter(|&&b| b == b'\n').count() as u64;
        let text = String::from_utf8_lossy(&data);
        let words = text.split_ascii_whitespace().count() as u64;
        let chars = text.chars().count() as u64;
        let maxlen = text.lines().map(|ln| ln.chars().map(|ch| if ch == '\t' { 8 } else { 1 }).sum::<u64>()).max().unwrap_or(0);
        let counts = [lines, words, chars, data.len() as u64, maxlen];
        for i in 0..4 {
            totals[i] += counts[i];
        }
        totals[4] = totals[4].max(maxlen);
        rows.push((counts, (f != "-").then(|| f.clone())));
    }
    if files.len() > 1 {
        rows.push((totals, Some(String::from("total"))));
    }
    for (counts, name) in rows {
        let mut parts = Vec::new();
        for (i, on) in [l, w, m, c, big].iter().enumerate() {
            if *on {
                parts.push(alloc::format!("{:>width$}", counts[i], width = width));
            }
        }
        let mut line = parts.join(" ");
        if let Some(n) = name {
            line.push(' ');
            line.push_str(&n);
        }
        outln!(ctx, "{}", line);
    }
    st
}

// ── sort ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct KeySpec {
    f1: usize,
    c1: usize,
    f2: Option<usize>,
    c2: usize,
    numeric: bool,
    reverse: bool,
    fold: bool,
    blanks: bool,
    human: bool,
    version: bool,
    general: bool,
}

fn parse_key(s: &str, global: &KeySpec) -> Option<KeySpec> {
    let mut k = KeySpec { f2: None, ..*global };
    let (start, end) = match s.split_once(',') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    let split_opts = |part: &str| -> (String, String) {
        let pos: String = part.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        let opts: String = part[pos.len()..].to_string();
        (pos, opts)
    };
    let (sp, so) = split_opts(start);
    let (f, c) = sp.split_once('.').unwrap_or((&sp, "1"));
    k.f1 = f.parse().ok().filter(|&x: &usize| x >= 1)?;
    k.c1 = c.parse().unwrap_or(1).max(1);
    let mut opts = so;
    if let Some(e) = end {
        let (ep, eo) = split_opts(e);
        let (f, c) = ep.split_once('.').unwrap_or((&ep, "0"));
        k.f2 = Some(f.parse().ok()?);
        k.c2 = c.parse().unwrap_or(0);
        opts.push_str(&eo);
    }
    for ch in opts.chars() {
        match ch {
            'n' => k.numeric = true,
            'r' => k.reverse = true,
            'f' => k.fold = true,
            'b' => k.blanks = true,
            'h' => k.human = true,
            'V' => k.version = true,
            'g' => k.general = true,
            _ => return None,
        }
    }
    Some(k)
}

/// Fields of a line: with a separator, split on it; otherwise each field is
/// a run of blanks followed by non-blanks (POSIX).
fn fields_of(line: &str, sep: Option<char>) -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    match sep {
        Some(s) => {
            let mut start = 0;
            for (i, ch) in line.char_indices() {
                if ch == s {
                    v.push((start, i));
                    start = i + ch.len_utf8();
                }
            }
            v.push((start, line.len()));
        }
        None => {
            let b = line.as_bytes();
            let mut i = 0;
            while i < b.len() {
                let start = i;
                while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
                    i += 1;
                }
                while i < b.len() && b[i] != b' ' && b[i] != b'\t' {
                    i += 1;
                }
                v.push((start, i));
            }
        }
    }
    v
}

fn key_text<'a>(line: &'a str, k: &KeySpec, sep: Option<char>) -> &'a str {
    let f = fields_of(line, sep);
    if k.f1 == 0 || k.f1 > f.len() {
        return "";
    }
    let (s0, e0) = f[k.f1 - 1];
    let mut start = s0;
    let field = &line[s0..e0];
    let skip_blank = if k.blanks || sep.is_none() { field.len() - field.trim_start().len() } else { 0 };
    start += skip_blank + (k.c1 - 1).min(field.len().saturating_sub(skip_blank));
    let end = match k.f2 {
        None => line.len(),
        Some(f2) if f2 == 0 || f2 > f.len() => line.len(),
        Some(f2) => {
            let (s2, e2) = f[f2 - 1];
            if k.c2 == 0 {
                e2
            } else {
                (s2 + k.c2).min(e2)
            }
        }
    };
    if start >= end || start > line.len() {
        ""
    } else {
        &line[start..end.min(line.len())]
    }
}

fn num_prefix(s: &str) -> f64 {
    let t = s.trim_start();
    let mut end = 0;
    for (i, ch) in t.char_indices() {
        if ch.is_ascii_digit() || ch == '.' || (i == 0 && (ch == '-' || ch == '+')) {
            end = i + 1;
        } else {
            break;
        }
    }
    t[..end].parse::<f64>().unwrap_or(0.0)
}

fn human_value(s: &str) -> f64 {
    let t = s.trim();
    let v = num_prefix(t);
    let suffix = t.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-' || c == '+').chars().next();
    let mult = match suffix {
        Some('K' | 'k') => 1e3,
        Some('M') => 1e6,
        Some('G') => 1e9,
        Some('T') => 1e12,
        Some('P') => 1e15,
        _ => 1.0,
    };
    v * mult
}

/// Natural ("version") comparison: digit runs compare numerically.
fn version_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < ab.len() && j < bb.len() {
        if ab[i].is_ascii_digit() && bb[j].is_ascii_digit() {
            let si = i;
            while i < ab.len() && ab[i].is_ascii_digit() {
                i += 1;
            }
            let sj = j;
            while j < bb.len() && bb[j].is_ascii_digit() {
                j += 1;
            }
            let na = a[si..i].trim_start_matches('0');
            let nb = b[sj..j].trim_start_matches('0');
            let o = na.len().cmp(&nb.len()).then(na.cmp(nb));
            if o != core::cmp::Ordering::Equal {
                return o;
            }
        } else {
            let o = ab[i].cmp(&bb[j]);
            if o != core::cmp::Ordering::Equal {
                return o;
            }
            i += 1;
            j += 1;
        }
    }
    (ab.len() - i).cmp(&(bb.len() - j))
}

fn compare(a: &str, b: &str, k: &KeySpec) -> core::cmp::Ordering {
    let (a2, b2) = if k.blanks { (a.trim_start(), b.trim_start()) } else { (a, b) };
    let o = if k.numeric || k.general {
        num_prefix(a2).partial_cmp(&num_prefix(b2)).unwrap_or(core::cmp::Ordering::Equal)
    } else if k.human {
        human_value(a2).partial_cmp(&human_value(b2)).unwrap_or(core::cmp::Ordering::Equal)
    } else if k.version {
        version_cmp(a2, b2)
    } else if k.fold {
        a2.to_uppercase().cmp(&b2.to_uppercase())
    } else {
        a2.cmp(b2)
    };
    if k.reverse {
        o.reverse()
    } else {
        o
    }
}

pub fn sort(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "nrufbhVgscCmz",
        values: "ktoS",
        long: &[
            ("numeric-sort", 'n', false),
            ("reverse", 'r', false),
            ("unique", 'u', false),
            ("ignore-case", 'f', false),
            ("ignore-leading-blanks", 'b', false),
            ("human-numeric-sort", 'h', false),
            ("version-sort", 'V', false),
            ("general-numeric-sort", 'g', false),
            ("stable", 's', false),
            ("check", 'c', false),
            ("key", 'k', true),
            ("field-separator", 't', true),
            ("output", 'o', true),
            ("zero-terminated", 'z', false),
        ],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let global = KeySpec {
        f1: 1,
        c1: 1,
        f2: None,
        c2: 0,
        numeric: p.has('n'),
        reverse: p.has('r'),
        fold: p.has('f'),
        blanks: p.has('b'),
        human: p.has('h'),
        version: p.has('V'),
        general: p.has('g'),
    };
    let sep = match p.value('t') {
        Some(t) if t.chars().count() == 1 => t.chars().next(),
        Some(t) if t == "\\t" => Some('\t'),
        Some(t) => return ctx.fail(alloc::format!("multi-character tab {}", q(t))),
        None => None,
    };
    let mut keys = Vec::new();
    for k in p.values('k') {
        match parse_key(k, &global) {
            Some(ks) => keys.push(ks),
            None => return ctx.fail(alloc::format!("invalid key specification {}", q(k))),
        }
    }
    let (inputs, ok) = read_inputs(ctx, &p.operands);
    if !ok && inputs.is_empty() {
        return 2;
    }
    let term = if p.has('z') { b'\0' } else { b'\n' };
    let mut all: Vec<String> = Vec::new();
    for (_, d) in &inputs {
        let mut parts: Vec<&[u8]> = d.split(|&b| b == term).collect();
        if d.ends_with(&[term]) || d.is_empty() {
            parts.pop();
        }
        all.extend(parts.into_iter().map(|l| String::from_utf8_lossy(l).into_owned()));
    }
    let cmp = |a: &String, b: &String| -> core::cmp::Ordering {
        for k in &keys {
            let o = compare(key_text(a, k, sep), key_text(b, k, sep), k);
            if o != core::cmp::Ordering::Equal {
                return o;
            }
        }
        if keys.is_empty() {
            let o = compare(a, b, &global);
            if o != core::cmp::Ordering::Equal || p.has('s') {
                return o;
            }
        } else if p.has('s') {
            return core::cmp::Ordering::Equal;
        }
        // Last-resort byte comparison (unless -s), reversed with -r like GNU.
        let o = a.cmp(b);
        if global.reverse {
            o.reverse()
        } else {
            o
        }
    };
    if p.has('c') {
        for w in all.windows(2) {
            if cmp(&w[0], &w[1]) == core::cmp::Ordering::Greater {
                let name = inputs.first().map(|i| i.0.clone()).unwrap_or_default();
                ctx.eprint(&alloc::format!("sort: {}:{}: disorder: {}\n", if name == "-" { "-" } else { &name }, 0, w[1]));
                return 1;
            }
        }
        return 0;
    }
    all.sort_by(cmp);
    if p.has('u') {
        all.dedup_by(|b, a| {
            if keys.is_empty() {
                compare(a, b, &KeySpec { reverse: false, ..global }) == core::cmp::Ordering::Equal
            } else {
                keys.iter().all(|k| compare(key_text(a, k, sep), key_text(b, k, sep), k) == core::cmp::Ordering::Equal)
            }
        });
    }
    let mut outbuf = Vec::new();
    for l in &all {
        outbuf.extend_from_slice(l.as_bytes());
        outbuf.push(term);
    }
    if let Some(o) = p.value('o') {
        let fs = ctx.fs();
        if let Err(e) = ops::write_file(&fs, o, &outbuf, 0o666) {
            return ctx.fail(alloc::format!("open failed: {}: {}", o, e));
        }
    } else {
        ctx.write(&outbuf);
    }
    if ok {
        0
    } else {
        2
    }
}

// ── uniq ───────────────────────────────────────────────────────────────────

pub fn uniq(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "cduiz",
        values: "fsw",
        long: &[("count", 'c', false), ("repeated", 'd', false), ("unique", 'u', false), ("ignore-case", 'i', false), ("skip-fields", 'f', true), ("skip-chars", 's', true), ("check-chars", 'w', true)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let input = p.operands.first().cloned().unwrap_or_else(|| String::from("-"));
    let data = match ctx.read_input(&input) {
        Ok(d) => d,
        Err(e) => return ctx.fail(alloc::format!("{input}: {e}")),
    };
    let skip_f: usize = p.value('f').and_then(|s| s.parse().ok()).unwrap_or(0);
    let skip_c: usize = p.value('s').and_then(|s| s.parse().ok()).unwrap_or(0);
    let check: Option<usize> = p.value('w').and_then(|s| s.parse().ok());
    let key = |l: &str| -> String {
        let mut rest = l;
        for _ in 0..skip_f {
            rest = rest.trim_start_matches([' ', '\t']);
            rest = rest.trim_start_matches(|c| c != ' ' && c != '\t');
        }
        let mut k: String = rest.chars().skip(skip_c).collect();
        if let Some(w) = check {
            k = k.chars().take(w).collect();
        }
        if p.has('i') {
            k = k.to_lowercase();
        }
        k
    };
    let text = String::from_utf8_lossy(&data).into_owned();
    let ls: Vec<&str> = lines(text.as_bytes()).into_iter().map(|l| core::str::from_utf8(l).unwrap_or("")).collect();
    let mut groups: Vec<(&str, usize)> = Vec::new();
    for l in ls {
        match groups.last_mut() {
            Some((first, n)) if key(first) == key(l) => *n += 1,
            _ => groups.push((l, 1)),
        }
    }
    let mut out = String::new();
    for (l, n) in groups {
        if (p.has('d') && n < 2) || (p.has('u') && n > 1) {
            continue;
        }
        if p.has('c') {
            out.push_str(&alloc::format!("{:>7} {}\n", n, l));
        } else {
            out.push_str(l);
            out.push('\n');
        }
    }
    if let Some(o) = p.operands.get(1) {
        let fs = ctx.fs();
        if let Err(e) = ops::write_file(&fs, o, out.as_bytes(), 0o666) {
            return ctx.fail(alloc::format!("{o}: {e}"));
        }
    } else {
        ctx.print(&out);
    }
    0
}

// ── cut ────────────────────────────────────────────────────────────────────

/// `1,3-5,7-` → sorted inclusive ranges (1-based; 0 = open end).
fn parse_list(s: &str) -> Option<Vec<(usize, usize)>> {
    let mut v = Vec::new();
    for part in s.split(',') {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (if a.is_empty() { 1 } else { a.parse().ok()? }, if b.is_empty() { usize::MAX } else { b.parse().ok()? }),
            None => {
                let n: usize = part.parse().ok()?;
                (n, n)
            }
        };
        if a == 0 || a > b {
            return None;
        }
        v.push((a, b));
    }
    Some(v)
}

pub fn cut(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "snz",
        values: "bcfdO",
        long: &[("bytes", 'b', true), ("characters", 'c', true), ("fields", 'f', true), ("delimiter", 'd', true), ("only-delimited", 's', false), ("complement", 'C', false), ("output-delimiter", 'O', true)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let (mode, list) = match (p.value('b'), p.value('c'), p.value('f')) {
        (Some(l), None, None) => ('b', l),
        (None, Some(l), None) => ('c', l),
        (None, None, Some(l)) => ('f', l),
        (None, None, None) => return ctx.fail("you must specify a list of bytes, characters, or fields"),
        _ => return ctx.fail("only one type of list may be specified"),
    };
    let Some(ranges) = parse_list(list) else { return ctx.fail(alloc::format!("invalid field range: {}", q(list))) };
    let delim = p.value('d').map(|d| d.chars().next().unwrap_or('\t')).unwrap_or('\t');
    if p.value('d').is_some_and(|d| d.chars().count() != 1) {
        return ctx.fail("the delimiter must be a single character");
    }
    let complement = p.has('C');
    let selected = |i: usize| ranges.iter().any(|&(a, b)| i >= a && i <= b) != complement;
    let out_delim = p.value('O').map(|s| s.to_string()).unwrap_or_else(|| delim.to_string());
    let (inputs, ok) = read_inputs(ctx, &p.operands);
    for (_, data) in inputs {
        let text = String::from_utf8_lossy(&data).into_owned();
        for line in lines(text.as_bytes()) {
            let line = core::str::from_utf8(line).unwrap_or("");
            let out: String = match mode {
                'b' => {
                    let b = line.as_bytes();
                    let v: Vec<u8> = b.iter().enumerate().filter(|(i, _)| selected(i + 1)).map(|(_, &c)| c).collect();
                    String::from_utf8_lossy(&v).into_owned()
                }
                'c' => line.chars().enumerate().filter(|(i, _)| selected(i + 1)).map(|(_, c)| c).collect(),
                _ => {
                    if !line.contains(delim) {
                        if p.has('s') {
                            continue;
                        }
                        line.to_string()
                    } else {
                        let parts: Vec<&str> = line.split(delim).collect();
                        let chosen: Vec<&str> = parts.iter().enumerate().filter(|(i, _)| selected(i + 1)).map(|(_, s)| *s).collect();
                        chosen.join(&out_delim)
                    }
                }
            };
            outln!(ctx, "{}", out);
        }
    }
    if ok {
        0
    } else {
        1
    }
}

// ── tr ─────────────────────────────────────────────────────────────────────

fn expand_set(s: &str) -> Option<Vec<char>> {
    let chars: Vec<char> = {
        // Escapes first.
        let (u, _) = super::fmtutil::unescape(s);
        u.chars().collect()
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '[' && chars.get(i + 1) == Some(&':') {
            let end = (i + 2..chars.len()).find(|&j| chars[j] == ':' && chars.get(j + 1) == Some(&']'))?;
            let class: String = chars[i + 2..end].iter().collect();
            let pred: fn(char) -> bool = match class.as_str() {
                "alpha" => |c| c.is_ascii_alphabetic(),
                "digit" => |c| c.is_ascii_digit(),
                "alnum" => |c| c.is_ascii_alphanumeric(),
                "upper" => |c| c.is_ascii_uppercase(),
                "lower" => |c| c.is_ascii_lowercase(),
                "space" => |c| c.is_ascii_whitespace() || c == '\x0b',
                "blank" => |c| c == ' ' || c == '\t',
                "punct" => |c| c.is_ascii_punctuation(),
                "xdigit" => |c| c.is_ascii_hexdigit(),
                "cntrl" => |c| c.is_ascii_control(),
                "print" => |c| (' '..='~').contains(&c),
                "graph" => |c| ('!'..='~').contains(&c),
                _ => return None,
            };
            out.extend((0u8..128).map(|b| b as char).filter(|&c| pred(c)));
            i = end + 2;
            continue;
        }
        if i + 2 < chars.len() && chars[i + 1] == '-' {
            let (a, b) = (chars[i], chars[i + 2]);
            if a > b {
                return None;
            }
            out.extend((a as u32..=b as u32).filter_map(char::from_u32));
            i += 3;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    Some(out)
}

pub fn tr(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "dscCt", values: "", long: &[("delete", 'd', false), ("squeeze-repeats", 's', false), ("complement", 'c', false), ("truncate-set1", 't', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let Some(s1) = p.operands.first().and_then(|s| expand_set(s)) else { return ctx.fail("missing operand") };
    let s2 = p.operands.get(1).and_then(|s| expand_set(s));
    let complement = p.has('c') || p.has('C');
    let in1 = |c: char| s1.contains(&c) != complement;
    let delete = p.has('d');
    let squeeze = p.has('s');
    if !delete && !squeeze && s2.is_none() {
        return ctx.fail(alloc::format!("missing operand after {}", q(&p.operands[0])));
    }
    let map = |c: char| -> char {
        match &s2 {
            Some(t) if !t.is_empty() && !delete => {
                if complement {
                    return *t.last().unwrap_or(&c);
                }
                match s1.iter().rposition(|&x| x == c) {
                    Some(i) => *t.get(i).or(t.last()).unwrap_or(&c),
                    None => c,
                }
            }
            _ => c,
        }
    };
    let squeeze_set: Vec<char> = if delete { s2.clone().unwrap_or_default() } else { s2.clone().unwrap_or_else(|| s1.clone()) };
    let mut last: Option<char> = None;
    let st = for_each_input(ctx, &[], &mut |ctx, data| {
        let text = String::from_utf8_lossy(data);
        let mut out = String::with_capacity(text.len());
        for c in text.chars() {
            if delete && in1(c) {
                continue;
            }
            let m = if delete || s2.is_none() { c } else if in1(c) { map(c) } else { c };
            if squeeze && last == Some(m) && (if s2.is_some() || delete { squeeze_set.contains(&m) } else { in1(m) }) {
                continue;
            }
            last = Some(m);
            out.push(m);
        }
        ctx.print(&out);
        true
    });
    if st {
        0
    } else {
        1
    }
}

// ── tee ────────────────────────────────────────────────────────────────────

pub fn tee(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "ai", values: "", long: &[("append", 'a', false), ("ignore-interrupts", 'i', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let fs = ctx.fs();
    let fl = crate::fs::file::flags::O_WRONLY | crate::fs::file::flags::O_CREAT | if p.has('a') { crate::fs::file::flags::O_APPEND } else { crate::fs::file::flags::O_TRUNC };
    let mut files = Vec::new();
    let mut st = 0;
    for f in &p.operands {
        match ops::open(&fs, f, fl, 0o666) {
            Ok(h) => files.push(h),
            Err(e) => {
                ctx.eprint(&alloc::format!("tee: {}: {}\n", f, e));
                st = 1;
            }
        }
    }
    let mut buf = alloc::vec![0u8; 16384];
    loop {
        match ctx.read_stdin(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                ctx.write(&buf[..n]);
                ctx.flush();
                for f in &files {
                    let _ = f.write_all(&buf[..n]);
                }
            }
            Err(Errno::EINTR) if p.has('i') && crate::proc::absorb_signals() => {}
            Err(_) => break,
        }
    }
    st
}

// ── seq / yes / rev / tac / nl ─────────────────────────────────────────────

pub fn seq(ctx: &mut Ctx) -> i32 {
    let mut sep = String::from("\n");
    let mut equal = false;
    let mut fmt: Option<String> = None;
    let mut nums = Vec::new();
    let mut i = 1;
    while i < ctx.args.len() {
        let a = ctx.args[i].clone();
        match a.as_str() {
            "-s" => {
                i += 1;
                sep = super::fmtutil::unescape(ctx.args.get(i).map(|s| s.as_str()).unwrap_or("")).0;
            }
            "-w" => equal = true,
            "-f" => {
                i += 1;
                fmt = ctx.args.get(i).cloned();
            }
            _ if a.starts_with("-s") && a.len() > 2 => sep = super::fmtutil::unescape(&a[2..]).0,
            _ => nums.push(a),
        }
        i += 1;
    }
    let parse = |s: &str| s.parse::<f64>().ok();
    let decimals = |s: &str| s.split_once('.').map(|(_, f)| f.len()).unwrap_or(0);
    let (first, inc, last) = match nums.len() {
        1 => ("1".to_string(), "1".to_string(), nums[0].clone()),
        2 => (nums[0].clone(), "1".to_string(), nums[1].clone()),
        3 => (nums[0].clone(), nums[1].clone(), nums[2].clone()),
        0 => return ctx.fail("missing operand"),
        _ => return ctx.fail(alloc::format!("extra operand {}", q(&nums[3]))),
    };
    let (Some(f), Some(s), Some(l)) = (parse(&first), parse(&inc), parse(&last)) else {
        let bad = [&first, &inc, &last].into_iter().find(|x| parse(x).is_none()).cloned().unwrap_or_default();
        return ctx.fail(alloc::format!("invalid floating point argument: {}", q(&bad)));
    };
    if s == 0.0 {
        return ctx.fail(alloc::format!("invalid Zero increment value: {}", q(&inc)));
    }
    let prec = decimals(&first).max(decimals(&inc));
    let render = |v: f64| -> String {
        match &fmt {
            Some(f) => super::basic::sprintf(f, &[alloc::format!("{:.*}", prec, v)]),
            None => alloc::format!("{:.*}", prec, v),
        }
    };
    let width = if equal { render(f).len().max(render(l).len()) } else { 0 };
    let mut v = f;
    let mut n = 0u64;
    let mut out = String::new();
    while (s > 0.0 && v <= l + 1e-9) || (s < 0.0 && v >= l - 1e-9) {
        if n > 0 {
            out.push_str(&sep);
        }
        let mut t = render(v);
        if equal {
            let neg = t.starts_with('-');
            let digits = t.trim_start_matches('-').to_string();
            let pad = width.saturating_sub(t.len());
            t = alloc::format!("{}{}{}", if neg { "-" } else { "" }, "0".repeat(pad), digits);
        }
        out.push_str(&t);
        n += 1;
        v = f + s * n as f64;
        if out.len() > 64 * 1024 {
            ctx.print(&out);
            out.clear();
            if ctx.should_stop() {
                return 130;
            }
        }
    }
    if n > 0 {
        out.push('\n');
    }
    ctx.print(&out);
    0
}

pub fn yes(ctx: &mut Ctx) -> i32 {
    let text = if ctx.args.len() > 1 { ctx.args[1..].join(" ") } else { String::from("y") };
    let line = alloc::format!("{text}\n");
    let chunk = line.repeat((8192 / line.len()).max(1));
    loop {
        ctx.print(&chunk);
        if !ctx.flush() || crate::proc::interrupted() {
            return 0;
        }
    }
}

pub fn rev(ctx: &mut Ctx) -> i32 {
    let (inputs, ok) = read_inputs(ctx, &ctx.args[1..].to_vec());
    for (_, d) in inputs {
        let text = String::from_utf8_lossy(&d).into_owned();
        for l in lines(text.as_bytes()) {
            let s: String = core::str::from_utf8(l).unwrap_or("").chars().rev().collect();
            outln!(ctx, "{}", s);
        }
    }
    if ok {
        0
    } else {
        1
    }
}

pub fn tac(ctx: &mut Ctx) -> i32 {
    let (inputs, ok) = read_inputs(ctx, &ctx.args[1..].to_vec());
    for (_, d) in inputs {
        for l in lines(&d).into_iter().rev() {
            ctx.write(l);
            ctx.write(b"\n");
        }
    }
    if ok {
        0
    } else {
        1
    }
}

pub fn nl(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "", values: "bnwsv", long: &[("body-numbering", 'b', true), ("number-format", 'n', true), ("number-width", 'w', true), ("number-separator", 's', true), ("starting-line-number", 'v', true)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let style = p.value('b').unwrap_or("t").to_string();
    let format = p.value('n').unwrap_or("rn").to_string();
    let width: usize = p.value('w').and_then(|s| s.parse().ok()).unwrap_or(6);
    let sep = p.value('s').unwrap_or("\t").to_string();
    let mut n: i64 = p.value('v').and_then(|s| s.parse().ok()).unwrap_or(1);
    let (inputs, ok) = read_inputs(ctx, &p.operands);
    for (_, d) in inputs {
        let text = String::from_utf8_lossy(&d).into_owned();
        for l in lines(text.as_bytes()) {
            let l = core::str::from_utf8(l).unwrap_or("");
            let number = match style.as_str() {
                "a" => true,
                "n" => false,
                _ => !l.is_empty(),
            };
            if number {
                let num = match format.as_str() {
                    "ln" => alloc::format!("{:<width$}", n, width = width),
                    "rz" => alloc::format!("{:0>width$}", n, width = width),
                    _ => alloc::format!("{:>width$}", n, width = width),
                };
                outln!(ctx, "{}{}{}", num, sep, l);
                n += 1;
            } else {
                outln!(ctx, "{}{}", " ".repeat(width + sep.len()), l);
            }
        }
    }
    if ok {
        0
    } else {
        1
    }
}

// ── base64 / sha256sum / hexdump ───────────────────────────────────────────

pub fn base64(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "di", values: "w", long: &[("decode", 'd', false), ("ignore-garbage", 'i', false), ("wrap", 'w', true)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let file = p.operands.first().cloned().unwrap_or_else(|| String::from("-"));
    let data = match ctx.read_input(&file) {
        Ok(d) => d,
        Err(e) => return ctx.fail(alloc::format!("{file}: {e}")),
    };
    if p.has('d') {
        let text: String = String::from_utf8_lossy(&data).chars().filter(|c| !c.is_whitespace()).collect();
        let text = if p.has('i') { text.chars().filter(|c| c.is_ascii_alphanumeric() || "+/=".contains(*c)).collect() } else { text };
        match fastros_codec::base64::decode(&text) {
            Some(b) => {
                ctx.write(&b);
                0
            }
            None => ctx.fail("invalid input"),
        }
    } else {
        let wrap: usize = p.value('w').and_then(|s| s.parse().ok()).unwrap_or(76);
        let enc = fastros_codec::base64::encode(&data);
        if wrap == 0 {
            outln!(ctx, "{}", enc);
        } else {
            for chunk in enc.as_bytes().chunks(wrap) {
                ctx.write(chunk);
                ctx.write(b"\n");
            }
        }
        0
    }
}

pub fn sha256sum(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "cbt", values: "", long: &[("check", 'c', false), ("binary", 'b', false), ("text", 't', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let files: Vec<String> = if p.operands.is_empty() { alloc::vec![String::from("-")] } else { p.operands.clone() };
    let mut st = 0;
    if p.has('c') {
        for list in files {
            let data = match ctx.read_input(&list) {
                Ok(d) => d,
                Err(e) => return ctx.fail(alloc::format!("{list}: {e}")),
            };
            let mut bad = 0;
            for line in String::from_utf8_lossy(&data).lines() {
                let Some((hash, name)) = line.split_once("  ").or_else(|| line.split_once(" *")) else { continue };
                let ok = ctx.read_input(name).map(|d| fastros_codec::hex::encode(&crate::crypto::sha256(&d)) == hash.to_ascii_lowercase()).unwrap_or(false);
                outln!(ctx, "{}: {}", name, if ok { "OK" } else { "FAILED" });
                if !ok {
                    bad += 1;
                }
            }
            if bad > 0 {
                ctx.eprint(&alloc::format!("sha256sum: WARNING: {bad} computed checksum{} did NOT match\n", if bad == 1 { "" } else { "s" }));
                st = 1;
            }
        }
        return st;
    }
    for f in files {
        match ctx.read_input(&f) {
            Ok(d) => {
                let h = fastros_codec::hex::encode(&crate::crypto::sha256(&d));
                outln!(ctx, "{}  {}", h, f);
            }
            Err(e) => {
                ctx.eprint(&alloc::format!("sha256sum: {f}: {e}\n"));
                st = 1;
            }
        }
    }
    st
}

pub fn hexdump(ctx: &mut Ctx) -> i32 {
    // `hexdump -C` / `xxd` canonical layout.
    let xxd = ctx.name() == "xxd";
    let files: Vec<String> = ctx.args[1..].iter().filter(|a| !a.starts_with('-')).cloned().collect();
    let (inputs, ok) = read_inputs(ctx, &files);
    let mut data = Vec::new();
    for (_, d) in inputs {
        data.extend_from_slice(&d);
    }
    let mut prev: Option<&[u8]> = None;
    let mut starred = false;
    for (i, chunk) in data.chunks(16).enumerate() {
        let off = i * 16;
        if !xxd && prev == Some(chunk) && chunk.len() == 16 {
            if !starred {
                outln!(ctx, "*");
                starred = true;
            }
            continue;
        }
        starred = false;
        prev = Some(chunk);
        let mut line = if xxd { alloc::format!("{off:08x}: ") } else { alloc::format!("{off:08x}  ") };
        for j in 0..16 {
            match chunk.get(j) {
                Some(b) if xxd => {
                    line.push_str(&alloc::format!("{b:02x}"));
                    if j % 2 == 1 {
                        line.push(' ');
                    }
                }
                Some(b) => line.push_str(&alloc::format!("{b:02x} ")),
                None if xxd => {
                    line.push_str("  ");
                    if j % 2 == 1 {
                        line.push(' ');
                    }
                }
                None => line.push_str("   "),
            }
            if !xxd && j == 7 {
                line.push(' ');
            }
        }
        let ascii: String = chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
        if xxd {
            line.push(' ');
            line.push_str(&ascii);
        } else {
            line.push_str(&alloc::format!(" |{ascii}|"));
        }
        outln!(ctx, "{}", line);
    }
    if !xxd && !data.is_empty() {
        outln!(ctx, "{:08x}", data.len());
    }
    if ok {
        0
    } else {
        1
    }
}
