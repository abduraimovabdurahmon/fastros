//! `diff`: compare files line by line (GNU diffutils output formats).
//!
//! Lines are interned to integers, common prefix/suffix are trimmed, and
//! the middle is solved with Myers' O((N+M)·D) greedy algorithm, which
//! yields a minimal edit script. Output: the default "normal" format and
//! unified (`-u`, `-U N`); `-q`, `-s`, `-r`, `-N`, `-i`, `-b`, `-w`, `-a`.

use crate::fs::{ops, FileType, Metadata, Timespec};
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use crate::time::civil;
use crate::outln;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Normal,
    Unified(usize),
}

struct Opts {
    format: Format,
    brief: bool,
    report_same: bool,
    recursive: bool,
    new_file: bool,
    icase: bool,
    ispace_change: bool,
    iall_space: bool,
    text: bool,
    labels: Vec<String>,
    /// Option letters for the `diff -r a b` lines printed in recursive mode.
    flags_shown: String,
}

/// One side of a comparison.
struct Side {
    name: String,
    data: Vec<u8>,
    meta: Option<Metadata>,
}

fn split_lines(data: &[u8]) -> (Vec<&[u8]>, bool) {
    if data.is_empty() {
        return (Vec::new(), true);
    }
    let complete = data.last() == Some(&b'\n');
    let body = if complete { &data[..data.len() - 1] } else { data };
    (body.split(|&b| b == b'\n').collect(), complete)
}

fn normalize(line: &[u8], o: &Opts) -> Vec<u8> {
    let mut v: Vec<u8> = if o.iall_space {
        line.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect()
    } else if o.ispace_change {
        let mut out = Vec::with_capacity(line.len());
        let mut in_space = false;
        for &b in line {
            if b == b' ' || b == b'\t' {
                in_space = true;
            } else {
                if in_space && !out.is_empty() {
                    out.push(b' ');
                }
                in_space = false;
                out.push(b);
            }
        }
        out
    } else {
        line.to_vec()
    };
    if o.icase {
        v.make_ascii_lowercase();
    }
    v
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Equal,
    Delete,
    Insert,
}

/// Myers diff over interned line ids; returns the edit script.
fn myers(a: &[u32], b: &[u32]) -> Vec<Op> {
    let n = a.len() as isize;
    let m = b.len() as isize;
    let max = (n + m) as usize;
    if max == 0 {
        return Vec::new();
    }
    let off = max as isize;
    let mut v = alloc::vec![0isize; 2 * max + 2];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    'outer: for d in 0..=max as isize {
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            let idx = (k + off) as usize;
            let mut x = if k == -d || (k != d && v[idx - 1] < v[idx + 1]) { v[idx + 1] } else { v[idx - 1] + 1 };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[idx] = x;
            if x >= n && y >= m {
                trace.push(v.clone());
                break 'outer;
            }
            k += 2;
        }
        if d % 64 == 0 {
            crate::sched::cond_resched();
        }
    }
    // Backtrack from (n, m).
    let mut ops = Vec::with_capacity((n + m) as usize);
    let mut x = n;
    let mut y = m;
    for d in (1..trace.len() as isize - 1).rev() {
        let v = &trace[d as usize];
        let k = x - y;
        let idx = (k + off) as usize;
        let prev_k = if k == -d || (k != d && v[idx - 1] < v[idx + 1]) { k + 1 } else { k - 1 };
        let prev_x = v[(prev_k + off) as usize];
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            ops.push(Op::Equal);
            x -= 1;
            y -= 1;
        }
        if x == prev_x {
            ops.push(Op::Insert);
        } else {
            ops.push(Op::Delete);
        }
        x = prev_x;
        y = prev_y;
    }
    while x > 0 && y > 0 {
        ops.push(Op::Equal);
        x -= 1;
        y -= 1;
    }
    ops.reverse();
    ops
}

/// A block of changes: old lines [a0, a1), new lines [b0, b1).
#[derive(Clone, Copy, Debug)]
struct Change {
    a0: usize,
    a1: usize,
    b0: usize,
    b1: usize,
}

fn changes(a: &[u32], b: &[u32]) -> Vec<Change> {
    // Trim common prefix and suffix (fast path for typical edits).
    let mut pre = 0;
    while pre < a.len() && pre < b.len() && a[pre] == b[pre] {
        pre += 1;
    }
    let mut suf = 0;
    while suf < a.len() - pre && suf < b.len() - pre && a[a.len() - 1 - suf] == b[b.len() - 1 - suf] {
        suf += 1;
    }
    let ops = myers(&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let mut out = Vec::new();
    let (mut i, mut j) = (pre, pre);
    let mut cur: Option<Change> = None;
    for op in ops {
        match op {
            Op::Equal => {
                if let Some(c) = cur.take() {
                    out.push(c);
                }
                i += 1;
                j += 1;
            }
            Op::Delete => {
                let c = cur.get_or_insert(Change { a0: i, a1: i, b0: j, b1: j });
                c.a1 = i + 1;
                i += 1;
            }
            Op::Insert => {
                let c = cur.get_or_insert(Change { a0: i, a1: i, b0: j, b1: j });
                c.b1 = j + 1;
                j += 1;
            }
        }
    }
    if let Some(c) = cur {
        out.push(c);
    }
    out
}

/// Lines `[lo, hi)` as the normal format writes them: `N` or `N,M` (1-based).
fn range(lo: usize, hi: usize) -> String {
    if hi - lo == 1 {
        (lo + 1).to_string()
    } else {
        alloc::format!("{},{}", lo + 1, hi)
    }
}

fn file_time(m: &Option<Metadata>) -> String {
    let t = m.as_ref().map(|m| m.mtime).unwrap_or(Timespec { sec: 0, nsec: 0 });
    let tm = civil::from_unix(t.sec);
    alloc::format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:09} +0000", tm.year, tm.month, tm.day, tm.hour, tm.min, tm.sec, t.nsec)
}

const NO_NL: &[u8] = b"\\ No newline at end of file\n";

fn emit(ctx: &mut Ctx, prefix: &[u8], line: &[u8], last_incomplete: bool) {
    let mut v = Vec::with_capacity(line.len() + 4);
    v.extend_from_slice(prefix);
    v.extend_from_slice(line);
    v.push(b'\n');
    if last_incomplete {
        v.extend_from_slice(NO_NL);
    }
    ctx.write(&v);
}

/// Compare two loaded files; prints the diff, returns true if they differ.
fn diff_sides(ctx: &mut Ctx, o: &Opts, a: &Side, b: &Side, header: Option<&str>) -> bool {
    if a.data == b.data {
        if o.report_same {
            outln!(ctx, "Files {} and {} are identical", a.name, b.name);
        }
        return false;
    }
    let binary = !o.text && (a.data[..a.data.len().min(8192)].contains(&0) || b.data[..b.data.len().min(8192)].contains(&0));
    let (la, ca) = split_lines(&a.data);
    let (lb, cb) = split_lines(&b.data);
    // Intern lines (normalized for -i/-b/-w).
    let mut ids: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
    let mut intern = |l: &[u8]| -> u32 {
        let key = normalize(l, o);
        let next = ids.len() as u32;
        *ids.entry(key).or_insert(next)
    };
    let ia: Vec<u32> = la.iter().map(|l| intern(l)).collect();
    let ib: Vec<u32> = lb.iter().map(|l| intern(l)).collect();
    let mut ch = changes(&ia, &ib);
    // A missing final newline is itself a difference on the last line.
    if ch.is_empty() && ca != cb && !la.is_empty() && !lb.is_empty() {
        ch.push(Change { a0: la.len() - 1, a1: la.len(), b0: lb.len() - 1, b1: lb.len() });
    }
    if ch.is_empty() {
        if o.report_same {
            outln!(ctx, "Files {} and {} are identical", a.name, b.name);
        }
        return false;
    }
    if o.brief || binary {
        if binary && !o.brief {
            outln!(ctx, "Binary files {} and {} differ", a.name, b.name);
        } else {
            outln!(ctx, "Files {} and {} differ", a.name, b.name);
        }
        return true;
    }
    if let Some(h) = header {
        outln!(ctx, "{}", h);
    }
    let incomplete_a = |i: usize| !ca && i + 1 == la.len();
    let incomplete_b = |j: usize| !cb && j + 1 == lb.len();
    match o.format {
        Format::Normal => {
            for c in &ch {
                let (dels, adds) = (c.a1 > c.a0, c.b1 > c.b0);
                let ar = if dels { range(c.a0, c.a1) } else { c.a0.to_string() };
                let br = if adds { range(c.b0, c.b1) } else { c.b0.to_string() };
                let letter = match (dels, adds) {
                    (true, true) => 'c',
                    (true, false) => 'd',
                    _ => 'a',
                };
                outln!(ctx, "{}{}{}", ar, letter, br);
                for i in c.a0..c.a1 {
                    emit(ctx, b"< ", la[i], incomplete_a(i));
                }
                if dels && adds {
                    ctx.print("---\n");
                }
                for j in c.b0..c.b1 {
                    emit(ctx, b"> ", lb[j], incomplete_b(j));
                }
            }
        }
        Format::Unified(ctxn) => {
            let la_name = o.labels.first().cloned().unwrap_or_else(|| alloc::format!("{}\t{}", a.name, file_time(&a.meta)));
            let lb_name = o.labels.get(1).cloned().unwrap_or_else(|| alloc::format!("{}\t{}", b.name, file_time(&b.meta)));
            outln!(ctx, "--- {}", la_name);
            outln!(ctx, "+++ {}", lb_name);
            // Group changes whose context would touch or overlap.
            let mut k = 0;
            while k < ch.len() {
                let mut end = k;
                while end + 1 < ch.len() && ch[end + 1].a0 - ch[end].a1 <= 2 * ctxn {
                    end += 1;
                }
                let first = ch[k];
                let last = ch[end];
                let a_start = first.a0.saturating_sub(ctxn);
                let a_end = (last.a1 + ctxn).min(la.len());
                let b_start = first.b0.saturating_sub(ctxn);
                let b_end = (last.b1 + ctxn).min(lb.len());
                let hr = |s: usize, e: usize| -> String {
                    let n = e - s;
                    match n {
                        0 => alloc::format!("{},0", s),
                        1 => (s + 1).to_string(),
                        _ => alloc::format!("{},{}", s + 1, n),
                    }
                };
                outln!(ctx, "@@ -{} +{} @@", hr(a_start, a_end), hr(b_start, b_end));
                let mut i = a_start;
                for c in &ch[k..=end] {
                    while i < c.a0 {
                        emit(ctx, b" ", la[i], incomplete_a(i));
                        i += 1;
                    }
                    for x in c.a0..c.a1 {
                        emit(ctx, b"-", la[x], incomplete_a(x));
                    }
                    for y in c.b0..c.b1 {
                        emit(ctx, b"+", lb[y], incomplete_b(y));
                    }
                    i = c.a1;
                }
                while i < a_end {
                    emit(ctx, b" ", la[i], incomplete_a(i));
                    i += 1;
                }
                k = end + 1;
            }
        }
    }
    true
}

enum Load {
    File(Side),
    Dir(Metadata),
    Missing,
}

fn load(ctx: &mut Ctx, path: &str) -> Result<Load, String> {
    if path == "-" {
        return ctx.read_input("-").map(|data| Load::File(Side { name: String::from("-"), data, meta: None })).map_err(|e| alloc::format!("-: {e}"));
    }
    let fsctx = ctx.fs();
    let meta = match ops::stat(&fsctx, path, true) {
        Ok(m) => m,
        Err(crate::errno::Errno::ENOENT) => return Ok(Load::Missing),
        Err(e) => return Err(alloc::format!("{path}: {e}")),
    };
    if meta.kind == FileType::Directory {
        return Ok(Load::Dir(meta));
    }
    let data = ops::read_file(&fsctx, path).map_err(|e| alloc::format!("{path}: {e}"))?;
    Ok(Load::File(Side { name: path.to_string(), data, meta: Some(meta) }))
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        alloc::format!("{dir}{name}")
    } else {
        alloc::format!("{dir}/{name}")
    }
}

fn kind_word(m: &Metadata) -> &'static str {
    match m.kind {
        FileType::Directory => "directory",
        FileType::Regular if m.size == 0 => "regular empty file",
        FileType::Regular => "regular file",
        FileType::Symlink => "symbolic link",
        FileType::Fifo => "fifo",
        FileType::Socket => "socket",
        FileType::CharDevice => "character special file",
        FileType::BlockDevice => "block special file",
    }
}

struct Status {
    differ: bool,
    trouble: bool,
}

fn compare_paths(ctx: &mut Ctx, o: &Opts, pa: &str, pb: &str, st: &mut Status, top: bool) {
    if ctx.should_stop() {
        return;
    }
    let la = match load(ctx, pa) {
        Ok(l) => l,
        Err(m) => {
            ctx.fail(m);
            st.trouble = true;
            return;
        }
    };
    let lb = match load(ctx, pb) {
        Ok(l) => l,
        Err(m) => {
            ctx.fail(m);
            st.trouble = true;
            return;
        }
    };
    let header = if top { None } else { Some(alloc::format!("diff{} {} {}", o.flags_shown, pa, pb)) };
    // `-N`: a missing file compares as an empty one.
    let empty = |name: &str| Side { name: name.to_string(), data: Vec::new(), meta: None };
    let (a, b) = match (la, lb) {
        (Load::Missing, Load::Missing) | (Load::Missing, Load::Dir(_)) | (Load::Dir(_), Load::Missing) => {
            let missing = if ops::stat(&ctx.fs(), pa, true).is_err() { pa } else { pb };
            ctx.fail(alloc::format!("{missing}: No such file or directory"));
            st.trouble = true;
            return;
        }
        (Load::Missing, _) | (_, Load::Missing) if !o.new_file => {
            let missing = if ops::stat(&ctx.fs(), pa, true).is_err() { pa } else { pb };
            ctx.fail(alloc::format!("{missing}: No such file or directory"));
            st.trouble = true;
            return;
        }
        (Load::Missing, Load::File(b)) => (empty(pa), b),
        (Load::File(a), Load::Missing) => (a, empty(pb)),
        (Load::File(a), Load::File(b)) => (a, b),
        (Load::Dir(_), Load::Dir(_)) => return compare_dirs(ctx, o, pa, pb, st),
        // `diff dir file` compares `dir/file`'s basename with `file`.
        (Load::Dir(_), Load::File(_)) if top => {
            let base = pb.rsplit('/').next().unwrap_or(pb);
            return compare_paths(ctx, o, &join(pa, base), pb, st, true);
        }
        (Load::File(_), Load::Dir(_)) if top => {
            let base = pa.rsplit('/').next().unwrap_or(pa);
            return compare_paths(ctx, o, pa, &join(pb, base), st, true);
        }
        (Load::Dir(m), Load::File(b)) => {
            outln!(ctx, "File {} is a {} while file {} is a {}", pa, kind_word(&m), pb, b.meta.as_ref().map(kind_word).unwrap_or("regular file"));
            st.differ = true;
            return;
        }
        (Load::File(a), Load::Dir(m)) => {
            outln!(ctx, "File {} is a {} while file {} is a {}", pa, a.meta.as_ref().map(kind_word).unwrap_or("regular file"), pb, kind_word(&m));
            st.differ = true;
            return;
        }
    };
    if diff_sides(ctx, o, &a, &b, header.as_deref()) {
        st.differ = true;
    }
}

fn compare_dirs(ctx: &mut Ctx, o: &Opts, da: &str, db: &str, st: &mut Status) {
    let fsctx = ctx.fs();
    let list = |p: &str| -> Result<BTreeSet<String>, String> { ops::list_dir(&fsctx, p).map(|v| v.into_iter().map(|e| e.name).collect()).map_err(|e| alloc::format!("{p}: {e}")) };
    let (na, nb) = match (list(da), list(db)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(m), _) | (_, Err(m)) => {
            ctx.fail(m);
            st.trouble = true;
            return;
        }
    };
    let all: BTreeSet<&String> = na.iter().chain(nb.iter()).collect();
    for name in all {
        if ctx.should_stop() {
            return;
        }
        let pa = join(da, name);
        let pb = join(db, name);
        let in_a = na.contains(name);
        let in_b = nb.contains(name);
        if !(in_a && in_b) && !o.new_file {
            outln!(ctx, "Only in {}: {}", if in_a { da } else { db }, name);
            st.differ = true;
            continue;
        }
        let ma = ops::stat(&fsctx, &pa, true).ok();
        let mb = ops::stat(&fsctx, &pb, true).ok();
        let a_dir = ma.as_ref().is_some_and(|m| m.kind == FileType::Directory);
        let b_dir = mb.as_ref().is_some_and(|m| m.kind == FileType::Directory);
        if a_dir && b_dir {
            if o.recursive {
                compare_dirs(ctx, o, &pa, &pb, st);
            } else {
                outln!(ctx, "Common subdirectories: {} and {}", pa, pb);
            }
            continue;
        }
        if (a_dir || b_dir) && !(a_dir && !in_b) && !(b_dir && !in_a) {
            if let (Some(ma), Some(mb)) = (&ma, &mb) {
                outln!(ctx, "File {} is a {} while file {} is a {}", pa, kind_word(ma), pb, kind_word(mb));
                st.differ = true;
                continue;
            }
        }
        compare_paths(ctx, o, &pa, &pb, st, false);
    }
}

pub fn diff(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "uqsrNibwaT",
        values: "UL",
        long: &[
            ("unified", 'U', true),
            ("brief", 'q', false),
            ("report-identical-files", 's', false),
            ("recursive", 'r', false),
            ("new-file", 'N', false),
            ("ignore-case", 'i', false),
            ("ignore-space-change", 'b', false),
            ("ignore-all-space", 'w', false),
            ("text", 'a', false),
            ("label", 'L', true),
            ("normal", '\u{1}', false),
        ],
    };
    // `-u` alone is `-U 3`; `--unified` alone too.
    let args: Vec<String> = ctx.args.iter().map(|a| if a == "--unified" { String::from("-u") } else { a.clone() }).collect();
    let p = match parse_opts(&args, &SPEC) {
        Ok(p) => p,
        Err(m) => {
            ctx.fail(m);
            ctx.eprint("diff: Try 'diff --help' for more information.\n");
            return 2;
        }
    };
    let format = if let Some(n) = p.value('U') {
        match n.parse() {
            Ok(n) => Format::Unified(n),
            Err(_) => {
                let n = n.to_string();
                ctx.fail(alloc::format!("invalid context length '{n}'"));
                return 2;
            }
        }
    } else if p.has('u') {
        Format::Unified(3)
    } else {
        Format::Normal
    };
    if p.operands.len() != 2 {
        let msg = if p.operands.len() < 2 { alloc::format!("missing operand after '{}'", p.operands.last().map(|s| s.as_str()).unwrap_or("diff")) } else { alloc::format!("extra operand '{}'", p.operands[2]) };
        ctx.fail(msg);
        ctx.eprint("diff: Try 'diff --help' for more information.\n");
        return 2;
    }
    let mut shown = String::new();
    for c in ['a', 'b', 'i', 'N', 'q', 'r', 's', 'u', 'w'] {
        if p.has(c) {
            shown.push(c);
        }
    }
    let flags_shown = if shown.is_empty() { String::new() } else { alloc::format!(" -{shown}") };
    let flags_shown = match (format, p.value('U')) {
        (Format::Unified(n), Some(_)) => alloc::format!("{flags_shown} -U {n}"),
        _ => flags_shown,
    };
    let o = Opts {
        format,
        brief: p.has('q'),
        report_same: p.has('s'),
        recursive: p.has('r'),
        new_file: p.has('N'),
        icase: p.has('i'),
        ispace_change: p.has('b'),
        iall_space: p.has('w'),
        text: p.has('a'),
        labels: p.values('L').to_vec(),
        flags_shown,
    };
    let mut st = Status { differ: false, trouble: false };
    let (a, b) = (p.operands[0].clone(), p.operands[1].clone());
    compare_paths(ctx, &o, &a, &b, &mut st, true);
    if st.trouble {
        2
    } else if st.differ {
        1
    } else {
        0
    }
}
