//! File information: `stat`, `realpath`, `readlink`, `which`, `du`.

use super::fmtutil::{self, NameCache};
use crate::errno::Errno;
use crate::fs::perm::MAY_EXEC;
use crate::fs::{ops, FileType, Metadata, Timespec};
use crate::shell::ctx::{human, parse_opts, Ctx, OptSpec};
use crate::time::civil;
use crate::{out, outln};
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ── stat ───────────────────────────────────────────────────────────────────

fn kind_name(m: &Metadata) -> &'static str {
    match m.kind {
        FileType::Regular if m.size == 0 => "regular empty file",
        FileType::Regular => "regular file",
        FileType::Directory => "directory",
        FileType::Symlink => "symbolic link",
        FileType::CharDevice => "character special file",
        FileType::BlockDevice => "block special file",
        FileType::Fifo => "fifo",
        FileType::Socket => "socket",
    }
}

/// `2026-09-11 09:38:59.763777631 +0000`.
fn stat_time(t: Timespec) -> String {
    let tm = civil::from_unix(t.sec);
    alloc::format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:09} +0000", tm.year, tm.month, tm.day, tm.hour, tm.min, tm.sec, t.nsec)
}

fn fs_type_name(magic: u64, name: &str) -> String {
    match magic {
        0xEF53 => String::from("ext2/ext3"),
        0x0102_1994 => String::from("tmpfs"),
        0x9fa0 => String::from("proc"),
        0x6265_6572 => String::from("sysfs"),
        _ => name.to_string(),
    }
}

struct StatTarget<'a> {
    name: &'a str,
    meta: Metadata,
    link: Option<String>,
}

fn stat_directive(ctx: &Ctx, names: &NameCache, t: &StatTarget, c: char) -> Option<String> {
    let m = &t.meta;
    Some(match c {
        'n' => t.name.to_string(),
        'N' => match &t.link {
            Some(l) => alloc::format!("'{}' -> '{}'", t.name, l),
            None => alloc::format!("'{}'", t.name),
        },
        's' => m.size.to_string(),
        'b' => m.blocks.to_string(),
        'B' => String::from("512"),
        'o' => m.blksize.to_string(),
        'f' => alloc::format!("{:x}", m.mode()),
        'F' => kind_name(m).to_string(),
        'a' => alloc::format!("{:o}", m.perm & 0o7777),
        'A' => fmtutil::mode_string(m),
        'u' => m.uid.to_string(),
        'U' => names.user(m.uid),
        'g' => m.gid.to_string(),
        'G' => names.group(m.gid),
        'i' => m.ino.to_string(),
        'h' => m.nlink.to_string(),
        'd' => m.dev.to_string(),
        'D' => alloc::format!("{:x}", m.dev),
        'H' => crate::fs::major(m.dev).to_string(),
        'L' => crate::fs::minor(m.dev).to_string(),
        't' => alloc::format!("{:x}", crate::fs::major(m.rdev)),
        'T' => alloc::format!("{:x}", crate::fs::minor(m.rdev)),
        'r' => m.rdev.to_string(),
        'x' => stat_time(m.atime),
        'y' => stat_time(m.mtime),
        'z' => stat_time(m.ctime),
        'w' => String::from("-"),
        'X' => m.atime.sec.to_string(),
        'Y' => m.mtime.sec.to_string(),
        'Z' => m.ctime.sec.to_string(),
        'W' => String::from("0"),
        'm' => {
            // Mount point: the longest mount path that prefixes the file.
            let real = ctx_realpath(ctx, t.name).unwrap_or_else(|| t.name.to_string());
            let ns = ctx.proc.fs.lock().ns.clone();
            ns.list().into_iter().map(|(p, _)| p).filter(|p| p == "/" || real == *p || real.starts_with(&alloc::format!("{p}/"))).max_by_key(|p| p.len()).unwrap_or_else(|| String::from("/"))
        }
        _ => return None,
    })
}

fn ctx_realpath(ctx: &Ctx, p: &str) -> Option<String> {
    ctx.fs().resolve(p, true).ok().map(|n| n.path())
}

/// Expand a `--format`/`--printf` string.
fn expand_format(ctx: &Ctx, names: &NameCache, t: &StatTarget, fmt: &str, escapes: bool) -> String {
    let c: Vec<char> = fmt.chars().collect();
    let mut o = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '\\' && escapes && i + 1 < c.len() {
            let (s, _) = fmtutil::unescape(&c[i..i + 2].iter().collect::<String>());
            o.push_str(&s);
            i += 2;
            continue;
        }
        if c[i] != '%' || i + 1 >= c.len() {
            o.push(c[i]);
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let mut left = false;
        let mut zero = false;
        while j < c.len() && matches!(c[j], '-' | '0' | '#' | '+' | ' ' | '\'') {
            left |= c[j] == '-';
            zero |= c[j] == '0';
            j += 1;
        }
        let mut w = String::new();
        while j < c.len() && c[j].is_ascii_digit() {
            w.push(c[j]);
            j += 1;
        }
        let Some(&d) = c.get(j) else {
            o.extend(&c[i..]);
            break;
        };
        if d == '%' {
            o.push('%');
            i = j + 1;
            continue;
        }
        match stat_directive(ctx, names, t, d) {
            Some(v) => {
                let width: usize = w.parse().unwrap_or(0);
                let pad = width.saturating_sub(fmtutil::width(&v));
                if left {
                    o.push_str(&v);
                    o.extend(core::iter::repeat_n(' ', pad));
                } else {
                    o.extend(core::iter::repeat_n(if zero { '0' } else { ' ' }, pad));
                    o.push_str(&v);
                }
            }
            None => o.extend(&c[i..=j]),
        }
        i = j + 1;
    }
    o
}

pub fn stat(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "Lft",
        values: "c",
        long: &[("dereference", 'L', false), ("file-system", 'f', false), ("terse", 't', false), ("format", 'c', true), ("printf", 'p', true)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => {
            ctx.fail(m);
            ctx.eprint("Try 'stat --help' for more information.\n");
            return 1;
        }
    };
    if p.operands.is_empty() {
        ctx.fail("missing operand");
        ctx.eprint("Try 'stat --help' for more information.\n");
        return 1;
    }
    let names = NameCache::new();
    let fsctx = ctx.fs();
    let follow = p.has('L');
    let mut status = 0;
    for op in p.operands.clone() {
        if p.has('f') {
            match ops::statfs(&fsctx, &op) {
                Ok((sf, node)) => {
                    let ty = fs_type_name(sf.fs_type, node.mount.fs.fs_type());
                    if let Some(f) = p.value('c').or(p.value('p')) {
                        let s = f.replace("%n", &op).replace("%T", &ty).replace("%b", &sf.blocks.to_string()).replace("%f", &sf.blocks_free.to_string()).replace("%a", &sf.blocks_avail.to_string()).replace("%S", &sf.block_size.to_string()).replace("%c", &sf.files.to_string()).replace("%d", &sf.files_free.to_string());
                        ctx.print(&s);
                        if p.value('c').is_some() {
                            ctx.print("\n");
                        }
                        continue;
                    }
                    outln!(ctx, "  File: \"{}\"", op);
                    outln!(ctx, "    ID: {:<16x} Namelen: {:<7} Type: {}", node.mount.fs.dev(), sf.name_max, ty);
                    outln!(ctx, "Block size: {:<10} Fundamental block size: {}", sf.block_size, sf.block_size);
                    outln!(ctx, "Blocks: Total: {:<10} Free: {:<10} Available: {}", sf.blocks, sf.blocks_free, sf.blocks_avail);
                    outln!(ctx, "Inodes: Total: {:<10} Free: {}", sf.files, sf.files_free);
                }
                Err(e) => {
                    ctx.fail(alloc::format!("cannot read file system information for '{op}': {e}"));
                    status = 1;
                }
            }
            continue;
        }
        let meta = match ops::stat(&fsctx, &op, follow) {
            Ok(m) => m,
            Err(e) => {
                ctx.fail(alloc::format!("cannot statx '{op}': {e}"));
                status = 1;
                continue;
            }
        };
        let link = if meta.kind == FileType::Symlink { ops::readlink(&fsctx, &op).ok() } else { None };
        let t = StatTarget { name: &op, meta, link };
        if let Some(f) = p.value('c') {
            let s = expand_format(ctx, &names, &t, f, false);
            outln!(ctx, "{}", s);
            continue;
        }
        if let Some(f) = p.value('p') {
            let s = expand_format(ctx, &names, &t, f, true);
            ctx.print(&s);
            continue;
        }
        if p.has('t') {
            let s = expand_format(ctx, &names, &t, "%n %s %b %f %u %g %D %i %h %t %T %X %Y %Z %W %o", false);
            outln!(ctx, "{}", s);
            continue;
        }
        let m = &t.meta;
        match &t.link {
            Some(l) => outln!(ctx, "  File: {} -> {}", op, l),
            None => outln!(ctx, "  File: {}", op),
        }
        outln!(ctx, "  Size: {:<10}\tBlocks: {:<10} IO Block: {:<6} {}", m.size, m.blocks, m.blksize, kind_name(m));
        let dev = alloc::format!("{},{}", crate::fs::major(m.dev), crate::fs::minor(m.dev));
        if matches!(m.kind, FileType::CharDevice | FileType::BlockDevice) {
            outln!(ctx, "Device: {}\tInode: {:<11} Links: {:<5} Device type: {},{}", dev, m.ino, m.nlink, crate::fs::major(m.rdev), crate::fs::minor(m.rdev));
        } else {
            outln!(ctx, "Device: {}\tInode: {:<11} Links: {}", dev, m.ino, m.nlink);
        }
        outln!(
            ctx,
            "Access: ({:04o}/{})  Uid: ({:>5}/{:>8})   Gid: ({:>5}/{:>8})",
            m.perm & 0o7777,
            fmtutil::mode_string(m),
            m.uid,
            names.user(m.uid),
            m.gid,
            names.group(m.gid)
        );
        outln!(ctx, "Access: {}", stat_time(m.atime));
        outln!(ctx, "Modify: {}", stat_time(m.mtime));
        outln!(ctx, "Change: {}", stat_time(m.ctime));
        outln!(ctx, " Birth: -");
    }
    status
}

// ── realpath / readlink ────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Canon {
    /// Every component must exist.
    Existing,
    /// All but the last component must exist.
    Parent,
    /// Nothing needs to exist.
    Missing,
}

/// Canonicalize `path` like coreutils `canonicalize_filename_mode`:
/// absolute, no `.`/`..`, no symlinks (unless `physical` is false).
fn canonicalize(ctx: &Ctx, path: &str, mode: Canon, physical: bool) -> Result<String, Errno> {
    let fsctx = ctx.fs();
    let mut todo: Vec<String> = Vec::new();
    let start = if path.starts_with('/') { String::from("/") } else { ctx.cwd() };
    let push_rev = |todo: &mut Vec<String>, p: &str| {
        let comps: Vec<&str> = p.split('/').filter(|c| !c.is_empty()).collect();
        for c in comps.into_iter().rev() {
            todo.push(c.to_string());
        }
    };
    push_rev(&mut todo, path);
    let mut out: Vec<String> = start.split('/').filter(|c| !c.is_empty()).map(|c| c.to_string()).collect();
    let mut links = 0;
    let mut missing_seen = false;
    while let Some(c) = todo.pop() {
        if c == "." {
            continue;
        }
        if c == ".." {
            out.pop();
            continue;
        }
        out.push(c);
        let cur = alloc::format!("/{}", out.join("/"));
        if missing_seen {
            if mode != Canon::Missing {
                return Err(Errno::ENOENT);
            }
            continue;
        }
        match ops::stat(&fsctx, &cur, false) {
            Ok(m) if m.kind == FileType::Symlink && physical => {
                links += 1;
                if links > 40 {
                    return Err(Errno::ELOOP);
                }
                let target = ops::readlink(&fsctx, &cur)?;
                out.pop();
                if target.starts_with('/') {
                    out.clear();
                }
                push_rev(&mut todo, &target);
            }
            Ok(m) => {
                if !todo.is_empty() && m.kind != FileType::Directory {
                    return Err(Errno::ENOTDIR);
                }
            }
            Err(Errno::ENOENT) => {
                let last = todo.is_empty();
                match mode {
                    Canon::Existing => return Err(Errno::ENOENT),
                    Canon::Parent if !last => return Err(Errno::ENOENT),
                    _ => missing_seen = true,
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(alloc::format!("/{}", out.join("/")))
}

pub fn realpath(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "emsLPqz",
        values: "",
        long: &[
            ("canonicalize-existing", 'e', false),
            ("canonicalize-missing", 'm', false),
            ("strip", 's', false),
            ("no-symlinks", 's', false),
            ("logical", 'L', false),
            ("physical", 'P', false),
            ("quiet", 'q', false),
            ("zero", 'z', false),
            ("relative-to", 'R', true),
        ],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    if p.operands.is_empty() {
        return ctx.fail("missing operand");
    }
    let mode = if p.has('e') {
        Canon::Existing
    } else if p.has('m') {
        Canon::Missing
    } else {
        Canon::Parent
    };
    let base = match p.value('R') {
        Some(b) => match canonicalize(ctx, b, Canon::Missing, !p.has('s')) {
            Ok(v) => Some(v),
            Err(e) => return ctx.fail_errno(b, e),
        },
        None => None,
    };
    let mut st = 0;
    for op in p.operands.clone() {
        match canonicalize(ctx, &op, mode, !p.has('s')) {
            Ok(r) => {
                let shown = match &base {
                    Some(b) => relative_to(&r, b),
                    None => r,
                };
                ctx.print(&shown);
                ctx.write(if p.has('z') { b"\0" } else { b"\n" });
            }
            Err(e) => {
                if !p.has('q') {
                    ctx.fail_errno(&op, e);
                }
                st = 1;
            }
        }
    }
    st
}

fn relative_to(path: &str, base: &str) -> String {
    let a: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    let b: Vec<&str> = base.split('/').filter(|c| !c.is_empty()).collect();
    let common = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
    let mut parts: Vec<&str> = core::iter::repeat_n("..", b.len() - common).collect();
    parts.extend(&a[common..]);
    if parts.is_empty() {
        String::from(".")
    } else {
        parts.join("/")
    }
}

pub fn readlink(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "femnqsvz",
        values: "",
        long: &[
            ("canonicalize", 'f', false),
            ("canonicalize-existing", 'e', false),
            ("canonicalize-missing", 'm', false),
            ("no-newline", 'n', false),
            ("quiet", 'q', false),
            ("silent", 's', false),
            ("verbose", 'v', false),
            ("zero", 'z', false),
        ],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    if p.operands.is_empty() {
        return ctx.fail("missing operand");
    }
    let canon = if p.has('f') {
        Some(Canon::Parent)
    } else if p.has('e') {
        Some(Canon::Existing)
    } else if p.has('m') {
        Some(Canon::Missing)
    } else {
        None
    };
    let fsctx = ctx.fs();
    let mut st = 0;
    let n = p.operands.len();
    for (i, op) in p.operands.clone().into_iter().enumerate() {
        let r = match canon {
            Some(mode) => canonicalize(ctx, &op, mode, true),
            None => ops::readlink(&fsctx, &op),
        };
        match r {
            Ok(v) => {
                ctx.print(&v);
                // -n only drops the newline when there is a single operand.
                if p.has('z') {
                    ctx.write(b"\0");
                } else if !(p.has('n') && n == 1 && i == 0) {
                    ctx.print("\n");
                }
            }
            Err(e) => {
                if p.has('v') {
                    ctx.fail_errno(&op, e);
                }
                st = 1;
            }
        }
    }
    st
}

// ── which ──────────────────────────────────────────────────────────────────

pub fn which(ctx: &mut Ctx) -> i32 {
    let mut all = false;
    let mut names = Vec::new();
    for a in ctx.args[1..].to_vec() {
        match a.as_str() {
            "-a" => all = true,
            s if s.starts_with('-') && s.len() > 1 => return ctx.fail(alloc::format!("invalid option -- '{}'", &s[1..])),
            _ => names.push(a),
        }
    }
    if names.is_empty() {
        return 1;
    }
    let path = ctx.env("PATH").unwrap_or_else(|| String::from("/bin:/usr/local/bin"));
    let fsctx = ctx.fs();
    let mut st = 0;
    for name in names {
        let mut found = false;
        let candidates: Vec<String> = if name.contains('/') {
            alloc::vec![name.clone()]
        } else {
            path.split(':').map(|d| if d.is_empty() { name.clone() } else { alloc::format!("{}/{}", d.trim_end_matches('/'), name) }).collect()
        };
        for c in candidates {
            let ok = ops::stat(&fsctx, &c, true).is_ok_and(|m| m.kind == FileType::Regular) && ops::access(&fsctx, &c, MAY_EXEC).is_ok();
            if ok {
                outln!(ctx, "{}", c);
                found = true;
                if !all {
                    break;
                }
            }
        }
        if !found {
            st = 1;
        }
    }
    st
}

// ── du ─────────────────────────────────────────────────────────────────────

struct DuOpts {
    all: bool,
    summarize: bool,
    human: bool,
    apparent: bool,
    bytes: bool,
    unit: u64,
    max_depth: Option<usize>,
    xdev: bool,
    deref: bool,
    null: bool,
}

struct Du<'a> {
    ctx: &'a mut Ctx,
    o: DuOpts,
    seen: BTreeSet<(u64, u64)>,
    status: i32,
}

impl Du<'_> {
    fn size_of(&self, m: &Metadata) -> u64 {
        if self.o.apparent || self.o.bytes {
            m.size
        } else {
            m.blocks * 512
        }
    }

    fn show(&mut self, bytes: u64, path: &str) {
        let v = if self.o.human {
            human(bytes)
        } else if self.o.bytes {
            bytes.to_string()
        } else {
            bytes.div_ceil(self.o.unit).to_string()
        };
        out!(self.ctx, "{}\t{}", v, path);
        self.ctx.write(if self.o.null { b"\0" } else { b"\n" });
    }

    fn walk(&mut self, path: &str, depth: usize, root_dev: u64) -> u64 {
        if self.ctx.should_stop() {
            return 0;
        }
        let fsctx = self.ctx.fs();
        let meta = match ops::stat(&fsctx, path, self.o.deref) {
            Ok(m) => m,
            Err(e) => {
                self.ctx.fail(alloc::format!("cannot access '{path}': {e}"));
                self.status = 1;
                return 0;
            }
        };
        // Every inode counts once: hard links, and operands given twice.
        if !self.seen.insert((meta.dev, meta.ino)) {
            return 0;
        }
        let mut total = self.size_of(&meta);
        if meta.kind == FileType::Directory && !(self.o.xdev && meta.dev != root_dev) {
            match ops::list_dir(&fsctx, path) {
                Ok(entries) => {
                    for e in entries {
                        let child = if path.ends_with('/') { alloc::format!("{path}{}", e.name) } else { alloc::format!("{path}/{}", e.name) };
                        total += self.walk(&child, depth + 1, root_dev);
                    }
                }
                Err(e) => {
                    self.ctx.fail(alloc::format!("cannot read directory '{path}': {e}"));
                    self.status = 1;
                }
            }
            let shown = if self.o.summarize { depth == 0 } else { self.o.max_depth.is_none_or(|d| depth <= d) };
            if shown {
                self.show(total, path);
            }
        } else if (self.o.all && !self.o.summarize && self.o.max_depth.is_none_or(|d| depth <= d)) || depth == 0 {
            self.show(total, path);
        }
        total
    }
}

pub fn du(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "ashbckmxLDSl0",
        values: "dB",
        long: &[
            ("all", 'a', false),
            ("summarize", 's', false),
            ("human-readable", 'h', false),
            ("bytes", 'b', false),
            ("total", 'c', false),
            ("apparent-size", 'A', false),
            ("max-depth", 'd', true),
            ("block-size", 'B', true),
            ("one-file-system", 'x', false),
            ("dereference", 'L', false),
            ("null", '0', false),
        ],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => {
            ctx.fail(m);
            ctx.eprint("Try 'du --help' for more information.\n");
            return 1;
        }
    };
    let max_depth = match p.value('d') {
        Some(v) => match v.parse::<usize>() {
            Ok(n) => Some(n),
            Err(_) => return ctx.fail(alloc::format!("invalid maximum depth '{v}'")),
        },
        None => None,
    };
    let unit = if p.has('m') {
        1 << 20
    } else if let Some(b) = p.value('B') {
        match fmtutil::parse_size(b) {
            Some(n) if n > 0 => n,
            _ => return ctx.fail(alloc::format!("invalid --block-size argument '{b}'")),
        }
    } else {
        1024
    };
    if p.has('s') && max_depth.is_some_and(|d| d > 0) {
        return ctx.fail("cannot both summarize and show all entries");
    }
    let o = DuOpts {
        all: p.has('a'),
        summarize: p.has('s') || max_depth == Some(0),
        human: p.has('h'),
        apparent: p.has('A'),
        bytes: p.has('b'),
        unit,
        max_depth,
        xdev: p.has('x'),
        deref: p.has('L'),
        null: p.has('0'),
    };
    let mut ops_list = p.operands.clone();
    if ops_list.is_empty() {
        ops_list.push(String::from("."));
    }
    let mut du = Du { ctx, o, seen: BTreeSet::new(), status: 0 };
    let mut grand = 0;
    for op in &ops_list {
        let dev = ops::stat(&du.ctx.fs(), op, true).map(|m| m.dev).unwrap_or(0);
        grand += du.walk(op, 0, dev);
    }
    if p.has('c') {
        du.show(grand, "total");
    }
    du.status
}
