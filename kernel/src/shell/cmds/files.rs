//! File commands.

use super::fmtutil::{self, NameCache};
use crate::fs::ops;
use crate::fs::{FileType, Metadata};
use crate::shell::ctx::{human, parse_opts, Ctx, OptSpec};
use crate::{out, outln};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ── ls ─────────────────────────────────────────────────────────────────────

struct LsOpts {
    all: bool,
    almost_all: bool,
    long: bool,
    human: bool,
    one: bool,
    dir_itself: bool,
    recursive: bool,
    reverse: bool,
    by_time: bool,
    by_size: bool,
    unsorted: bool,
    inode: bool,
    classify: bool,
    numeric: bool,
    color: bool,
    columns: bool,
}

struct Entry {
    name: String,
    path: String,
    meta: Option<Metadata>,
    target: Option<String>,
    target_meta: Option<Metadata>,
}

pub fn ls(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "aAlhdRrtSUi1CFnx",
        values: "",
        long: &[
            ("all", 'a', false),
            ("almost-all", 'A', false),
            ("human-readable", 'h', false),
            ("directory", 'd', false),
            ("recursive", 'R', false),
            ("reverse", 'r', false),
            ("inode", 'i', false),
            ("classify", 'F', false),
            ("numeric-uid-gid", 'n', false),
            ("color", 'c', true),
            ("colour", 'c', true),
        ],
    };
    // `--color` alone means always.
    let args: Vec<String> = ctx.args.iter().map(|a| if a == "--color" || a == "--colour" { String::from("--color=always") } else { a.clone() }).collect();
    let p = match parse_opts(&args, &SPEC) {
        Ok(p) => p,
        Err(m) => {
            ctx.fail(m);
            ctx.eprint("Try 'ls --help' for more information.\n");
            return 2;
        }
    };
    let tty = ctx.stdout_tty().is_some();
    let color = match p.value('c') {
        Some("always") | Some("yes") | Some("force") => true,
        Some("never") | Some("no") | Some("none") => false,
        Some("auto") | Some("tty") | Some("if-tty") => tty,
        Some(other) => {
            let o = other.to_string();
            ctx.fail(alloc::format!("invalid argument '{o}' for '--color'"));
            return 2;
        }
        None => tty && ctx.env("TERM").is_none_or(|t| t != "dumb"),
    };
    let o = LsOpts {
        all: p.has('a'),
        almost_all: p.has('A'),
        long: p.has('l') || p.has('n'),
        human: p.has('h'),
        one: p.has('1'),
        dir_itself: p.has('d'),
        recursive: p.has('R'),
        reverse: p.has('r'),
        by_time: p.has('t'),
        by_size: p.has('S'),
        unsorted: p.has('U'),
        inode: p.has('i'),
        classify: p.has('F'),
        numeric: p.has('n'),
        color,
        columns: (tty && !p.has('1')) || p.has('C'),
    };
    let names = NameCache::new();
    let mut operands = p.operands.clone();
    if operands.is_empty() {
        operands.push(String::from("."));
    }
    let fsctx = ctx.fs();
    let mut status = 0;
    let mut files: Vec<Entry> = Vec::new();
    let mut dirs: Vec<(String, String)> = Vec::new();
    for op in &operands {
        // Like GNU ls: operands that are symlinks are followed unless -l or -d.
        match ops::stat(&fsctx, op, !o.long && !o.dir_itself) {
            Ok(m) => {
                let follow = ops::stat(&fsctx, op, true).ok();
                let is_dir = follow.as_ref().is_some_and(|f| f.kind == FileType::Directory);
                if is_dir && !o.dir_itself && !(o.long && m.kind == FileType::Symlink) {
                    dirs.push((op.clone(), op.clone()));
                } else {
                    files.push(make_entry(&fsctx, op.clone(), op.clone(), Some(m)));
                }
            }
            Err(e) => {
                ctx.eprint(&alloc::format!("ls: cannot access '{op}': {e}\n"));
                status = 2;
            }
        }
    }
    let multiple = operands.len() > 1 || o.recursive;
    let mut printed = false;
    if !files.is_empty() {
        sort_entries(&mut files, &o);
        print_entries(ctx, &files, &o, &names, false);
        printed = true;
    }
    sort_dirs(&fsctx, &mut dirs, &o);
    let mut queue: Vec<(String, String)> = dirs;
    queue.reverse();
    while let Some((label, path)) = queue.pop() {
        if ctx.should_stop() {
            return 130;
        }
        if printed {
            ctx.print("\n");
        }
        if multiple {
            outln!(ctx, "{}:", label);
        }
        printed = true;
        let list = match ops::list_dir(&fsctx, &path) {
            Ok(l) => l,
            Err(e) => {
                ctx.eprint(&alloc::format!("ls: cannot open directory '{path}': {e}\n"));
                status = 2;
                continue;
            }
        };
        let mut entries: Vec<Entry> = Vec::new();
        if o.all {
            for dot in [".", ".."] {
                let p = join(&path, dot);
                let m = ops::stat(&fsctx, &p, false).ok();
                entries.push(Entry { name: dot.to_string(), path: p, meta: m, target: None, target_meta: None });
            }
        }
        for e in list {
            if e.name.starts_with('.') && !o.all && !o.almost_all {
                continue;
            }
            let p = join(&path, &e.name);
            let m = ops::stat(&fsctx, &p, false).ok();
            entries.push(make_entry(&fsctx, e.name, p, m));
        }
        sort_entries(&mut entries, &o);
        print_entries(ctx, &entries, &o, &names, true);
        if o.recursive {
            let mut subs: Vec<(String, String)> = entries
                .iter()
                .filter(|e| e.name != "." && e.name != ".." && e.meta.as_ref().is_some_and(|m| m.kind == FileType::Directory))
                .map(|e| (join(&label, &e.name), e.path.clone()))
                .collect();
            subs.reverse();
            queue.extend(subs);
        }
    }
    status
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        alloc::format!("{dir}{name}")
    } else {
        alloc::format!("{dir}/{name}")
    }
}

fn make_entry(fsctx: &ops::Ctx, name: String, path: String, meta: Option<Metadata>) -> Entry {
    let (target, target_meta) = match &meta {
        Some(m) if m.kind == FileType::Symlink => (ops::readlink(fsctx, &path).ok(), ops::stat(fsctx, &path, true).ok()),
        _ => (None, None),
    };
    Entry { name, path, meta, target, target_meta }
}

fn sort_dirs(fsctx: &ops::Ctx, dirs: &mut [(String, String)], o: &LsOpts) {
    if o.unsorted {
        return;
    }
    dirs.sort_by(|a, b| a.0.cmp(&b.0));
    if o.by_time {
        dirs.sort_by_key(|d| core::cmp::Reverse(ops::stat(fsctx, &d.1, true).map(|m| m.mtime).unwrap_or_default()));
    }
    if o.reverse {
        dirs.reverse();
    }
}

fn sort_entries(v: &mut [Entry], o: &LsOpts) {
    if o.unsorted {
        return;
    }
    v.sort_by(|a, b| a.name.cmp(&b.name));
    if o.by_size {
        v.sort_by_key(|e| core::cmp::Reverse(e.meta.as_ref().map(|m| m.size).unwrap_or(0)));
    } else if o.by_time {
        v.sort_by_key(|e| core::cmp::Reverse(e.meta.as_ref().map(|m| m.mtime).unwrap_or_default()));
    }
    if o.reverse {
        v.reverse();
    }
}

fn indicator(m: &Metadata) -> &'static str {
    match m.kind {
        FileType::Directory => "/",
        FileType::Symlink => "@",
        FileType::Fifo => "|",
        FileType::Socket => "=",
        FileType::Regular if m.perm & 0o111 != 0 => "*",
        _ => "",
    }
}

fn display_name(e: &Entry, o: &LsOpts) -> (String, usize) {
    let mut w = fmtutil::width(&e.name);
    let mut s = match (&e.meta, o.color) {
        (Some(m), true) => fmtutil::colorize(&e.name, fmtutil::ls_color(&e.name, m, e.target_meta.is_some())),
        _ => e.name.clone(),
    };
    if o.classify {
        if let Some(m) = &e.meta {
            let ind = indicator(m);
            s.push_str(ind);
            w += ind.len();
        }
    }
    (s, w)
}

fn print_entries(ctx: &mut Ctx, entries: &[Entry], o: &LsOpts, names: &NameCache, is_dir_listing: bool) {
    if o.long {
        print_long(ctx, entries, o, names, is_dir_listing);
        return;
    }
    let items: Vec<(String, usize)> = entries
        .iter()
        .map(|e| {
            let (s, w) = display_name(e, o);
            if o.inode {
                let ino = e.meta.as_ref().map(|m| m.ino).unwrap_or(0).to_string();
                (alloc::format!("{ino} {s}"), w + ino.len() + 1)
            } else {
                (s, w)
            }
        })
        .collect();
    if o.columns && !o.one {
        let (cols, _) = ctx.term_size();
        for line in fmtutil::columns(&items, cols) {
            outln!(ctx, "{}", line);
        }
    } else {
        for (s, _) in items {
            outln!(ctx, "{}", s);
        }
    }
}

fn print_long(ctx: &mut Ctx, entries: &[Entry], o: &LsOpts, names: &NameCache, is_dir_listing: bool) {
    struct Row {
        ino: String,
        mode: String,
        links: String,
        user: String,
        group: String,
        size: String,
        time: String,
        name: String,
    }
    let mut total_blocks = 0u64;
    let mut rows = Vec::new();
    for e in entries {
        let Some(m) = &e.meta else { continue };
        total_blocks += m.blocks;
        let size = if matches!(m.kind, FileType::CharDevice | FileType::BlockDevice) {
            alloc::format!("{}, {}", crate::fs::major(m.rdev), crate::fs::minor(m.rdev))
        } else if o.human {
            human(m.size)
        } else {
            m.size.to_string()
        };
        let (mut name, _) = display_name(e, o);
        if let Some(t) = &e.target {
            let tshown = match (&e.target_meta, o.color) {
                (Some(tm), true) => fmtutil::colorize(t, fmtutil::ls_color(t, tm, true)),
                _ => t.clone(),
            };
            name = alloc::format!("{name} -> {tshown}");
        }
        rows.push(Row {
            ino: m.ino.to_string(),
            mode: fmtutil::mode_string(m),
            links: m.nlink.to_string(),
            user: if o.numeric { m.uid.to_string() } else { names.user(m.uid) },
            group: if o.numeric { m.gid.to_string() } else { names.group(m.gid) },
            size,
            time: fmtutil::ls_time(m.mtime.sec),
            name,
        });
    }
    if is_dir_listing {
        let kb = if o.human { human(total_blocks * 512) } else { (total_blocks / 2).to_string() };
        outln!(ctx, "total {}", kb);
    }
    let w = |f: &dyn Fn(&Row) -> usize| rows.iter().map(f).max().unwrap_or(0);
    let wi = w(&|r| r.ino.len());
    let wl = w(&|r| r.links.len());
    let wu = w(&|r| fmtutil::width(&r.user));
    let wg = w(&|r| fmtutil::width(&r.group));
    let ws = w(&|r| r.size.len());
    for r in rows {
        if o.inode {
            out!(ctx, "{} ", fmtutil::pad_left(&r.ino, wi));
        }
        outln!(
            ctx,
            "{} {} {} {} {} {} {}",
            r.mode,
            fmtutil::pad_left(&r.links, wl),
            fmtutil::pad_right(&r.user, wu),
            fmtutil::pad_right(&r.group, wg),
            fmtutil::pad_left(&r.size, ws),
            r.time,
            r.name
        );
    }
}

// ── basename / dirname ────────────────────────────────────────────────────

pub fn basename(ctx: &mut Ctx) -> i32 {
    let args: Vec<String> = ctx.args[1..].to_vec();
    let (multi, suffix, names): (bool, Option<String>, Vec<String>) = match args.first().map(|s| s.as_str()) {
        Some("-a") => (true, None, args[1..].to_vec()),
        Some("-s") if args.len() >= 2 => (true, Some(args[1].clone()), args[2..].to_vec()),
        _ => (false, args.get(1).cloned(), args.get(..1).map(|v| v.to_vec()).unwrap_or_default()),
    };
    if names.is_empty() || (!multi && args.len() > 2) {
        if args.len() > 2 && !multi {
            return ctx.fail(alloc::format!("extra operand '{}'", args[2]));
        }
        return ctx.fail("missing operand");
    }
    for n in names {
        let trimmed = n.trim_end_matches('/');
        let mut b = if trimmed.is_empty() && n.starts_with('/') { "/" } else { trimmed.rsplit('/').next().unwrap_or("") }.to_string();
        if let Some(s) = &suffix {
            if b.len() > s.len() && b.ends_with(s.as_str()) {
                b.truncate(b.len() - s.len());
            }
        }
        outln!(ctx, "{}", b);
    }
    0
}

pub fn dirname(ctx: &mut Ctx) -> i32 {
    if ctx.args.len() < 2 {
        return ctx.fail("missing operand");
    }
    for n in ctx.args[1..].to_vec() {
        let t = n.trim_end_matches('/');
        let d = if t.is_empty() && n.starts_with('/') {
            "/".to_string()
        } else {
            match t.rfind('/') {
                Some(0) => "/".to_string(),
                Some(i) => t[..i].trim_end_matches('/').to_string().chars().collect::<String>(),
                None => ".".to_string(),
            }
        };
        let d = if d.is_empty() { "/".to_string() } else { d };
        outln!(ctx, "{}", d);
    }
    0
}
