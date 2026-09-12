//! Commands that create, copy, move, remove and modify files.

use super::fmtutil;
use crate::errno::Errno;
use crate::fs::file::flags;
use crate::fs::ops::{self, Ctx as FsCtx};
use crate::fs::{FileType, Metadata, Timespec};
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use crate::{out, outln};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

fn q(s: &str) -> String {
    alloc::format!("'{s}'")
}

fn basename(p: &str) -> &str {
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "/";
    }
    t.rsplit('/').next().unwrap_or(t)
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        alloc::format!("{dir}{name}")
    } else {
        alloc::format!("{dir}/{name}")
    }
}

fn is_dir(fs: &FsCtx, p: &str) -> bool {
    ops::stat(fs, p, true).is_ok_and(|m| m.kind == FileType::Directory)
}

/// Ask a yes/no question on stderr, read the answer from stdin.
fn confirm(ctx: &mut Ctx, question: &str) -> bool {
    ctx.eprint(question);
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while let Ok(1) = ctx.read_stdin(&mut b) {
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
    }
    matches!(line.first(), Some(b'y') | Some(b'Y'))
}

// ── mkdir / rmdir ──────────────────────────────────────────────────────────

pub fn mkdir(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "pv", values: "m", long: &[("parents", 'p', false), ("verbose", 'v', false), ("mode", 'm', true)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    if p.operands.is_empty() {
        ctx.fail("missing operand");
        ctx.eprint("Try 'mkdir --help' for more information.\n");
        return 1;
    }
    let mode = match p.value('m') {
        Some(m) => match parse_mode(m, 0o777, true) {
            Some(v) => Some(v),
            None => return ctx.fail(alloc::format!("invalid mode {}", q(m))),
        },
        None => None,
    };
    let fs = ctx.fs();
    let mut st = 0;
    for d in p.operands.clone() {
        let r = if p.has('p') {
            // Report each directory created along the way with -v.
            let mut created = Vec::new();
            let mut cur = String::new();
            let mut res = Ok(());
            if d.starts_with('/') {
                cur.push('/');
            }
            for comp in d.split('/').filter(|c| !c.is_empty()) {
                if !cur.is_empty() && !cur.ends_with('/') {
                    cur.push('/');
                }
                cur.push_str(comp);
                match ops::mkdir(&fs, &cur, 0o777) {
                    Ok(()) => created.push(cur.clone()),
                    Err(Errno::EEXIST) if is_dir(&fs, &cur) => {}
                    Err(Errno::EEXIST) => {
                        res = Err(Errno::EEXIST);
                        break;
                    }
                    Err(e) => {
                        res = Err(e);
                        break;
                    }
                }
            }
            if p.has('v') {
                for c in &created {
                    outln!(ctx, "mkdir: created directory {}", q(c));
                }
            }
            res
        } else {
            let r = ops::mkdir(&fs, &d, mode.unwrap_or(0o777));
            if r.is_ok() && p.has('v') {
                outln!(ctx, "mkdir: created directory {}", q(&d));
            }
            r
        };
        match r {
            Ok(()) => {
                if let Some(m) = mode {
                    let _ = ops::chmod(&fs, &d, m, true);
                }
            }
            Err(e) => {
                ctx.eprint(&alloc::format!("mkdir: cannot create directory {}: {}\n", q(&d), e));
                st = 1;
            }
        }
    }
    st
}

pub fn rmdir(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "pv", values: "", long: &[("parents", 'p', false), ("verbose", 'v', false), ("ignore-fail-on-non-empty", 'i', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    if p.operands.is_empty() {
        return ctx.fail("missing operand");
    }
    let fs = ctx.fs();
    let mut st = 0;
    for d in p.operands.clone() {
        let mut cur = d.trim_end_matches('/').to_string();
        loop {
            if p.has('v') {
                outln!(ctx, "rmdir: removing directory, {}", q(&cur));
            }
            match ops::rmdir(&fs, &cur) {
                Ok(()) => {}
                Err(Errno::ENOTEMPTY) if p.has('i') => break,
                Err(e) => {
                    ctx.eprint(&alloc::format!("rmdir: failed to remove {}: {}\n", q(&cur), e));
                    st = 1;
                    break;
                }
            }
            if !p.has('p') {
                break;
            }
            match cur.rfind('/') {
                Some(i) if i > 0 => cur.truncate(i),
                _ => break,
            }
        }
    }
    st
}

// ── touch ──────────────────────────────────────────────────────────────────

/// `2026-09-11 07:14:05`, `2026-09-11`, `@1789000000`.
fn parse_datetime(s: &str) -> Option<i64> {
    if let Some(n) = s.strip_prefix('@') {
        return n.parse().ok();
    }
    let s = s.trim();
    let (date, time) = s.split_once([' ', 'T']).unwrap_or((s, "00:00:00"));
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let mo: u32 = d.next()?.parse().ok()?;
    let da: u32 = d.next()?.parse().ok()?;
    let mut t = time.split(':');
    let h: i64 = t.next().unwrap_or("0").parse().ok()?;
    let mi: i64 = t.next().unwrap_or("0").parse().ok()?;
    let se: i64 = t.next().unwrap_or("0").split('.').next()?.parse().ok()?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(crate::time::civil::days_from_civil(y, mo, da) * 86400 + h * 3600 + mi * 60 + se)
}

pub fn touch(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "acmh",
        values: "drt",
        long: &[("no-create", 'c', false), ("date", 'd', true), ("reference", 'r', true), ("no-dereference", 'h', false)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    if p.operands.is_empty() {
        return ctx.fail("missing file operand");
    }
    let fs = ctx.fs();
    let time = if let Some(d) = p.value('d') {
        match parse_datetime(d) {
            Some(t) => Timespec::from_secs(t),
            None => return ctx.fail(alloc::format!("invalid date format {}", q(d))),
        }
    } else if let Some(r) = p.value('r') {
        match ops::stat(&fs, r, true) {
            Ok(m) => m.mtime,
            Err(e) => return ctx.fail(alloc::format!("failed to get attributes of {}: {}", q(r), e)),
        }
    } else if let Some(t) = p.value('t') {
        // [[CC]YY]MMDDhhmm[.ss]
        let (main, secs) = t.split_once('.').unwrap_or((t, "0"));
        let digits = main.len();
        let parse = |s: &str| s.parse::<i64>().ok();
        let r = (|| -> Option<i64> {
            let (y, rest) = match digits {
                12 => (parse(&main[..4])?, &main[4..]),
                10 => (2000 + parse(&main[..2])?, &main[2..]),
                8 => (crate::time::civil::from_unix(crate::time::unix_now() as i64).year, main),
                _ => return None,
            };
            let mo = parse(&rest[0..2])? as u32;
            let d = parse(&rest[2..4])? as u32;
            let h = parse(&rest[4..6])?;
            let mi = parse(&rest[6..8])?;
            Some(crate::time::civil::days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + parse(secs)?)
        })();
        match r {
            Some(t) => Timespec::from_secs(t),
            None => return ctx.fail(alloc::format!("invalid date format {}", q(t))),
        }
    } else {
        Timespec::now()
    };
    let only_a = p.has('a') && !p.has('m');
    let only_m = p.has('m') && !p.has('a');
    let mut st = 0;
    for f in p.operands.clone() {
        if ops::stat(&fs, &f, !p.has('h')).is_err() {
            if p.has('c') {
                continue;
            }
            match ops::open(&fs, &f, flags::O_WRONLY | flags::O_CREAT, 0o666) {
                Ok(_) => {}
                Err(e) => {
                    ctx.eprint(&alloc::format!("touch: cannot touch {}: {}\n", q(&f), e));
                    st = 1;
                    continue;
                }
            }
        }
        let (a, m) = (if only_m { None } else { Some(time) }, if only_a { None } else { Some(time) });
        if let Err(e) = ops::utimes(&fs, &f, a, m, !p.has('h')) {
            ctx.eprint(&alloc::format!("touch: setting times of {}: {}\n", q(&f), e));
            st = 1;
        }
    }
    st
}

// ── rm ─────────────────────────────────────────────────────────────────────

pub fn rm(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "rRfivd",
        values: "",
        long: &[("recursive", 'r', false), ("force", 'f', false), ("interactive", 'i', false), ("verbose", 'v', false), ("dir", 'd', false), ("no-preserve-root", 'N', false)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let force = p.has('f');
    if p.operands.is_empty() {
        if force {
            return 0;
        }
        ctx.fail("missing operand");
        ctx.eprint("Try 'rm --help' for more information.\n");
        return 1;
    }
    let recursive = p.has('r') || p.has('R');
    let fs = ctx.fs();
    let mut st = 0;
    for f in p.operands.clone() {
        let name = basename(&f);
        if name == "." || name == ".." {
            ctx.eprint(&alloc::format!("rm: refusing to remove '.' or '..' directory: skipping {}\n", q(&f)));
            st = 1;
            continue;
        }
        if f.trim_end_matches('/').is_empty() && !p.has('N') {
            ctx.eprint("rm: it is dangerous to operate recursively on '/'\nrm: use --no-preserve-root to override this failsafe\n");
            st = 1;
            continue;
        }
        let meta = match ops::stat(&fs, &f, false) {
            Ok(m) => m,
            Err(e) => {
                if !(force && e == Errno::ENOENT) {
                    ctx.eprint(&alloc::format!("rm: cannot remove {}: {}\n", q(&f), e));
                    st = 1;
                }
                continue;
            }
        };
        if meta.kind == FileType::Directory {
            if !recursive {
                if p.has('d') {
                    match ops::rmdir(&fs, &f) {
                        Ok(()) => {
                            if p.has('v') {
                                outln!(ctx, "removed directory {}", q(&f));
                            }
                        }
                        Err(e) => {
                            ctx.eprint(&alloc::format!("rm: cannot remove {}: {}\n", q(&f), e));
                            st = 1;
                        }
                    }
                    continue;
                }
                ctx.eprint(&alloc::format!("rm: cannot remove {}: Is a directory\n", q(&f)));
                st = 1;
                continue;
            }
            if !remove_recursive(ctx, &fs, &f, p.has('v'), p.has('i'), force) {
                st = 1;
            }
            continue;
        }
        if p.has('i') && !confirm(ctx, &alloc::format!("rm: remove file {}? ", q(&f))) {
            continue;
        }
        match ops::unlink(&fs, &f) {
            Ok(()) => {
                if p.has('v') {
                    outln!(ctx, "removed {}", q(&f));
                }
            }
            Err(e) => {
                ctx.eprint(&alloc::format!("rm: cannot remove {}: {}\n", q(&f), e));
                st = 1;
            }
        }
    }
    st
}

fn remove_recursive(ctx: &mut Ctx, fs: &FsCtx, path: &str, verbose: bool, interactive: bool, force: bool) -> bool {
    if ctx.should_stop() {
        return false;
    }
    if interactive && !confirm(ctx, &alloc::format!("rm: descend into directory {}? ", q(path))) {
        return true;
    }
    let entries = match ops::list_dir(fs, path) {
        Ok(e) => e,
        Err(e) => {
            ctx.eprint(&alloc::format!("rm: cannot remove {}: {}\n", q(path), e));
            return false;
        }
    };
    let mut ok = true;
    for e in entries {
        let child = join(path, &e.name);
        let is_dir = ops::stat(fs, &child, false).is_ok_and(|m| m.kind == FileType::Directory);
        if is_dir {
            ok &= remove_recursive(ctx, fs, &child, verbose, interactive, force);
        } else {
            if interactive && !confirm(ctx, &alloc::format!("rm: remove file {}? ", q(&child))) {
                continue;
            }
            match ops::unlink(fs, &child) {
                Ok(()) => {
                    if verbose {
                        outln!(ctx, "removed {}", q(&child));
                    }
                }
                Err(err) => {
                    ctx.eprint(&alloc::format!("rm: cannot remove {}: {}\n", q(&child), err));
                    ok = false;
                }
            }
        }
    }
    match ops::rmdir(fs, path) {
        Ok(()) => {
            if verbose {
                outln!(ctx, "removed directory {}", q(path));
            }
        }
        Err(e) => {
            if !(force && e == Errno::ENOENT) {
                ctx.eprint(&alloc::format!("rm: cannot remove {}: {}\n", q(path), e));
                ok = false;
            }
        }
    }
    ok
}

// ── cp / mv ────────────────────────────────────────────────────────────────

struct CpOpts {
    recursive: bool,
    preserve: bool,
    force: bool,
    interactive: bool,
    no_clobber: bool,
    verbose: bool,
    deref: bool,
    update: bool,
    hard_link: bool,
    symlink: bool,
}

fn copy_file_data(fs: &FsCtx, src: &str, dst: &str, mode: u16, force: bool) -> Result<(), String> {
    let inf = ops::open(fs, src, flags::O_RDONLY, 0).map_err(|e| alloc::format!("cannot open {} for reading: {}", q(src), e))?;
    let outf = match ops::open(fs, dst, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC, mode) {
        Ok(f) => f,
        Err(Errno::EACCES) if force => {
            let _ = ops::unlink(fs, dst);
            ops::open(fs, dst, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC, mode).map_err(|e| alloc::format!("cannot create regular file {}: {}", q(dst), e))?
        }
        Err(e) => return Err(alloc::format!("cannot create regular file {}: {}", q(dst), e)),
    };
    let mut buf = alloc::vec![0u8; 64 * 1024];
    loop {
        if crate::proc::interrupted() {
            return Err(String::from("interrupted"));
        }
        let n = inf.read(&mut buf).map_err(|e| alloc::format!("error reading {}: {}", q(src), e))?;
        if n == 0 {
            break;
        }
        outf.write_all(&buf[..n]).map_err(|e| alloc::format!("error writing {}: {}", q(dst), e))?;
    }
    Ok(())
}

fn preserve_attrs(fs: &FsCtx, dst: &str, m: &Metadata, follow: bool) {
    let _ = ops::chown(fs, dst, Some(m.uid), Some(m.gid), follow);
    if m.kind != FileType::Symlink {
        let _ = ops::chmod(fs, dst, m.perm, follow);
    }
    let _ = ops::utimes(fs, dst, Some(m.atime), Some(m.mtime), follow);
}

fn copy_one(ctx: &mut Ctx, fs: &FsCtx, src: &str, dst: &str, o: &CpOpts) -> bool {
    let m = match ops::stat(fs, src, o.deref) {
        Ok(m) => m,
        Err(e) => {
            ctx.eprint(&alloc::format!("cp: cannot stat {}: {}\n", q(src), e));
            return false;
        }
    };
    if let Ok(dm) = ops::stat(fs, dst, true) {
        if dm.dev == m.dev && dm.ino == m.ino {
            ctx.eprint(&alloc::format!("cp: {} and {} are the same file\n", q(src), q(dst)));
            return false;
        }
        if m.kind != FileType::Directory {
            if o.no_clobber {
                return true;
            }
            if o.update && dm.mtime >= m.mtime {
                return true;
            }
            if o.interactive && !confirm(ctx, &alloc::format!("cp: overwrite {}? ", q(dst))) {
                return true;
            }
        }
    }
    if o.hard_link && m.kind != FileType::Directory {
        return match ops::link(fs, src, dst) {
            Ok(()) => true,
            Err(e) => {
                ctx.eprint(&alloc::format!("cp: cannot create hard link {} to {}: {}\n", q(dst), q(src), e));
                false
            }
        };
    }
    if o.symlink && m.kind != FileType::Directory {
        return match ops::symlink(fs, src, dst) {
            Ok(()) => true,
            Err(e) => {
                ctx.eprint(&alloc::format!("cp: cannot create symbolic link {}: {}\n", q(dst), e));
                false
            }
        };
    }
    match m.kind {
        FileType::Directory => {
            if !o.recursive {
                ctx.eprint(&alloc::format!("cp: -r not specified; omitting directory {}\n", q(src)));
                return false;
            }
            // Refuse to copy a directory into itself.
            if let (Ok(s), Ok(d)) = (fs.resolve(src, true), fs.resolve(crate::shell::builtins::normalize(&alloc::format!("{}/{}", ctx.cwd(), dst)).as_str(), true).or_else(|_| fs.resolve_parent(dst).map(|(p, _)| p))) {
                let sp = s.path();
                let dp = d.path();
                if dp == sp || dp.starts_with(&(sp.clone() + "/")) {
                    ctx.eprint(&alloc::format!("cp: cannot copy a directory, {}, into itself, {}\n", q(src), q(dst)));
                    return false;
                }
            }
            match ops::mkdir(fs, dst, 0o700) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(e) => {
                    ctx.eprint(&alloc::format!("cp: cannot create directory {}: {}\n", q(dst), e));
                    return false;
                }
            }
            if o.verbose {
                outln!(ctx, "{} -> {}", q(src), q(dst));
            }
            let entries = match ops::list_dir(fs, src) {
                Ok(e) => e,
                Err(e) => {
                    ctx.eprint(&alloc::format!("cp: cannot access {}: {}\n", q(src), e));
                    return false;
                }
            };
            let mut ok = true;
            let child_opts = CpOpts { deref: false, ..*o };
            for e in entries {
                if ctx.should_stop() {
                    return false;
                }
                ok &= copy_one(ctx, fs, &join(src, &e.name), &join(dst, &e.name), &child_opts);
            }
            if o.preserve {
                preserve_attrs(fs, dst, &m, true);
            } else {
                let umask = ctx.proc.fs.lock().umask; // drop the lock before chmod may block
                let _ = ops::chmod(fs, dst, m.perm & !umask, true);
            }
            ok
        }
        FileType::Symlink => {
            let target = ops::readlink(fs, src).unwrap_or_default();
            let _ = ops::unlink(fs, dst);
            match ops::symlink(fs, &target, dst) {
                Ok(()) => {
                    if o.verbose {
                        outln!(ctx, "{} -> {}", q(src), q(dst));
                    }
                    if o.preserve {
                        let _ = ops::chown(fs, dst, Some(m.uid), Some(m.gid), false);
                    }
                    true
                }
                Err(e) => {
                    ctx.eprint(&alloc::format!("cp: cannot create symbolic link {}: {}\n", q(dst), e));
                    false
                }
            }
        }
        FileType::Fifo | FileType::CharDevice | FileType::BlockDevice | FileType::Socket if !o.deref || m.kind == FileType::Fifo => {
            match ops::mknod(fs, dst, m.kind, m.perm, m.rdev) {
                Ok(()) => true,
                Err(e) => {
                    ctx.eprint(&alloc::format!("cp: cannot create special file {}: {}\n", q(dst), e));
                    false
                }
            }
        }
        _ => {
            if let Err(msg) = copy_file_data(fs, src, dst, m.perm & 0o777, o.force) {
                ctx.eprint(&alloc::format!("cp: {msg}\n"));
                return false;
            }
            if o.preserve {
                preserve_attrs(fs, dst, &m, true);
            }
            if o.verbose {
                outln!(ctx, "{} -> {}", q(src), q(dst));
            }
            true
        }
    }
}

impl Clone for CpOpts {
    fn clone(&self) -> Self {
        *self
    }
}
impl Copy for CpOpts {}

pub fn cp(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "rRapfinvLPHdlsu",
        values: "t",
        long: &[
            ("recursive", 'r', false),
            ("archive", 'a', false),
            ("force", 'f', false),
            ("interactive", 'i', false),
            ("no-clobber", 'n', false),
            ("verbose", 'v', false),
            ("dereference", 'L', false),
            ("no-dereference", 'P', false),
            ("link", 'l', false),
            ("symbolic-link", 's', false),
            ("update", 'u', false),
            ("target-directory", 't', true),
            ("preserve", 'p', false),
        ],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let o = CpOpts {
        recursive: p.has('r') || p.has('R') || p.has('a'),
        preserve: p.has('p') || p.has('a'),
        force: p.has('f'),
        interactive: p.has('i'),
        no_clobber: p.has('n'),
        verbose: p.has('v'),
        deref: !(p.has('P') || p.has('a') || p.has('d')) || p.has('L'),
        update: p.has('u'),
        hard_link: p.has('l'),
        symlink: p.has('s'),
    };
    transfer(ctx, &p.operands, p.value('t'), "cp", |ctx, fs, s, d| copy_one(ctx, fs, s, d, &o))
}

/// Shared operand handling of cp/mv: `SRC DST`, `SRC... DIR`, `-t DIR SRC...`.
fn transfer(ctx: &mut Ctx, operands: &[String], target: Option<&str>, name: &str, mut f: impl FnMut(&mut Ctx, &FsCtx, &str, &str) -> bool) -> i32 {
    let fs = ctx.fs();
    let (sources, dest): (Vec<String>, String) = match target {
        Some(t) => (operands.to_vec(), t.to_string()),
        None => {
            if operands.len() < 2 {
                if operands.is_empty() {
                    ctx.eprint(&alloc::format!("{name}: missing file operand\n"));
                } else {
                    ctx.eprint(&alloc::format!("{name}: missing destination file operand after {}\n", q(&operands[0])));
                }
                ctx.eprint(&alloc::format!("Try '{name} --help' for more information.\n"));
                return 1;
            }
            (operands[..operands.len() - 1].to_vec(), operands[operands.len() - 1].clone())
        }
    };
    let dest_is_dir = is_dir(&fs, &dest);
    if sources.len() > 1 && !dest_is_dir {
        ctx.eprint(&alloc::format!("{name}: target {} is not a directory\n", q(&dest)));
        return 1;
    }
    let mut st = 0;
    for s in sources {
        let d = if dest_is_dir { join(&dest, basename(&s)) } else { dest.clone() };
        if !f(ctx, &fs, &s, &d) {
            st = 1;
        }
        if ctx.should_stop() {
            return 130;
        }
    }
    st
}

pub fn mv(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "finvuT",
        values: "t",
        long: &[("force", 'f', false), ("interactive", 'i', false), ("no-clobber", 'n', false), ("verbose", 'v', false), ("update", 'u', false), ("target-directory", 't', true)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let (verbose, no_clobber, interactive, update) = (p.has('v'), p.has('n'), p.has('i') && !p.has('f'), p.has('u'));
    transfer(ctx, &p.operands, p.value('t'), "mv", |ctx, fs, s, d| {
        let sm = match ops::stat(fs, s, false) {
            Ok(m) => m,
            Err(e) => {
                ctx.eprint(&alloc::format!("mv: cannot stat {}: {}\n", q(s), e));
                return false;
            }
        };
        if let Ok(dm) = ops::stat(fs, d, false) {
            if dm.dev == sm.dev && dm.ino == sm.ino {
                ctx.eprint(&alloc::format!("mv: {} and {} are the same file\n", q(s), q(d)));
                return false;
            }
            if no_clobber || (update && dm.mtime >= sm.mtime) {
                return true;
            }
            if interactive && !confirm(ctx, &alloc::format!("mv: overwrite {}? ", q(d))) {
                return true;
            }
        }
        match ops::rename(fs, s, d) {
            Ok(()) => {}
            Err(Errno::EXDEV) => {
                // Across filesystems: copy then remove.
                let o = CpOpts { recursive: true, preserve: true, force: true, interactive: false, no_clobber: false, verbose: false, deref: false, update: false, hard_link: false, symlink: false };
                if !copy_one(ctx, fs, s, d, &o) {
                    return false;
                }
                if let Err(e) = ops::remove_tree(fs, s) {
                    ctx.eprint(&alloc::format!("mv: cannot remove {}: {}\n", q(s), e));
                    return false;
                }
            }
            Err(Errno::EINVAL) if sm.kind == FileType::Directory => {
                ctx.eprint(&alloc::format!("mv: cannot move {} to a subdirectory of itself, {}\n", q(s), q(d)));
                return false;
            }
            Err(e) => {
                ctx.eprint(&alloc::format!("mv: cannot move {} to {}: {}\n", q(s), q(d), e));
                return false;
            }
        }
        if verbose {
            outln!(ctx, "renamed {} -> {}", q(s), q(d));
        }
        true
    })
}

// ── ln ─────────────────────────────────────────────────────────────────────

pub fn ln(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "sfvnrT",
        values: "t",
        long: &[("symbolic", 's', false), ("force", 'f', false), ("verbose", 'v', false), ("no-dereference", 'n', false), ("relative", 'r', false), ("target-directory", 't', true)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let fs = ctx.fs();
    let ops_list: Vec<String> = p.operands.clone();
    let (targets, dest) = match (p.value('t'), ops_list.len()) {
        (Some(t), _) => (ops_list.clone(), Some(t.to_string())),
        (None, 0) => return ctx.fail("missing file operand"),
        (None, 1) => (ops_list.clone(), None),
        (None, _) => (ops_list[..ops_list.len() - 1].to_vec(), Some(ops_list[ops_list.len() - 1].clone())),
    };
    let dest_dir = dest.as_ref().is_some_and(|d| !p.has('n') && is_dir(&fs, d) || (p.has('n') && ops::stat(&fs, d, false).is_ok_and(|m| m.kind == FileType::Directory)));
    if targets.len() > 1 && !dest_dir {
        return ctx.fail(alloc::format!("target {} is not a directory", q(dest.as_deref().unwrap_or(""))));
    }
    let mut st = 0;
    for t in targets {
        let link = match &dest {
            Some(d) if dest_dir => join(d, basename(&t)),
            Some(d) => d.clone(),
            None => basename(&t).to_string(),
        };
        if p.has('f') {
            let _ = ops::unlink(&fs, &link);
        }
        let r = if p.has('s') { ops::symlink(&fs, &t, &link) } else { ops::link(&fs, &t, &link) };
        match r {
            Ok(()) => {
                if p.has('v') {
                    outln!(ctx, "{} -> {}", q(&link), q(&t));
                }
            }
            Err(e) => {
                let kind = if p.has('s') { "symbolic link" } else { "hard link" };
                if p.has('s') {
                    ctx.eprint(&alloc::format!("ln: failed to create {} {}: {}\n", kind, q(&link), e));
                } else {
                    ctx.eprint(&alloc::format!("ln: failed to create {} {} => {}: {}\n", kind, q(&link), q(&t), e));
                }
                st = 1;
            }
        }
    }
    st
}

// ── chmod / chown / chgrp ──────────────────────────────────────────────────

/// Apply an octal or symbolic mode (`u+x,go-w`, `a=r`, `+x`, `g=u`) to `cur`.
pub fn parse_mode(spec: &str, cur: u16, is_dir: bool) -> Option<u16> {
    if !spec.is_empty() && spec.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        let v = u16::from_str_radix(spec, 8).ok()?;
        if v > 0o7777 {
            return None;
        }
        // Like GNU: short octal modes on directories keep setuid/setgid.
        let keep = if is_dir && spec.len() < 5 { cur & 0o6000 } else { 0 };
        return Some(v | keep);
    }
    let umask = 0o022u16;
    let mut mode = cur;
    for clause in spec.split(',') {
        let b = clause.as_bytes();
        let mut i = 0;
        let mut who = 0u16;
        while i < b.len() && b"ugoa".contains(&b[i]) {
            who |= match b[i] {
                b'u' => 0o4700,
                b'g' => 0o2070,
                b'o' => 0o1007,
                _ => 0o7777,
            };
            i += 1;
        }
        let who_given = who != 0;
        if !who_given {
            who = 0o7777;
        }
        if i >= b.len() {
            return None;
        }
        while i < b.len() {
            let op = b[i];
            if !b"+-=".contains(&op) {
                return None;
            }
            i += 1;
            let mut perm = 0u16;
            // Copy from another class: g=u, o=g ...
            if i < b.len() && b"ugo".contains(&b[i]) {
                let src = match b[i] {
                    b'u' => (mode >> 6) & 7,
                    b'g' => (mode >> 3) & 7,
                    _ => mode & 7,
                };
                perm = src << 6 | src << 3 | src;
                i += 1;
            } else {
                while i < b.len() && b"rwxXst".contains(&b[i]) {
                    perm |= match b[i] {
                        b'r' => 0o444,
                        b'w' => 0o222,
                        b'x' => 0o111,
                        b'X' => {
                            if is_dir || mode & 0o111 != 0 {
                                0o111
                            } else {
                                0
                            }
                        }
                        b's' => 0o6000,
                        _ => 0o1000,
                    };
                    i += 1;
                }
            }
            let mut mask = who & perm;
            if !who_given && op != b'-' {
                // `+w` without `ugoa` honours the umask (POSIX).
                mask &= !umask;
            }
            let class_bits = if who_given { who } else { 0o7777 };
            match op {
                b'+' => mode |= mask,
                b'-' => mode &= !(if who_given { who & perm } else { perm }),
                _ => {
                    let clear = class_bits & 0o0777 | (class_bits & 0o7000 & if perm & 0o7000 != 0 { 0o7777 } else { 0 });
                    mode = (mode & !clear) | mask;
                }
            }
        }
    }
    Some(mode & 0o7777)
}

pub fn chmod(ctx: &mut Ctx) -> i32 {
    // Modes like `-x` look like options: take the first non-option operand as the mode.
    let mut recursive = false;
    let mut verbose = false;
    let mut changes = false;
    let mut quiet = false;
    let mut rest = Vec::new();
    for a in ctx.args[1..].iter() {
        match a.as_str() {
            "-R" | "--recursive" => recursive = true,
            "-v" | "--verbose" => verbose = true,
            "-c" | "--changes" => changes = true,
            "-f" | "--silent" | "--quiet" => quiet = true,
            _ => rest.push(a.clone()),
        }
    }
    if rest.len() < 2 {
        if rest.is_empty() {
            return ctx.fail("missing operand");
        }
        return ctx.fail(alloc::format!("missing operand after {}", q(&rest[0])));
    }
    let spec = rest[0].clone();
    let fs = ctx.fs();
    let mut st = 0;
    for f in rest[1..].to_vec() {
        st |= chmod_one(ctx, &fs, &f, &spec, recursive, verbose, changes, quiet);
    }
    st
}

#[allow(clippy::too_many_arguments)]
fn chmod_one(ctx: &mut Ctx, fs: &FsCtx, path: &str, spec: &str, recursive: bool, verbose: bool, changes: bool, quiet: bool) -> i32 {
    let m = match ops::stat(fs, path, true) {
        Ok(m) => m,
        Err(e) => {
            if !quiet {
                ctx.eprint(&alloc::format!("chmod: cannot access {}: {}\n", q(path), e));
            }
            return 1;
        }
    };
    let Some(new) = parse_mode(spec, m.perm, m.kind == FileType::Directory) else {
        ctx.eprint(&alloc::format!("chmod: invalid mode: {}\n", q(spec)));
        return 1;
    };
    let mut st = 0;
    match ops::chmod(fs, path, new, true) {
        Ok(()) => {
            if verbose || (changes && new != m.perm) {
                let old_s = fmtutil::mode_string(&m);
                let mut nm = m.clone();
                nm.perm = new;
                if new == m.perm {
                    outln!(ctx, "mode of {} retained as {:04o} ({})", q(path), new, &old_s[1..]);
                } else {
                    outln!(ctx, "mode of {} changed from {:04o} ({}) to {:04o} ({})", q(path), m.perm, &old_s[1..], new, &fmtutil::mode_string(&nm)[1..]);
                }
            }
        }
        Err(e) => {
            if !quiet {
                ctx.eprint(&alloc::format!("chmod: changing permissions of {}: {}\n", q(path), e));
            }
            st = 1;
        }
    }
    if recursive && m.kind == FileType::Directory {
        if let Ok(entries) = ops::list_dir(fs, path) {
            for e in entries {
                let child = join(path, &e.name);
                if ops::stat(fs, &child, false).is_ok_and(|m| m.kind == FileType::Symlink) {
                    continue;
                }
                st |= chmod_one(ctx, fs, &child, spec, true, verbose, changes, quiet);
            }
        }
    }
    st
}

fn resolve_owner(spec: &str) -> Result<(Option<u32>, Option<u32>), String> {
    let (u, g) = match spec.split_once([':', '.']) {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let uid = if u.is_empty() {
        None
    } else if let Ok(n) = u.parse::<u32>() {
        Some(n)
    } else {
        Some(crate::users::by_name(u).map(|x| x.uid).ok_or_else(|| alloc::format!("invalid user: {}", q(spec)))?)
    };
    let gid = match g {
        None => None,
        Some("") => {
            // `user:` = user's login group.
            uid.and_then(|id| crate::users::by_uid(id)).map(|x| x.gid)
        }
        Some(g) => {
            if let Ok(n) = g.parse::<u32>() {
                Some(n)
            } else {
                Some(crate::users::group_by_name(g).map(|x| x.gid).ok_or_else(|| alloc::format!("invalid group: {}", q(spec)))?)
            }
        }
    };
    Ok((uid, gid))
}

fn chown_walk(ctx: &mut Ctx, fs: &FsCtx, path: &str, uid: Option<u32>, gid: Option<u32>, recursive: bool, follow: bool, verbose: bool, name: &str) -> i32 {
    let mut st = 0;
    if let Err(e) = ops::chown(fs, path, uid, gid, follow) {
        let what = if uid.is_some() { "ownership" } else { "group" };
        ctx.eprint(&alloc::format!("{name}: changing {what} of {}: {}\n", q(path), e));
        st = 1;
    } else if verbose {
        outln!(ctx, "changed ownership of {}", q(path));
    }
    if recursive && ops::stat(fs, path, false).is_ok_and(|m| m.kind == FileType::Directory) {
        if let Ok(entries) = ops::list_dir(fs, path) {
            for e in entries {
                st |= chown_walk(ctx, fs, &join(path, &e.name), uid, gid, true, false, verbose, name);
            }
        }
    }
    st
}

pub fn chown(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "Rhvcf", values: "", long: &[("recursive", 'R', false), ("no-dereference", 'h', false), ("verbose", 'v', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    if p.operands.len() < 2 {
        return ctx.fail("missing operand");
    }
    let (uid, gid) = match resolve_owner(&p.operands[0]) {
        Ok(x) => x,
        Err(m) => return ctx.fail(m),
    };
    let fs = ctx.fs();
    let mut st = 0;
    for f in p.operands[1..].to_vec() {
        if ops::stat(&fs, &f, false).is_err() {
            ctx.eprint(&alloc::format!("chown: cannot access {}: No such file or directory\n", q(&f)));
            st = 1;
            continue;
        }
        st |= chown_walk(ctx, &fs, &f, uid, gid, p.has('R'), !p.has('h'), p.has('v'), "chown");
    }
    st
}

pub fn chgrp(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "Rhvcf", values: "", long: &[("recursive", 'R', false), ("no-dereference", 'h', false), ("verbose", 'v', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    if p.operands.len() < 2 {
        return ctx.fail("missing operand");
    }
    let g = &p.operands[0];
    let gid = match g.parse::<u32>().ok().or_else(|| crate::users::group_by_name(g).map(|x| x.gid)) {
        Some(x) => x,
        None => return ctx.fail(alloc::format!("invalid group: {}", q(g))),
    };
    let fs = ctx.fs();
    let mut st = 0;
    for f in p.operands[1..].to_vec() {
        st |= chown_walk(ctx, &fs, &f, None, Some(gid), p.has('R'), !p.has('h'), p.has('v'), "chgrp");
    }
    st
}

// ── mktemp / truncate / mkfifo / sync ─────────────────────────────────────

pub fn mktemp(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "dqtu", values: "p", long: &[("directory", 'd', false), ("quiet", 'q', false), ("tmpdir", 'p', true), ("dry-run", 'u', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let template = p.operands.first().cloned().unwrap_or_else(|| String::from("tmp.XXXXXXXXXX"));
    let xs = template.len() - template.trim_end_matches('X').len();
    if xs < 3 {
        return ctx.fail(alloc::format!("too few X's in template {}", q(&template)));
    }
    let base = &template[..template.len() - xs];
    let dir = if template.contains('/') && p.value('p').is_none() && !p.has('t') {
        String::new()
    } else {
        p.value('p').map(|s| s.to_string()).or_else(|| ctx.env("TMPDIR")).unwrap_or_else(|| String::from("/tmp"))
    };
    let fs = ctx.fs();
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for _ in 0..100 {
        let mut name = String::from(base);
        for _ in 0..xs {
            name.push(CHARS[crate::crypto::rng::below(CHARS.len() as u64) as usize] as char);
        }
        let path = if dir.is_empty() { name } else { join(&dir, &name) };
        let r = if p.has('u') {
            Ok(())
        } else if p.has('d') {
            ops::mkdir(&fs, &path, 0o700)
        } else {
            ops::open(&fs, &path, flags::O_RDWR | flags::O_CREAT | flags::O_EXCL, 0o600).map(|_| ())
        };
        match r {
            Ok(()) => {
                outln!(ctx, "{}", path);
                return 0;
            }
            Err(Errno::EEXIST) => continue,
            Err(e) => {
                if !p.has('q') {
                    let kind = if p.has('d') { "directory" } else { "file" };
                    ctx.fail(alloc::format!("failed to create {kind} via template {}: {e}", q(&path)));
                }
                return 1;
            }
        }
    }
    ctx.fail("failed to create a unique name")
}

pub fn truncate(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "c", values: "s", long: &[("size", 's', true), ("no-create", 'c', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    let Some(spec) = p.value('s').map(|s| s.to_string()) else { return ctx.fail("you must specify either '--size' or '--reference'") };
    let fs = ctx.fs();
    let (rel, num) = match spec.chars().next() {
        Some(c @ ('+' | '-')) => (Some(c), &spec[1..]),
        _ => (None, spec.as_str()),
    };
    let Some(n) = fmtutil::parse_size(num) else { return ctx.fail(alloc::format!("invalid number: {}", q(&spec))) };
    let mut st = 0;
    for f in p.operands.clone() {
        if ops::stat(&fs, &f, true).is_err() {
            if p.has('c') {
                continue;
            }
            if let Err(e) = ops::open(&fs, &f, flags::O_WRONLY | flags::O_CREAT, 0o666) {
                ctx.eprint(&alloc::format!("truncate: cannot open {} for writing: {}\n", q(&f), e));
                st = 1;
                continue;
            }
        }
        let cur = ops::stat(&fs, &f, true).map(|m| m.size).unwrap_or(0);
        let size = match rel {
            Some('+') => cur + n,
            Some(_) => cur.saturating_sub(n),
            None => n,
        };
        if let Err(e) = ops::truncate(&fs, &f, size) {
            ctx.eprint(&alloc::format!("truncate: failed to truncate {} at {} bytes: {}\n", q(&f), size, e));
            st = 1;
        }
    }
    st
}

pub fn mkfifo(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "", values: "m", long: &[("mode", 'm', true)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => return ctx.fail(m),
    };
    if p.operands.is_empty() {
        return ctx.fail("missing operand");
    }
    let mode = p.value('m').and_then(|m| parse_mode(m, 0o666, false)).unwrap_or(0o666);
    let fs = ctx.fs();
    let mut st = 0;
    for f in p.operands.clone() {
        if let Err(e) = ops::mknod(&fs, &f, FileType::Fifo, mode, 0) {
            ctx.eprint(&alloc::format!("mkfifo: cannot create fifo {}: {}\n", q(&f), e));
            st = 1;
        }
    }
    st
}

pub fn sync(ctx: &mut Ctx) -> i32 {
    let _ = ctx;
    crate::fs::bcache::sync_all();
    0
}
