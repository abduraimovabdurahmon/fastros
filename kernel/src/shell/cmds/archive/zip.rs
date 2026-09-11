//! `zip` and `unzip` — Info-ZIP zip 3.0 / unzip 6.0 behaviour and output.

use super::{basename, clear_path, create_file, join, lstat, open_read, quote_name, set_mtime, umask, FileAt, FileSink, FileSource, LinkGuard};
use crate::errno::Errno;
use crate::fs::ops::{self, Ctx as FsCtx};
use crate::fs::{FileType, Metadata};
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use crate::{out, outln};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use fastros_archive as ar;
use fastros_archive::path::{sanitize, PathError};
use fastros_archive::zip::{Added, FileMeta, Method, ZipArchive, ZipWriter};

/// Files up to this size are compressed in memory (exact local headers);
/// larger ones stream with a data descriptor.
const BUFFERED_MAX: u64 = 16 << 20;

// ── zip ─────────────────────────────────────────────────────────────────────

const ZIP_SPEC: OptSpec = OptSpec {
    flags: "rjqyDh0123456789",
    values: "",
    long: &[("recurse-paths", 'r', false), ("junk-paths", 'j', false), ("quiet", 'q', false), ("symlinks", 'y', false), ("no-dir-entries", 'D', false), ("help", 'h', false)],
};

const ZIP_USAGE: &str = "Usage: zip [-options] zipfile list
  -r   recurse into directories      -j   junk (don't record) directory names
  -q   quiet operation               -y   store symbolic links as the link
  -D   do not add directory entries  -0   store only
  -1   compress faster               -9   compress better
";

struct Item {
    name: String,
    path: String,
    meta: Metadata,
}

struct ZipOpts {
    recurse: bool,
    junk: bool,
    quiet: bool,
    symlinks: bool,
    no_dirs: bool,
    level: u8,
}

/// Info-ZIP's `percent()`: space saved, rounded.
fn percent(n: u64, m: u64) -> u64 {
    if n > m {
        (1 + 200 * (n - m) / n) / 2
    } else {
        0
    }
}

/// Archive member name for a filesystem path: no leading `/`, no `.`/`..`.
fn zip_name(path: &str, junk: bool) -> String {
    if junk {
        return basename(path).to_string();
    }
    path.split('/').filter(|c| !c.is_empty() && *c != "." && *c != "..").collect::<Vec<_>>().join("/")
}

fn zip_warn(ctx: &mut Ctx, s: &str) {
    ctx.eprint(&alloc::format!("\tzip warning: {s}\n"));
}

fn collect(ctx: &mut Ctx, fs: &FsCtx, o: &ZipOpts, path: &str, skip: Option<(u64, u64)>, items: &mut Vec<Item>, top: bool) {
    let m = if o.symlinks { lstat(fs, path) } else { ops::stat(fs, path, true) };
    let m = match m {
        Ok(m) => m,
        Err(_) if top => {
            zip_warn(ctx, &alloc::format!("name not matched: {path}"));
            return;
        }
        Err(e) => {
            zip_warn(ctx, &alloc::format!("could not open for reading: {path}: {e}"));
            return;
        }
    };
    if skip == Some((m.dev, m.ino)) {
        return;
    }
    let name = zip_name(path, o.junk);
    match m.kind {
        FileType::Directory => {
            if !o.junk && !o.no_dirs && !name.is_empty() {
                items.push(Item { name: alloc::format!("{name}/"), path: path.to_string(), meta: m.clone() });
            }
            if o.recurse {
                let mut kids: Vec<String> = match ops::list_dir(fs, path) {
                    Ok(v) => v.into_iter().map(|e| e.name).filter(|n| n != "." && n != "..").collect(),
                    Err(e) => {
                        zip_warn(ctx, &alloc::format!("could not open for reading: {path}: {e}"));
                        return;
                    }
                };
                kids.sort();
                for k in kids {
                    collect(ctx, fs, o, &join(path, &k), skip, items, false);
                }
            }
        }
        FileType::Regular | FileType::Symlink => {
            if !name.is_empty() {
                items.push(Item { name, path: path.to_string(), meta: m });
            }
        }
        _ => zip_warn(ctx, &alloc::format!("ignoring special file: {path}")),
    }
}

type Zw<'a> = ZipWriter<&'a mut dyn ar::Write>;

fn add_item(fs: &FsCtx, zw: &mut Zw, it: &Item, level: u8) -> Result<Added, String> {
    let meta = FileMeta { name: it.name.clone(), mode: it.meta.mode(), mtime: it.meta.mtime.sec, uid: it.meta.uid, gid: it.meta.gid };
    let io = |e: ar::Error| alloc::format!("{e}");
    match it.meta.kind {
        FileType::Directory => {
            zw.add_directory(&meta).map_err(io)?;
            Ok(Added { method: Method::Stored, size: 0, compressed: 0, crc32: 0 })
        }
        FileType::Symlink => {
            let target = ops::readlink(fs, &it.path).map_err(|e| alloc::format!("{e}"))?;
            zw.add_symlink(&meta, &target).map_err(io)?;
            Ok(Added { method: Method::Stored, size: target.len() as u64, compressed: target.len() as u64, crc32: 0 })
        }
        _ => {
            let f = open_read(fs, &it.path).map_err(|e| alloc::format!("could not open for reading: {e}"))?;
            let mut src = FileSource(f);
            if it.meta.size <= BUFFERED_MAX {
                let mut data = Vec::with_capacity(it.meta.size as usize);
                ar::copy(&mut src, &mut data).map_err(io)?;
                zw.add_file(&meta, &data, level).map_err(io)
            } else {
                zw.start_file(&meta, level).map_err(io)?;
                let mut buf = alloc::vec![0u8; 64 * 1024];
                loop {
                    let n = ar::Read::read(&mut src, &mut buf).map_err(io)?;
                    if n == 0 {
                        break;
                    }
                    zw.write_chunk(&buf[..n]).map_err(io)?;
                }
                zw.finish_file().map_err(io)
            }
        }
    }
}

pub fn zip(ctx: &mut Ctx) -> i32 {
    let p = match parse_opts(&ctx.args, &ZIP_SPEC) {
        Ok(p) => p,
        Err(m) => {
            ctx.eprint(&alloc::format!("zip error: Invalid command arguments ({m})\n"));
            return 16;
        }
    };
    if p.has('h') || p.operands.is_empty() {
        ctx.print(ZIP_USAGE);
        return 0;
    }
    let mut level = 6u8;
    for a in &ctx.args[1..] {
        if a.starts_with('-') && !a.starts_with("--") {
            for c in a.chars().skip(1) {
                if let Some(d) = c.to_digit(10) {
                    level = d as u8;
                }
            }
        }
    }
    let o = ZipOpts { recurse: p.has('r'), junk: p.has('j'), quiet: p.has('q'), symlinks: p.has('y'), no_dirs: p.has('D'), level };
    let mut archive = p.operands[0].clone();
    if !basename(&archive).contains('.') {
        archive.push_str(".zip");
    }
    let fs = ctx.fs();
    let existing = ops::stat(&fs, &archive, true).ok();
    let skip = existing.as_ref().map(|m| (m.dev, m.ino));
    let mut items = Vec::new();
    for f in p.operands[1..].to_vec() {
        collect(ctx, &fs, &o, &f, skip, &mut items, true);
    }
    // A name given twice is stored once (the later wins, like Info-ZIP).
    let mut seen = alloc::collections::BTreeSet::new();
    items.reverse();
    items.retain(|it| seen.insert(it.name.clone()));
    items.reverse();
    if items.is_empty() {
        ctx.eprint(&alloc::format!("\nzip error: Nothing to do! ({archive})\n"));
        return 12;
    }
    let old = match &existing {
        Some(_) => match open_read(&fs, &archive).and_then(FileAt::new) {
            Ok(src) => match ZipArchive::open(src) {
                Ok(a) => Some(a),
                Err(_) => {
                    ctx.eprint(&alloc::format!("\nzip error: Zip file structure invalid ({archive})\n"));
                    return 3;
                }
            },
            Err(e) => {
                ctx.eprint(&alloc::format!("\nzip error: Could not open zip file ({archive}): {e}\n"));
                return 15;
            }
        },
        None => None,
    };
    let tmp = alloc::format!("{archive}.{}.tmp", ctx.proc.pid);
    let out = match create_file(&fs, &tmp, 0o666) {
        Ok(f) => f,
        Err(e) => {
            ctx.eprint(&alloc::format!("\nzip I/O error: {e}\nzip error: Could not create output file ({archive})\n"));
            return 15;
        }
    };
    let mut sink = FileSink(out);
    let mut zw = ZipWriter::new(&mut sink as &mut dyn ar::Write);
    let mut done = alloc::vec![false; items.len()];
    let mut failed = false;
    let report = |ctx: &mut Ctx, verb: &str, it: &Item, r: Result<Added, String>| match r {
        Ok(a) => {
            if !o.quiet {
                let (what, pct) = if a.method == Method::Deflated { ("deflated", percent(a.size, a.compressed)) } else { ("stored", 0) };
                outln!(ctx, "{verb:>8}: {} ({what} {pct}%)", it.name);
            }
            true
        }
        Err(e) => {
            ctx.eprint(&alloc::format!("\nzip I/O error: {}: {e}\n", it.path));
            false
        }
    };
    if let Some(a) = &old {
        for i in 0..a.entries().len() {
            let name = a.entries()[i].name.clone();
            match items.iter().position(|it| it.name == name) {
                Some(k) => {
                    done[k] = true;
                    let r = add_item(&fs, &mut zw, &items[k], o.level);
                    if !report(ctx, "updating", &items[k], r) {
                        failed = true;
                        break;
                    }
                }
                None => {
                    if let Err(e) = zw.copy_entry(a, i) {
                        ctx.eprint(&alloc::format!("\nzip error: {name}: {e}\n"));
                        failed = true;
                        break;
                    }
                }
            }
        }
    }
    if !failed {
        for (k, it) in items.iter().enumerate() {
            if done[k] {
                continue;
            }
            if ctx.should_stop() {
                failed = true;
                break;
            }
            let r = add_item(&fs, &mut zw, it, o.level);
            if !report(ctx, "adding", it, r) {
                failed = true;
                break;
            }
        }
    }
    let finished = if failed { Err(ar::Error::Length) } else { zw.finish(b"").map(|_| ()) };
    drop(old);
    if let Err(e) = finished {
        let _ = ops::unlink(&fs, &tmp);
        if !failed {
            ctx.eprint(&alloc::format!("\nzip I/O error: {e}\nzip error: Output file write failure ({archive})\n"));
        }
        return 15;
    }
    if let Err(e) = ops::rename(&fs, &tmp, &archive) {
        let _ = ops::unlink(&fs, &tmp);
        ctx.eprint(&alloc::format!("\nzip error: Could not rename temporary file to {archive}: {e}\n"));
        return 15;
    }
    0
}

// ── unzip ───────────────────────────────────────────────────────────────────

const UNZIP_SPEC: OptSpec = OptSpec { flags: "lqopntjh:", values: "d", long: &[("help", 'h', false)] };

const UNZIP_USAGE: &str = "Usage: unzip [-lqoptnj:] file[.zip] [list] [-d exdir]
  -l  list files (short format)        -t  test compressed archive data
  -p  extract files to pipe, no messages
  -d  extract files into exdir         -j  junk paths (do not make directories)
  -o  overwrite files WITHOUT prompting  -n  never overwrite existing files
  -q  quiet mode (-qq => quieter)      -:  allow '..' in member names (unsafe)
";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Overwrite {
    Ask,
    All,
    Never,
}

/// unzip's exit codes.
struct UStatus {
    code: i32,
}

impl UStatus {
    fn warn(&mut self) {
        if self.code == 0 {
            self.code = 1;
        }
    }
    fn error(&mut self) {
        if self.code < 2 {
            self.code = 2;
        }
    }
}

struct DirFix {
    path: String,
    mode: Option<u16>,
    mtime: i64,
}

fn date_time(t: i64) -> (String, String) {
    let tm = crate::time::civil::from_unix(t);
    (alloc::format!("{:04}-{:02}-{:02}", tm.year, tm.month, tm.day), alloc::format!("{:02}:{:02}", tm.hour, tm.min))
}

fn zip_error_text(e: &ar::Error) -> String {
    match e {
        ar::Error::Checksum { expected, actual } => alloc::format!("bad CRC {actual:08x}  (should be {expected:08x})"),
        ar::Error::Length => String::from("error:  invalid compressed data length"),
        ar::Error::Corrupt(_) | ar::Error::UnexpectedEof => String::from("error:  invalid compressed data to inflate"),
        ar::Error::Unsupported(s) => alloc::format!("unsupported: {s}"),
        other => alloc::format!("error:  {other}"),
    }
}

pub fn unzip(ctx: &mut Ctx) -> i32 {
    let p = match parse_opts(&ctx.args, &UNZIP_SPEC) {
        Ok(p) => p,
        Err(m) => {
            ctx.eprint(&alloc::format!("unzip: {m}\n"));
            ctx.eprint(UNZIP_USAGE);
            return 10;
        }
    };
    if p.has('h') || p.operands.is_empty() {
        ctx.print(UNZIP_USAGE);
        return 0;
    }
    let fs = ctx.fs();
    let given = p.operands[0].clone();
    let candidates = [given.clone(), alloc::format!("{given}.zip"), alloc::format!("{given}.ZIP")];
    let Some(name) = candidates.iter().find(|c| ops::stat(&fs, c, true).is_ok_and(|m| m.kind == FileType::Regular)).cloned() else {
        ctx.eprint(&alloc::format!("unzip:  cannot find or open {given}, {given}.zip or {given}.ZIP.\n"));
        return 9;
    };
    let quiet = p.count('q');
    let pipe = p.has('p');
    let archive = match open_read(&fs, &name).and_then(FileAt::new) {
        Ok(src) => match ZipArchive::open(src) {
            Ok(a) => a,
            Err(ar::Error::BadMagic) => {
                out!(ctx, "Archive:  {name}\n");
                ctx.eprint(&alloc::format!(
                    "  End-of-central-directory signature not found.  Either this file is not\n  a zipfile, or it constitutes one disk of a multi-part archive.  In the\n  latter case the central directory and zipfile comment will be found on\n  the last disk(s) of this archive.\nunzip:  cannot find zipfile directory in one of {given} or\n        {given}.zip, and cannot find {given}.ZIP, period.\n"
                ));
                return 9;
            }
            Err(e) => {
                out!(ctx, "Archive:  {name}\n");
                ctx.eprint(&alloc::format!("error:  zipfile is damaged: {e}\n"));
                return 3;
            }
        },
        Err(e) => {
            ctx.eprint(&alloc::format!("unzip:  cannot find or open {name}: {e}\n"));
            return 9;
        }
    };
    let members: Vec<String> = p.operands[1..].to_vec();
    let mut matched = alloc::vec![false; members.len()];
    let mut wanted = |n: &str| -> bool {
        if members.is_empty() {
            return true;
        }
        let mut hit = false;
        for (i, m) in members.iter().enumerate() {
            if fastros_sh::pattern::matches(m, n) {
                matched[i] = true;
                hit = true;
            }
        }
        hit
    };
    let selected: Vec<usize> = (0..archive.entries().len()).filter(|&i| wanted(&archive.entries()[i].name)).collect();
    let mut st = UStatus { code: 0 };
    if p.has('l') {
        list(ctx, &archive, &name, &selected);
    } else if p.has('t') {
        test(ctx, &archive, &name, &selected, quiet, &mut st);
    } else if pipe {
        ctx.flush();
        for &i in &selected {
            let e = &archive.entries()[i];
            if e.is_dir() {
                continue;
            }
            let r = archive.reader(i).and_then(|mut r| ar::copy(&mut r, &mut FileSink(ctx.stdout())));
            if let Err(err) = r {
                ctx.eprint(&alloc::format!("{}:  {}\n", e.name, zip_error_text(&err)));
                st.error();
            }
        }
    } else {
        let policy = if p.has('o') {
            Overwrite::All
        } else if p.has('n') {
            Overwrite::Never
        } else {
            Overwrite::Ask
        };
        let mut x = Extract {
            fs: ctx.fs(),
            exdir: p.value('d').map(|s| s.to_string()),
            junk: p.has('j'),
            allow_dotdot: p.has(':'),
            quiet,
            policy,
            guard: LinkGuard::default(),
            dirs: Vec::new(),
            umask: umask(ctx),
        };
        if let Some(d) = x.exdir.clone() {
            if let Err(e) = ops::mkdir_all(&fs, &d, 0o777) {
                ctx.eprint(&alloc::format!("checkdir:  cannot create extraction directory: {d}\n           {e}\n"));
                return 3;
            }
        }
        if quiet == 0 {
            out!(ctx, "Archive:  {name}\n");
        }
        for &i in &selected {
            if ctx.should_stop() {
                st.code = 80;
                break;
            }
            x.entry(ctx, &archive, i, &mut st);
        }
        x.finish_dirs();
    }
    for (i, m) in members.iter().enumerate() {
        if !matched[i] {
            ctx.eprint(&alloc::format!("caution: filename not matched:  {m}\n"));
            if st.code == 0 {
                st.code = 11;
            }
        }
    }
    st.code
}

fn list(ctx: &mut Ctx, a: &ZipArchive<FileAt>, name: &str, selected: &[usize]) {
    out!(ctx, "Archive:  {name}\n");
    ctx.print("  Length      Date    Time    Name\n---------  ---------- -----   ----\n");
    let mut total = 0u64;
    for &i in selected {
        let e = &a.entries()[i];
        let (d, t) = date_time(e.mtime);
        out!(ctx, "{:>9}  {d} {t}   {}\n", e.size, quote_name(&e.name));
        total += e.size;
    }
    let n = selected.len();
    out!(ctx, "---------                     -------\n{total:>9}                     {n} file{}\n", if n == 1 { "" } else { "s" });
}

fn test(ctx: &mut Ctx, a: &ZipArchive<FileAt>, name: &str, selected: &[usize], quiet: usize, st: &mut UStatus) {
    if quiet == 0 {
        out!(ctx, "Archive:  {name}\n");
    }
    let mut bad = 0;
    for &i in selected {
        let e = &a.entries()[i];
        let r = a.reader(i).and_then(|mut r| ar::copy(&mut r, &mut ar::Discard::default()));
        match r {
            Ok(_) => {
                if quiet == 0 {
                    out!(ctx, "    testing: {:<22}   OK\n", quote_name(&e.name));
                }
            }
            Err(err) => {
                out!(ctx, "    testing: {:<22}   {}\n", quote_name(&e.name), zip_error_text(&err));
                bad += 1;
                st.error();
            }
        }
    }
    if bad == 0 {
        if quiet < 2 {
            out!(ctx, "No errors detected in compressed data of {name}.\n");
        }
    } else {
        out!(ctx, "At least one error was detected in {name}.\n");
    }
}

struct Extract {
    fs: FsCtx,
    exdir: Option<String>,
    junk: bool,
    allow_dotdot: bool,
    quiet: usize,
    policy: Overwrite,
    guard: LinkGuard,
    dirs: Vec<DirFix>,
    umask: u16,
}

impl Extract {
    fn line(&self, ctx: &mut Ctx, verb: &str, name: &str, tail: &str) {
        if self.quiet == 0 {
            outln!(ctx, "{verb:>11}: {:<22}  {tail}", quote_name(name));
        }
    }

    /// Relative extraction path for a member; `None` = skip (reported).
    fn relative(&self, ctx: &mut Ctx, name: &str, st: &mut UStatus) -> Option<String> {
        let name = if self.junk { basename(name) } else { name };
        if name.starts_with('/') && self.quiet < 2 {
            ctx.eprint(&alloc::format!("warning:  stripped absolute path spec from {}\n", quote_name(name)));
        }
        match sanitize(name) {
            Ok(s) => Some(s.path),
            Err(PathError::ParentReference) if self.allow_dotdot => {
                Some(name.split('/').filter(|c| !c.is_empty() && *c != ".").collect::<Vec<_>>().join("/"))
            }
            Err(PathError::ParentReference) => {
                ctx.eprint(&alloc::format!("{:>11}: {:<22}  refused: member name contains '..' (use -: to allow)\n", "skipping", quote_name(name)));
                st.warn();
                None
            }
            Err(PathError::Invalid) => {
                ctx.eprint(&alloc::format!("{:>11}: {:<22}  invalid member name\n", "skipping", quote_name(name)));
                st.warn();
                None
            }
        }
    }

    /// Resolve an existing target according to -o/-n or by asking.
    fn may_replace(&mut self, ctx: &mut Ctx, path: &str) -> bool {
        if lstat(&self.fs, path).is_err() {
            return true;
        }
        match self.policy {
            Overwrite::All => return true,
            Overwrite::Never => return false,
            Overwrite::Ask => {}
        }
        loop {
            ctx.print(&alloc::format!("replace {path}? [y]es, [n]o, [A]ll, [N]one, [r]ename: "));
            ctx.flush();
            let Some(ans) = super::read_answer(ctx) else {
                ctx.print("NULL\n(EOF or read error, treating as \"[N]one\" ...)\n");
                self.policy = Overwrite::Never;
                return false;
            };
            match ans.trim() {
                "y" | "Y" => return true,
                "n" => return false,
                "A" => {
                    self.policy = Overwrite::All;
                    return true;
                }
                "N" => {
                    self.policy = Overwrite::Never;
                    return false;
                }
                "r" => {
                    ctx.print("rename is not supported; not replaced\n");
                    return false;
                }
                _ => ctx.print("error:  invalid response [ ]\n"),
            }
        }
    }

    fn entry(&mut self, ctx: &mut Ctx, a: &ZipArchive<FileAt>, i: usize, st: &mut UStatus) {
        let e = a.entries()[i].clone();
        if self.junk && e.is_dir() {
            return;
        }
        let Some(rel) = self.relative(ctx, &e.name, st) else {
            return;
        };
        if rel.is_empty() {
            return;
        }
        if self.guard.crosses(&rel) {
            ctx.eprint(&alloc::format!("{:>11}: {:<22}  refused: path passes through a symbolic link from this archive\n", "skipping", quote_name(&e.name)));
            st.error();
            return;
        }
        let path = match &self.exdir {
            Some(d) => join(d, &rel),
            None => rel.clone(),
        };
        let perm = e.unix_mode().map(|m| (m & 0o1777) as u16);
        if e.is_dir() {
            if let Err(err) = ops::mkdir_all(&self.fs, &path, 0o777) {
                ctx.eprint(&alloc::format!("checkdir error:  cannot create {path}\n                 {err}\n"));
                st.error();
                return;
            }
            self.guard.forget(&rel);
            if self.quiet == 0 {
                outln!(ctx, "   creating: {}", quote_name(&e.name));
            }
            self.dirs.push(DirFix { path, mode: perm, mtime: e.mtime });
            return;
        }
        if e.is_encrypted() {
            ctx.eprint(&alloc::format!("{:>11}: {:<22}  encrypted (not supported)\n", "skipping", quote_name(&e.name)));
            st.warn();
            return;
        }
        if let Method::Other(m) = e.method {
            ctx.eprint(&alloc::format!("{:>11}: {:<22}  unsupported compression method {m}\n", "skipping", quote_name(&e.name)));
            st.warn();
            return;
        }
        if let Some(parent) = path.rsplit_once('/').map(|(p, _)| p).filter(|p| !p.is_empty()) {
            if let Err(err) = ops::mkdir_all(&self.fs, parent, 0o777) {
                ctx.eprint(&alloc::format!("checkdir error:  cannot create {parent}\n                 {err}\n"));
                st.error();
                return;
            }
        }
        if !self.may_replace(ctx, &path) {
            return;
        }
        if let Err(err) = clear_path(&self.fs, &path) {
            ctx.eprint(&alloc::format!("error:  cannot create {path}\n        {err}\n"));
            st.error();
            return;
        }
        self.guard.forget(&rel);
        if e.is_symlink() {
            let mut target = Vec::new();
            let r = a.reader(i).and_then(|mut r| ar::copy(&mut r, &mut target));
            let target = String::from_utf8_lossy(&target).into_owned();
            match r.map_err(|e| zip_error_text(&e)).and_then(|_| ops::symlink(&self.fs, &target, &path).map_err(|e| alloc::format!("error:  {e}"))) {
                Ok(()) => {
                    self.guard.add(&rel);
                    if self.quiet == 0 {
                        outln!(ctx, "{:>11}: {:<22}  -> {} ", "linking", quote_name(&e.name), quote_name(&target));
                    }
                }
                Err(m) => {
                    ctx.eprint(&alloc::format!("{:>11}: {:<22}  {m}\n", "linking", quote_name(&e.name)));
                    st.error();
                }
            }
            return;
        }
        let verb = if e.method == Method::Deflated { "inflating" } else { "extracting" };
        let f = match create_file(&self.fs, &path, 0o600) {
            Ok(f) => f,
            Err(err) => {
                ctx.eprint(&alloc::format!("error:  cannot create {path}\n        {err}\n"));
                st.error();
                return;
            }
        };
        let r = a.reader(i).and_then(|mut r| ar::copy(&mut r, &mut FileSink(f)));
        match r {
            Ok(_) => {
                self.line(ctx, verb, &e.name, "");
                let mode = perm.unwrap_or(0o666 & !self.umask);
                let _ = ops::chmod(&self.fs, &path, mode, false);
                set_mtime(&self.fs, &path, e.mtime, false);
            }
            Err(err) if err == super::io_err(Errno::EINTR) => {
                let _ = ops::unlink(&self.fs, &path);
                st.code = 80;
            }
            Err(err) => {
                let _ = ops::unlink(&self.fs, &path);
                self.line(ctx, verb, &e.name, &zip_error_text(&err));
                st.error();
            }
        }
    }

    fn finish_dirs(&mut self) {
        for d in core::mem::take(&mut self.dirs).into_iter().rev() {
            if let Some(m) = d.mode {
                let _ = ops::chmod(&self.fs, &d.path, m, true);
            }
            set_mtime(&self.fs, &d.path, d.mtime, true);
        }
    }
}
