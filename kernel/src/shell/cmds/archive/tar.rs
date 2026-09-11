//! `tar` — create, list and extract (GNU tar 1.35 behaviour and output).

use super::{clear_path, create_file, join, listing_time, lstat, open_read, perm_string, quote_name, set_mtime, umask, FileSink, FileSource, LinkGuard, Replay};
use crate::errno::Errno;
use crate::fs::ops::{self, Ctx as FsCtx};
use crate::fs::{FileType, Metadata};
use crate::shell::cmds::fmtutil::NameCache;
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use fastros_archive as ar;
use fastros_archive::gzip::{self as gz, GzDecoder, GzEncoder};
use fastros_archive::path::{is_under, sanitize, strip_components, PathError};
use fastros_archive::tar::{Entry, Kind, TarReader, TarWriter};

const O_EXCLUDE: char = '\u{E000}';
const O_NUMERIC: char = '\u{E001}';
const O_STRIP: char = '\u{E002}';
const O_OVERWRITE: char = '\u{E003}';
const O_NO_SAME_OWNER: char = '\u{E004}';
const O_SAME_OWNER: char = '\u{E005}';

const SPEC: OptSpec = OptSpec {
    flags: "cxtzvpOPkha?\u{E001}\u{E003}\u{E004}\u{E005}",
    values: "fC\u{E000}\u{E002}",
    long: &[
        ("create", 'c', false),
        ("extract", 'x', false),
        ("get", 'x', false),
        ("list", 't', false),
        ("gzip", 'z', false),
        ("gunzip", 'z', false),
        ("ungzip", 'z', false),
        ("verbose", 'v', false),
        ("file", 'f', true),
        ("directory", 'C', true),
        ("preserve-permissions", 'p', false),
        ("same-permissions", 'p', false),
        ("to-stdout", 'O', false),
        ("absolute-names", 'P', false),
        ("keep-old-files", 'k', false),
        ("dereference", 'h', false),
        ("auto-compress", 'a', false),
        ("numeric-owner", O_NUMERIC, false),
        ("exclude", O_EXCLUDE, true),
        ("strip-components", O_STRIP, true),
        ("overwrite", O_OVERWRITE, false),
        ("no-same-owner", O_NO_SAME_OWNER, false),
        ("same-owner", O_SAME_OWNER, false),
        ("help", '?', false),
    ],
};

const USAGE: &str = "Usage: tar [OPTION...] [FILE]...
Create, list or extract tape archives.

Examples:
  tar -cf archive.tar foo bar  # Create archive.tar from files foo and bar.
  tar -tvf archive.tar         # List all files in archive.tar verbosely.
  tar -xf archive.tar          # Extract all files from archive.tar.
  tar -xzf archive.tgz -C dir  # Extract a gzip-compressed archive into dir.

  -c, --create               create a new archive
  -x, --extract, --get       extract files from an archive
  -t, --list                 list the contents of an archive
  -f, --file=ARCHIVE         use archive file ARCHIVE ('-' = stdin/stdout)
  -C, --directory=DIR        change to directory DIR
  -z, --gzip                 filter the archive through gzip
  -a, --auto-compress        use archive suffix to determine the compression
  -v, --verbose              verbosely list files processed (-vv: long format)
  -p, --preserve-permissions extract information about file permissions
  -O, --to-stdout            extract files to standard output
  -P, --absolute-names       don't strip leading '/' or refuse '..' in names
  -k, --keep-old-files       don't replace existing files when extracting
  -h, --dereference          follow symlinks; archive the files they point to
      --exclude=PATTERN      exclude files, given as a PATTERN
      --strip-components=N   strip N leading components from file names
      --numeric-owner        always use numbers for user/group names
      --no-same-owner        extract files as yourself
";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Create,
    Extract,
    List,
}

struct Opts {
    op: Op,
    gzip: bool,
    auto: bool,
    verbose: usize,
    file: String,
    dir: Option<String>,
    preserve: bool,
    to_stdout: bool,
    absolute: bool,
    keep_old: bool,
    deref: bool,
    numeric: bool,
    same_owner: bool,
    excludes: Vec<String>,
    strip: usize,
    members: Vec<String>,
}

/// Old-style `tar xzvf a.tgz`: the first word is a bundle of letters whose
/// value-taking options consume the following words in order.
fn expand_bundled(args: &[String]) -> Vec<String> {
    if args.len() < 2 || args[1].starts_with('-') || args[1].is_empty() {
        return args.to_vec();
    }
    let mut out = alloc::vec![args[0].clone()];
    let mut rest = args[2..].iter();
    for c in args[1].chars() {
        out.push(alloc::format!("-{c}"));
        if c == 'f' || c == 'C' {
            if let Some(v) = rest.next() {
                out.push(v.clone());
            }
        }
    }
    out.extend(rest.cloned());
    out
}

fn msg(ctx: &mut Ctx, s: &str) {
    ctx.eprint(&alloc::format!("tar: {s}\n"));
}

fn try_help(ctx: &mut Ctx) -> i32 {
    ctx.eprint("Try 'tar --help' or 'tar --usage' for more information.\n");
    2
}

pub fn tar(ctx: &mut Ctx) -> i32 {
    let args = expand_bundled(&ctx.args);
    let p = match parse_opts(&args, &SPEC) {
        Ok(p) => p,
        Err(m) => {
            msg(ctx, &m);
            return try_help(ctx);
        }
    };
    if p.has('?') {
        ctx.print(USAGE);
        return 0;
    }
    let ops: Vec<Op> = [('c', Op::Create), ('x', Op::Extract), ('t', Op::List)].iter().filter(|(c, _)| p.has(*c)).map(|&(_, o)| o).collect();
    if ops.len() != 1 {
        if ops.is_empty() {
            msg(ctx, "You must specify one of the '-Acdtrux', '--delete' or '--test-label' options");
        } else {
            msg(ctx, "You may not specify more than one '-Acdtrux', '--delete' or  '--test-label' option");
        }
        return try_help(ctx);
    }
    let strip = match p.value(O_STRIP) {
        Some(v) => match v.parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                msg(ctx, &alloc::format!("{v}: Invalid number of elements"));
                return try_help(ctx);
            }
        },
        None => 0,
    };
    let root = ctx.cred().is_root();
    let o = Opts {
        op: ops[0],
        gzip: p.has('z'),
        auto: p.has('a'),
        verbose: p.count('v'),
        file: p.value('f').unwrap_or("-").to_string(),
        dir: p.value('C').map(|s| s.to_string()),
        preserve: p.has('p') || root,
        to_stdout: p.has('O'),
        absolute: p.has('P'),
        keep_old: p.has('k') && !p.has(O_OVERWRITE),
        deref: p.has('h'),
        numeric: p.has(O_NUMERIC),
        same_owner: (root || p.has(O_SAME_OWNER)) && !p.has(O_NO_SAME_OWNER),
        excludes: p.values(O_EXCLUDE).to_vec(),
        strip,
        members: p.operands.clone(),
    };
    match o.op {
        Op::Create => create(ctx, &o),
        Op::Extract | Op::List => read_archive(ctx, &o),
    }
}

/// GNU's default exclusion matching: the pattern may match the whole name
/// or any trailing run of components.
fn excluded(pats: &[String], name: &str) -> bool {
    let n = name.trim_end_matches('/');
    pats.iter().any(|pat| {
        let pat = pat.trim_end_matches('/');
        let mut s = n;
        loop {
            if fastros_sh::pattern::matches(pat, s) {
                return true;
            }
            match s.find('/') {
                Some(i) => s = &s[i + 1..],
                None => return false,
            }
        }
    })
}

/// `tar -tv` line formatting; GNU widens the owner/size column as needed
/// and never narrows it again.
struct Lister {
    ugswidth: usize,
    numeric: bool,
}

impl Lister {
    fn new(numeric: bool) -> Lister {
        Lister { ugswidth: 19, numeric }
    }

    fn long(&mut self, e: &Entry) -> String {
        let user = if self.numeric || e.uname.is_empty() { e.uid.to_string() } else { e.uname.clone() };
        let group = if self.numeric || e.gname.is_empty() { e.gid.to_string() } else { e.gname.clone() };
        let size = match e.kind {
            Kind::CharDevice | Kind::BlockDevice => alloc::format!("{},{}", e.dev_major, e.dev_minor),
            _ => e.size.to_string(),
        };
        let pad = user.len() + 1 + group.len() + 1 + size.len();
        if pad > self.ugswidth {
            self.ugswidth = pad;
        }
        let w = self.ugswidth - pad + size.len();
        let mut s = alloc::format!("{} {user}/{group} {size:>w$} {} {}", perm_string(e.kind.letter(), e.mode), listing_time(e.mtime), quote_name(&e.path));
        match e.kind {
            Kind::Symlink => s.push_str(&alloc::format!(" -> {}", quote_name(&e.link))),
            Kind::HardLink => s.push_str(&alloc::format!(" link to {}", quote_name(&e.link))),
            _ => {}
        }
        s
    }
}

// ── create ──────────────────────────────────────────────────────────────────

struct Creator<'o> {
    o: &'o Opts,
    fs: FsCtx,
    names: NameCache,
    links: BTreeMap<(u64, u64), String>,
    archive_id: Option<(u64, u64)>,
    listing_to_stderr: bool,
    lister: Lister,
    errors: bool,
    warned_root: bool,
}

fn create(ctx: &mut Ctx, o: &Opts) -> i32 {
    if o.members.is_empty() {
        msg(ctx, "Cowardly refusing to create an empty archive");
        return try_help(ctx);
    }
    let fs = ctx.fs();
    let to_stdout = o.file == "-";
    let (file, archive_id): (Arc<dyn crate::fs::file::File>, Option<(u64, u64)>) = if to_stdout {
        if ctx.stdout_tty().is_some() {
            msg(ctx, "Refusing to write archive contents to terminal (missing -f option?)");
            msg(ctx, "Error is not recoverable: exiting now");
            return 2;
        }
        ctx.flush();
        (ctx.stdout(), None)
    } else {
        match ops::open(&fs, &o.file, crate::fs::file::flags::O_WRONLY | crate::fs::file::flags::O_CREAT | crate::fs::file::flags::O_TRUNC, 0o666) {
            Ok(f) => {
                let id = f.stat().ok().map(|m| (m.dev, m.ino));
                (f, id)
            }
            Err(e) => {
                msg(ctx, &alloc::format!("{}: Cannot open: {e}", o.file));
                msg(ctx, "Error is not recoverable: exiting now");
                return 2;
            }
        }
    };
    let gzip = o.gzip || (o.auto && [".tgz", ".tar.gz", ".taz"].iter().any(|s| o.file.ends_with(s)));
    let mut c = Creator {
        o,
        fs,
        names: NameCache::new(),
        links: BTreeMap::new(),
        archive_id,
        listing_to_stderr: to_stdout,
        lister: Lister::new(o.numeric),
        errors: false,
        warned_root: false,
    };
    let r = if gzip {
        let mut enc = GzEncoder::new(FileSink(file), 6, &gz::Header::default());
        let res = {
            let mut tw = TarWriter::new(&mut enc as &mut dyn ar::Write);
            c.run(ctx, &mut tw).and_then(|_| tw.finish().map(|_| ()))
        };
        res.and_then(|_| enc.finish().map(|_| ()))
    } else {
        let mut sink = FileSink(file);
        let mut tw = TarWriter::new(&mut sink as &mut dyn ar::Write);
        c.run(ctx, &mut tw).and_then(|_| tw.finish().map(|_| ()))
    };
    if let Err(e) = r {
        if e != super::io_err(Errno::EINTR) && e != super::io_err(Errno::EPIPE) {
            msg(ctx, &alloc::format!("{}: Cannot write: {e}", o.file));
            msg(ctx, "Error is not recoverable: exiting now");
        }
        return 2;
    }
    if c.errors {
        msg(ctx, "Exiting with failure status due to previous errors");
        return 2;
    }
    0
}

type Tw<'a> = TarWriter<&'a mut dyn ar::Write>;

impl Creator<'_> {
    fn run(&mut self, ctx: &mut Ctx, tw: &mut Tw) -> ar::Result<()> {
        for m in self.o.members.clone() {
            let mut name = m.clone();
            if !self.o.absolute && name.starts_with('/') {
                if !self.warned_root {
                    self.warned_root = true;
                    msg(ctx, "Removing leading `/' from member names");
                }
                name = name.trim_start_matches('/').to_string();
                if name.is_empty() {
                    name = String::from("./");
                }
            }
            let fs_path = match &self.o.dir {
                Some(d) if !m.starts_with('/') => join(d, &m),
                _ => m.clone(),
            };
            self.add(ctx, tw, &fs_path, &name)?;
        }
        Ok(())
    }

    fn verbose(&mut self, ctx: &mut Ctx, e: &Entry) {
        if self.o.verbose == 0 {
            return;
        }
        let line = if self.o.verbose >= 2 { self.lister.long(e) } else { quote_name(&e.path) };
        if self.listing_to_stderr {
            ctx.eprint(&alloc::format!("{line}\n"));
        } else {
            ctx.println(&line);
        }
    }

    fn entry_for(&self, name: &str, kind: Kind, m: &Metadata) -> Entry {
        let mut e = Entry::new(name, kind);
        e.mode = (m.perm & 0o7777) as u32;
        e.uid = m.uid;
        e.gid = m.gid;
        if !self.o.numeric {
            e.uname = self.names.user(m.uid);
            e.gname = self.names.group(m.gid);
            // Unknown ids stay numeric-only, as GNU tar does.
            if e.uname == m.uid.to_string() {
                e.uname.clear();
            }
            if e.gname == m.gid.to_string() {
                e.gname.clear();
            }
        }
        e.mtime = m.mtime.sec;
        e
    }

    fn add(&mut self, ctx: &mut Ctx, tw: &mut Tw, fs_path: &str, name: &str) -> ar::Result<()> {
        if ctx.should_stop() {
            return Err(super::io_err(Errno::EINTR));
        }
        if excluded(&self.o.excludes, name) {
            return Ok(());
        }
        let m = match ops::stat(&self.fs, fs_path, self.o.deref) {
            Ok(m) => m,
            Err(e) => {
                msg(ctx, &alloc::format!("{name}: Cannot stat: {e}"));
                self.errors = true;
                return Ok(());
            }
        };
        if self.archive_id == Some((m.dev, m.ino)) {
            msg(ctx, &alloc::format!("{name}: file is the archive; not dumped"));
            return Ok(());
        }
        match m.kind {
            FileType::Directory => {
                let dname = if name.ends_with('/') { name.to_string() } else { alloc::format!("{name}/") };
                let e = self.entry_for(&dname, Kind::Directory, &m);
                tw.append(&e, b"")?;
                self.verbose(ctx, &e);
                let mut kids: Vec<String> = match ops::list_dir(&self.fs, fs_path) {
                    Ok(v) => v.into_iter().map(|d| d.name).filter(|n| n != "." && n != "..").collect(),
                    Err(err) => {
                        msg(ctx, &alloc::format!("{name}: Cannot open: {err}"));
                        self.errors = true;
                        return Ok(());
                    }
                };
                kids.sort();
                for k in kids {
                    self.add(ctx, tw, &join(fs_path, &k), &alloc::format!("{dname}{k}"))?;
                }
            }
            FileType::Regular => {
                if m.nlink > 1 {
                    if let Some(first) = self.links.get(&(m.dev, m.ino)) {
                        let mut e = self.entry_for(name, Kind::HardLink, &m);
                        e.link = first.clone();
                        tw.append(&e, b"")?;
                        self.verbose(ctx, &e);
                        return Ok(());
                    }
                    self.links.insert((m.dev, m.ino), name.to_string());
                }
                let f = match open_read(&self.fs, fs_path) {
                    Ok(f) => f,
                    Err(err) => {
                        msg(ctx, &alloc::format!("{name}: Cannot open: {err}"));
                        self.errors = true;
                        return Ok(());
                    }
                };
                let mut e = self.entry_for(name, Kind::File, &m);
                e.size = m.size;
                tw.append_header(&e)?;
                self.verbose(ctx, &e);
                self.copy_contents(ctx, tw, f, name, m.size)?;
                tw.finish_entry()?;
            }
            FileType::Symlink => {
                let mut e = self.entry_for(name, Kind::Symlink, &m);
                e.link = ops::readlink(&self.fs, fs_path).unwrap_or_default();
                tw.append(&e, b"")?;
                self.verbose(ctx, &e);
            }
            FileType::CharDevice | FileType::BlockDevice => {
                let kind = if m.kind == FileType::CharDevice { Kind::CharDevice } else { Kind::BlockDevice };
                let mut e = self.entry_for(name, kind, &m);
                e.dev_major = crate::fs::major(m.rdev);
                e.dev_minor = crate::fs::minor(m.rdev);
                tw.append(&e, b"")?;
                self.verbose(ctx, &e);
            }
            FileType::Fifo => {
                let e = self.entry_for(name, Kind::Fifo, &m);
                tw.append(&e, b"")?;
                self.verbose(ctx, &e);
            }
            FileType::Socket => msg(ctx, &alloc::format!("{name}: socket ignored")),
        }
        Ok(())
    }

    /// Stream exactly `size` bytes; a file that shrinks or fails is padded
    /// with zeros so the archive stays well-formed.
    fn copy_contents(&mut self, ctx: &mut Ctx, tw: &mut Tw, f: Arc<dyn crate::fs::file::File>, name: &str, size: u64) -> ar::Result<()> {
        let mut src = FileSource(f);
        let mut buf = alloc::vec![0u8; 64 * 1024];
        let mut left = size;
        while left > 0 {
            let want = (buf.len() as u64).min(left) as usize;
            match ar::Read::read(&mut src, &mut buf[..want]) {
                Ok(0) => {
                    msg(ctx, &alloc::format!("{name}: File shrank by {left} bytes; padding with zeros"));
                    self.errors = true;
                    break;
                }
                Ok(n) => {
                    tw.write_data(&buf[..n])?;
                    left -= n as u64;
                }
                Err(e) if e == super::io_err(Errno::EINTR) => return Err(e),
                Err(e) => {
                    msg(ctx, &alloc::format!("{name}: Read error at byte {}: {e}", size - left));
                    self.errors = true;
                    break;
                }
            }
        }
        for b in buf.iter_mut() {
            *b = 0;
        }
        while left > 0 {
            let n = (buf.len() as u64).min(left) as usize;
            tw.write_data(&buf[..n])?;
            left -= n as u64;
        }
        Ok(())
    }
}

// ── list / extract ──────────────────────────────────────────────────────────

struct DirFix {
    path: String,
    mode: u32,
    mtime: i64,
    uid: u32,
    gid: u32,
}

struct Reader<'o> {
    o: &'o Opts,
    fs: FsCtx,
    dest: String,
    lister: Lister,
    matched: Vec<bool>,
    guard: LinkGuard,
    dirs: Vec<DirFix>,
    umask: u16,
    errors: bool,
    warned_root: bool,
    listing_to_stderr: bool,
}

fn gzip_failure(ctx: &mut Ctx, e: &ar::Error) -> bool {
    let text = match e {
        ar::Error::BadMagic => "not in gzip format",
        ar::Error::Checksum { .. } => "invalid compressed data--crc error",
        ar::Error::Length => "invalid compressed data--length error",
        ar::Error::Corrupt("invalid compressed data") => "invalid compressed data--format violated",
        _ => return false,
    };
    ctx.eprint(&alloc::format!("gzip: stdin: {text}\n"));
    msg(ctx, "Child returned status 1");
    true
}

fn read_archive(ctx: &mut Ctx, o: &Opts) -> i32 {
    let fs = ctx.fs();
    let file: Arc<dyn crate::fs::file::File> = if o.file == "-" {
        if ctx.stdin_tty().is_some() {
            msg(ctx, "Refusing to read archive contents from terminal (missing -f option?)");
            msg(ctx, "Error is not recoverable: exiting now");
            return 2;
        }
        ctx.stdin()
    } else {
        match open_read(&fs, &o.file) {
            Ok(f) => f,
            Err(e) => {
                msg(ctx, &alloc::format!("{}: Cannot open: {e}", o.file));
                msg(ctx, "Error is not recoverable: exiting now");
                return 2;
            }
        }
    };
    let replay = match Replay::sniff(FileSource(file), 512) {
        Ok(r) => r,
        Err(e) => {
            msg(ctx, &alloc::format!("{}: Read error: {e}", o.file));
            return 2;
        }
    };
    let compressed = gz::is_gzip(replay.head());
    if o.gzip && !compressed && !replay.head().is_empty() {
        ctx.eprint("gzip: stdin: not in gzip format\n");
        msg(ctx, "Child returned status 1");
        msg(ctx, "Error is not recoverable: exiting now");
        return 2;
    }
    let mut src: Box<dyn ar::Read> = if compressed { Box::new(GzDecoder::new(replay)) } else { Box::new(replay) };
    let mut tr = TarReader::new(&mut *src as &mut dyn ar::Read);
    let dest = o.dir.clone().unwrap_or_else(|| String::from("."));
    if o.op == Op::Extract && o.dir.is_some() {
        match ops::stat(&fs, &dest, true) {
            Ok(m) if m.kind == FileType::Directory => {}
            Ok(_) => {
                msg(ctx, &alloc::format!("{dest}: Cannot open: {}", Errno::ENOTDIR));
                msg(ctx, "Error is not recoverable: exiting now");
                return 2;
            }
            Err(e) => {
                msg(ctx, &alloc::format!("{dest}: Cannot open: {e}"));
                msg(ctx, "Error is not recoverable: exiting now");
                return 2;
            }
        }
    }
    let mut r = Reader {
        o,
        fs,
        dest,
        lister: Lister::new(o.numeric),
        matched: alloc::vec![false; o.members.len()],
        guard: LinkGuard::default(),
        dirs: Vec::new(),
        umask: umask(ctx),
        errors: false,
        warned_root: false,
        listing_to_stderr: o.to_stdout,
    };
    let mut first = true;
    loop {
        if ctx.should_stop() {
            return 2;
        }
        let e = match tr.next_entry() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                if !gzip_failure(ctx, &err) {
                    match err {
                        ar::Error::UnexpectedEof | ar::Error::Corrupt(_) if first => msg(ctx, "This does not look like a tar archive"),
                        ar::Error::UnexpectedEof => msg(ctx, "Unexpected EOF in archive"),
                        ar::Error::Corrupt(_) => msg(ctx, "Skipping to next header"),
                        ar::Error::Io(s) if s == Errno::EINTR.desc() => return 2,
                        other => msg(ctx, &alloc::format!("{other}")),
                    }
                }
                r.finish_dirs(ctx);
                msg(ctx, if first { "Exiting with failure status due to previous errors" } else { "Error is not recoverable: exiting now" });
                return 2;
            }
        };
        first = false;
        let res = if o.op == Op::List { r.list(ctx, &e) } else { r.extract(ctx, &mut tr, &e) };
        if let Err(err) = res {
            if !gzip_failure(ctx, &err) {
                match err {
                    ar::Error::UnexpectedEof => msg(ctx, "Unexpected EOF in archive"),
                    ar::Error::Io(s) if s == Errno::EINTR.desc() || s == Errno::EPIPE.desc() => return 2,
                    other => msg(ctx, &alloc::format!("{other}")),
                }
            }
            r.finish_dirs(ctx);
            msg(ctx, "Error is not recoverable: exiting now");
            return 2;
        }
    }
    r.finish_dirs(ctx);
    for (i, m) in o.members.iter().enumerate() {
        if !r.matched[i] {
            msg(ctx, &alloc::format!("{m}: Not found in archive"));
            r.errors = true;
        }
    }
    if r.errors {
        msg(ctx, "Exiting with failure status due to previous errors");
        return 2;
    }
    0
}

type Tr<'a> = TarReader<&'a mut dyn ar::Read>;

impl Reader<'_> {
    fn selected(&mut self, name: &str) -> bool {
        if self.o.members.is_empty() {
            return true;
        }
        let mut hit = false;
        for (i, m) in self.o.members.iter().enumerate() {
            let m = m.trim_start_matches("./");
            let n = name.trim_start_matches("./");
            if is_under(n, m) {
                self.matched[i] = true;
                hit = true;
            }
        }
        hit
    }

    fn show(&mut self, ctx: &mut Ctx, e: &Entry, name: &str) {
        if self.o.verbose == 0 && self.o.op != Op::List {
            return;
        }
        let line = if self.o.verbose >= 1 && (self.o.op == Op::List || self.o.verbose >= 2) {
            let mut shown = e.clone();
            shown.path = name.to_string();
            self.lister.long(&shown)
        } else {
            quote_name(name)
        };
        if self.listing_to_stderr {
            ctx.eprint(&alloc::format!("{line}\n"));
        } else {
            ctx.println(&line);
        }
    }

    fn list(&mut self, ctx: &mut Ctx, e: &Entry) -> ar::Result<()> {
        if !self.selected(&e.path) || excluded(&self.o.excludes, &e.path) {
            return Ok(());
        }
        let name = e.path.clone();
        self.show(ctx, e, &name);
        Ok(())
    }

    fn fail(&mut self, ctx: &mut Ctx, s: &str) {
        msg(ctx, s);
        self.errors = true;
    }

    /// Map a member name onto the destination; `None` when it must be skipped.
    fn target(&mut self, ctx: &mut Ctx, name: &str) -> Option<(String, String)> {
        if self.o.absolute {
            let path = if name.starts_with('/') { name.to_string() } else { join(&self.dest, name) };
            return Some((name.trim_start_matches('/').to_string(), path));
        }
        match sanitize(name) {
            Ok(s) => {
                if s.stripped_root && !self.warned_root {
                    self.warned_root = true;
                    msg(ctx, "Removing leading `/' from member names");
                }
                if s.path.is_empty() {
                    return None;
                }
                let full = join(&self.dest, &s.path);
                Some((s.path, full))
            }
            Err(PathError::ParentReference) => {
                self.fail(ctx, &alloc::format!("{}: Member name contains '..'", quote_name(name)));
                None
            }
            Err(PathError::Invalid) => {
                self.fail(ctx, &alloc::format!("{}: Invalid member name", quote_name(name)));
                None
            }
        }
    }

    fn owner(&self, e: &Entry) -> (u32, u32) {
        if self.o.numeric {
            return (e.uid, e.gid);
        }
        let uid = if e.uname.is_empty() { e.uid } else { crate::users::by_name(&e.uname).map(|u| u.uid).unwrap_or(e.uid) };
        let gid = if e.gname.is_empty() { e.gid } else { crate::users::group_by_name(&e.gname).map(|g| g.gid).unwrap_or(e.gid) };
        (uid, gid)
    }

    fn mode_for(&self, e: &Entry) -> u16 {
        let m = (e.mode & 0o7777) as u16;
        if self.o.preserve {
            m
        } else {
            m & !self.umask
        }
    }

    fn apply_attrs(&self, path: &str, e: &Entry, follow: bool) {
        if self.o.same_owner {
            let (u, g) = self.owner(e);
            let _ = ops::chown(&self.fs, path, Some(u), Some(g), follow);
        }
        if e.kind != Kind::Symlink {
            let _ = ops::chmod(&self.fs, path, self.mode_for(e), follow);
            set_mtime(&self.fs, path, e.mtime, follow);
        }
    }

    fn extract(&mut self, ctx: &mut Ctx, tr: &mut Tr, e: &Entry) -> ar::Result<()> {
        let mut name = e.path.clone();
        if self.o.strip > 0 {
            match strip_components(&name, self.o.strip) {
                Some(n) => name = n,
                None => return Ok(()),
            }
        }
        if !self.selected(&name) || excluded(&self.o.excludes, &name) {
            return Ok(());
        }
        if self.o.to_stdout {
            self.show(ctx, e, &name);
            if matches!(e.kind, Kind::File | Kind::Other(_)) {
                ctx.flush();
                let mut out = FileSink(ctx.stdout());
                ar::copy(tr, &mut out)?;
            }
            return Ok(());
        }
        let Some((rel, path)) = self.target(ctx, &name) else {
            return Ok(());
        };
        if self.guard.crosses(&rel) {
            self.fail(ctx, &alloc::format!("{}: Cannot open: path passes through a symbolic link extracted from this archive", quote_name(&name)));
            return Ok(());
        }
        self.show(ctx, e, &name);
        if let Some(parent) = path.rsplit_once('/').map(|(p, _)| p).filter(|p| !p.is_empty()) {
            if let Err(err) = ops::mkdir_all(&self.fs, parent, 0o777) {
                self.fail(ctx, &alloc::format!("{}: Cannot mkdir: {err}", quote_name(parent)));
                return Ok(());
            }
        }
        let qn = quote_name(&name);
        match e.kind {
            Kind::Directory => {
                match ops::mkdir(&self.fs, &path, 0o700) {
                    Ok(()) => {}
                    Err(Errno::EEXIST) if lstat(&self.fs, &path).is_ok_and(|m| m.kind == FileType::Directory) => {}
                    Err(Errno::EEXIST) if !self.o.keep_old => {
                        if let Err(err) = ops::unlink(&self.fs, &path).and_then(|_| ops::mkdir(&self.fs, &path, 0o700)) {
                            self.fail(ctx, &alloc::format!("{qn}: Cannot mkdir: {err}"));
                            return Ok(());
                        }
                    }
                    Err(err) => {
                        self.fail(ctx, &alloc::format!("{qn}: Cannot mkdir: {err}"));
                        return Ok(());
                    }
                }
                self.guard.forget(&rel);
                let (uid, gid) = self.owner(e);
                self.dirs.push(DirFix { path, mode: self.mode_for(e) as u32, mtime: e.mtime, uid, gid });
            }
            Kind::File | Kind::Other(_) => {
                if let Kind::Other(f) = e.kind {
                    msg(ctx, &alloc::format!("{qn}: Unknown file type '{}', extracted as normal file", f as char));
                }
                if self.o.keep_old && lstat(&self.fs, &path).is_ok() {
                    self.fail(ctx, &alloc::format!("{qn}: Cannot open: File exists"));
                    return Ok(());
                }
                if let Err(err) = clear_path(&self.fs, &path) {
                    self.fail(ctx, &alloc::format!("{qn}: Cannot open: {err}"));
                    return Ok(());
                }
                self.guard.forget(&rel);
                let f = match create_file(&self.fs, &path, 0o600) {
                    Ok(f) => f,
                    Err(err) => {
                        self.fail(ctx, &alloc::format!("{qn}: Cannot open: {err}"));
                        return Ok(());
                    }
                };
                let mut buf = alloc::vec![0u8; 64 * 1024];
                let mut write_err = None;
                loop {
                    let n = tr.read_data(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    if write_err.is_none() {
                        if let Err(err) = f.write_all(&buf[..n]) {
                            write_err = Some(err);
                        }
                    }
                }
                if let Some(err) = write_err {
                    self.fail(ctx, &alloc::format!("{qn}: Cannot write: {err}"));
                }
                drop(f);
                self.apply_attrs(&path, e, false);
            }
            Kind::HardLink => {
                let mut lname = e.link.clone();
                if self.o.strip > 0 {
                    match strip_components(&lname, self.o.strip) {
                        Some(n) => lname = n,
                        None => return Ok(()),
                    }
                }
                let Some((lrel, lpath)) = self.target(ctx, &lname) else {
                    return Ok(());
                };
                if self.guard.crosses(&lrel) {
                    self.fail(ctx, &alloc::format!("{qn}: Cannot hard link to '{}': path passes through a symbolic link extracted from this archive", quote_name(&lname)));
                    return Ok(());
                }
                let r = clear_path(&self.fs, &path).and_then(|_| ops::link(&self.fs, &lpath, &path));
                if let Err(err) = r {
                    self.fail(ctx, &alloc::format!("{qn}: Cannot hard link to '{}': {err}", quote_name(&lname)));
                }
                self.guard.forget(&rel);
            }
            Kind::Symlink => {
                let r = clear_path(&self.fs, &path).and_then(|_| ops::symlink(&self.fs, &e.link, &path));
                match r {
                    Ok(()) => {
                        self.guard.add(&rel);
                        if self.o.same_owner {
                            let (u, g) = self.owner(e);
                            let _ = ops::chown(&self.fs, &path, Some(u), Some(g), false);
                        }
                        set_mtime(&self.fs, &path, e.mtime, false);
                    }
                    Err(err) => self.fail(ctx, &alloc::format!("{qn}: Cannot create symlink to '{}': {err}", quote_name(&e.link))),
                }
            }
            Kind::CharDevice | Kind::BlockDevice | Kind::Fifo => {
                let (kind, rdev) = match e.kind {
                    Kind::CharDevice => (FileType::CharDevice, crate::fs::makedev(e.dev_major, e.dev_minor)),
                    Kind::BlockDevice => (FileType::BlockDevice, crate::fs::makedev(e.dev_major, e.dev_minor)),
                    _ => (FileType::Fifo, 0),
                };
                let r = clear_path(&self.fs, &path).and_then(|_| ops::mknod(&self.fs, &path, kind, self.mode_for(e), rdev));
                match r {
                    Ok(()) => {
                        self.guard.forget(&rel);
                        self.apply_attrs(&path, e, false);
                    }
                    Err(err) => self.fail(ctx, &alloc::format!("{qn}: Cannot mknod: {err}")),
                }
            }
        }
        Ok(())
    }

    /// Directory modes and times are restored last (deepest first), so
    /// read-only directories could still be filled.
    fn finish_dirs(&mut self, _ctx: &mut Ctx) {
        for d in core::mem::take(&mut self.dirs).into_iter().rev() {
            if self.o.same_owner {
                let _ = ops::chown(&self.fs, &d.path, Some(d.uid), Some(d.gid), true);
            }
            let _ = ops::chmod(&self.fs, &d.path, d.mode as u16, true);
            set_mtime(&self.fs, &d.path, d.mtime, true);
        }
    }
}
