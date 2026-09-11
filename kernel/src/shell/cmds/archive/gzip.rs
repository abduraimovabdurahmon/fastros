//! `gzip`, `gunzip`, `zcat` — GNU gzip 1.12 behaviour and messages.

use super::{basename, create_file, io_err, lstat, open_read, FileSink, FileSource};
use crate::errno::Errno;
use crate::fs::ops::{self, Ctx as FsCtx};
use crate::fs::FileType;
use crate::out;
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use fastros_archive as ar;
use fastros_archive::gzip::{self as gz, GzDecoder, GzEncoder, Trailing};

const SPEC: OptSpec = OptSpec {
    flags: "cdfhklnNqrtv123456789",
    values: "S",
    long: &[
        ("stdout", 'c', false),
        ("to-stdout", 'c', false),
        ("decompress", 'd', false),
        ("uncompress", 'd', false),
        ("force", 'f', false),
        ("help", 'h', false),
        ("keep", 'k', false),
        ("list", 'l', false),
        ("no-name", 'n', false),
        ("name", 'N', false),
        ("quiet", 'q', false),
        ("recursive", 'r', false),
        ("suffix", 'S', true),
        ("test", 't', false),
        ("verbose", 'v', false),
        ("fast", '1', false),
        ("best", '9', false),
    ],
};

const USAGE: &str = "Usage: gzip [OPTION]... [FILE]...
Compress or uncompress FILEs (by default, compress FILES in-place).

  -c, --stdout      write on standard output, keep original files unchanged
  -d, --decompress  decompress
  -f, --force       force overwrite of output file and compress links
  -k, --keep        keep (don't delete) input files
  -l, --list        list compressed file contents
  -n, --no-name     do not save or restore the original name and timestamp
  -N, --name        save or restore the original name and timestamp
  -q, --quiet       suppress all warnings
  -r, --recursive   operate recursively on directories
  -S, --suffix=SUF  use suffix SUF on compressed files
  -t, --test        test compressed file integrity
  -v, --verbose     verbose mode
  -1, --fast        compress faster
  -9, --best        compress better
";

struct Opts {
    decompress: bool,
    stdout: bool,
    force: bool,
    keep: bool,
    list: bool,
    test: bool,
    verbose: bool,
    quiet: bool,
    save_name: bool,
    restore_name: bool,
    recursive: bool,
    level: u8,
    suffix: String,
}

/// Exit status bookkeeping: errors (1) dominate warnings (2).
struct Status {
    code: i32,
}

impl Status {
    fn error(&mut self) {
        self.code = 1;
    }
    fn warn(&mut self) {
        if self.code == 0 {
            self.code = 2;
        }
    }
}

/// Totals for `gzip -l` over several files.
#[derive(Default)]
struct ListTotals {
    files: u32,
    total_in: i64,
    total_out: i64,
    header_bytes: i64,
    printed_header: bool,
}

pub fn gzip(ctx: &mut Ctx) -> i32 {
    run(ctx, false, false)
}

pub fn gunzip(ctx: &mut Ctx) -> i32 {
    run(ctx, true, false)
}

pub fn zcat(ctx: &mut Ctx) -> i32 {
    run(ctx, true, true)
}

/// GNU `display_ratio`: `%5.1f%%` of num/den.
fn ratio(num: i64, den: i64) -> String {
    if den == 0 {
        return String::from("  0.0%");
    }
    let n = num as i128 * 1000;
    let d = den as i128;
    let r = if (n < 0) != (d < 0) { (2 * n - d) / (2 * d) } else { (2 * n + d) / (2 * d) };
    let neg = r < 0 || (r == 0 && n < 0);
    let a = r.unsigned_abs();
    let s = alloc::format!("{}{}.{}", if neg { "-" } else { "" }, a / 10, a % 10);
    alloc::format!("{s:>5}%")
}

/// The name a compressed file decompresses to, if it has a known suffix.
fn strip_suffix(name: &str, user: &str) -> Option<String> {
    let base = basename(name);
    let dir = &name[..name.len() - base.len()];
    let known: [(&str, &str); 8] = [(user, ""), (".gz", ""), ("-gz", ""), (".z", ""), ("-z", ""), ("_z", ""), (".tgz", ".tar"), (".taz", ".tar")];
    for (suf, repl) in known {
        if !suf.is_empty() && base.len() > suf.len() && base.ends_with(suf) {
            return Some(alloc::format!("{dir}{}{repl}", &base[..base.len() - suf.len()]));
        }
    }
    None
}

fn gz_msg(e: &ar::Error) -> String {
    match e {
        ar::Error::BadMagic => String::from("not in gzip format"),
        ar::Error::UnexpectedEof => String::from("unexpected end of file"),
        ar::Error::Checksum { .. } => String::from("invalid compressed data--crc error"),
        ar::Error::Length => String::from("invalid compressed data--length error"),
        ar::Error::Corrupt(_) => String::from("invalid compressed data--format violated"),
        ar::Error::Unsupported(s) => alloc::format!("{s} -- not supported"),
        other => other.to_string(),
    }
}

fn run(ctx: &mut Ctx, decompress: bool, to_stdout: bool) -> i32 {
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(m) => {
            ctx.fail(m);
            ctx.eprint("Try 'gzip --help' for more information.\n");
            return 1;
        }
    };
    if p.has('h') {
        ctx.print(USAGE);
        return 0;
    }
    // The last level digit given wins (-1 … -9, --fast, --best).
    let mut level = 6u8;
    for a in &ctx.args[1..] {
        if a == "--fast" {
            level = 1;
        } else if a == "--best" {
            level = 9;
        } else if a.starts_with('-') && !a.starts_with("--") {
            for c in a.chars().skip(1) {
                if let Some(d) = c.to_digit(10) {
                    if d > 0 {
                        level = d as u8;
                    }
                }
            }
        }
    }
    let o = Opts {
        decompress: decompress || p.has('d') || p.has('t') || p.has('l'),
        stdout: to_stdout || p.has('c'),
        force: p.has('f'),
        keep: p.has('k'),
        list: p.has('l'),
        test: p.has('t'),
        verbose: p.has('v') && !p.has('q'),
        quiet: p.has('q'),
        save_name: !p.has('n'),
        restore_name: p.has('N'),
        recursive: p.has('r'),
        level,
        suffix: p.value('S').unwrap_or(".gz").to_string(),
    };
    if o.suffix.is_empty() || o.suffix.contains('/') {
        ctx.fail("invalid suffix");
        return 1;
    }
    let mut st = Status { code: 0 };
    let mut totals = ListTotals::default();
    let files = if p.operands.is_empty() { alloc::vec![String::from("-")] } else { p.operands.clone() };
    for f in files {
        if ctx.should_stop() {
            break;
        }
        if f == "-" {
            do_stdin(ctx, &o, &mut st);
        } else {
            do_path(ctx, &o, &f, &mut st, &mut totals, true);
        }
    }
    if o.list && totals.files > 1 {
        list_totals(ctx, &o, &totals);
    }
    st.code
}

fn do_stdin(ctx: &mut Ctx, o: &Opts, st: &mut Status) {
    if o.list {
        ctx.eprint("gzip: option --list not valid with standard input\n");
        st.error();
        return;
    }
    if !o.decompress && !o.force && ctx.stdout_tty().is_some() {
        ctx.eprint("gzip: compressed data not written to a terminal. Use -f to force compression.\nFor help, type: gzip -h\n");
        st.error();
        return;
    }
    if o.decompress && !o.force && ctx.stdin_tty().is_some() {
        ctx.eprint("gzip: compressed data not read from a terminal. Use -f to force decompression.\nFor help, type: gzip -h\n");
        st.error();
        return;
    }
    ctx.flush();
    let input = FileSource(ctx.stdin());
    let out = ctx.stdout();
    if o.decompress {
        let mut dec = GzDecoder::new(input);
        let r = if o.test { ar::copy(&mut dec, &mut ar::Discard::default()) } else { ar::copy(&mut dec, &mut FileSink(out)) };
        match r {
            Ok(_) => {
                report_trailing(ctx, o, "stdin", dec.trailing(), st);
                if o.test && o.verbose {
                    ctx.eprint(" OK\n");
                }
            }
            Err(e) => {
                if !quiet_io(&e) {
                    ctx.eprint(&alloc::format!("gzip: stdin: {}\n", gz_msg(&e)));
                }
                st.error();
            }
        }
    } else {
        let mtime = if o.save_name { crate::time::unix_now() as u32 } else { 0 };
        let mut enc = GzEncoder::new(FileSink(out), o.level, &gz::Header { mtime, ..Default::default() });
        let r = ar::copy(&mut FileSource(ctx.stdin()), &mut enc).and_then(|_| enc.finish());
        if let Err(e) = r {
            if !quiet_io(&e) {
                ctx.eprint(&alloc::format!("gzip: stdin: {}\n", gz_msg(&e)));
            }
            st.error();
        }
    }
}

/// Broken pipes and Ctrl-C end silently, as a signal would.
fn quiet_io(e: &ar::Error) -> bool {
    matches!(e, ar::Error::Io(s) if *s == Errno::EPIPE.desc() || *s == Errno::EINTR.desc())
}

fn report_trailing(ctx: &mut Ctx, o: &Opts, name: &str, t: Trailing, st: &mut Status) {
    let what = match t {
        Trailing::Nothing => return,
        Trailing::Zeros => "trailing zero bytes ignored",
        Trailing::Garbage => "trailing garbage ignored",
    };
    if !o.quiet {
        ctx.eprint(&alloc::format!("gzip: {name}: decompression OK, {what}\n"));
    }
    st.warn();
}

fn do_path(ctx: &mut Ctx, o: &Opts, path: &str, st: &mut Status, totals: &mut ListTotals, top: bool) {
    let fs = ctx.fs();
    let m = match lstat(&fs, path) {
        Ok(m) => m,
        Err(e) => {
            // Decompressing `foo` also finds `foo.gz`, like GNU gzip.
            if o.decompress && e == Errno::ENOENT && top {
                let alt = alloc::format!("{path}{}", o.suffix);
                if lstat(&fs, &alt).is_ok() {
                    return do_path(ctx, o, &alt, st, totals, false);
                }
            }
            ctx.eprint(&alloc::format!("gzip: {path}: {e}\n"));
            st.error();
            return;
        }
    };
    let m = if m.kind == FileType::Symlink {
        if !o.force && !o.stdout {
            if !o.quiet {
                ctx.eprint(&alloc::format!("gzip: {path} is not a directory or a regular file - ignored\n"));
            }
            st.warn();
            return;
        }
        match ops::stat(&fs, path, true) {
            Ok(m) => m,
            Err(e) => {
                ctx.eprint(&alloc::format!("gzip: {path}: {e}\n"));
                st.error();
                return;
            }
        }
    } else {
        m
    };
    match m.kind {
        FileType::Directory => {
            if !o.recursive {
                if !o.quiet {
                    ctx.eprint(&alloc::format!("gzip: {path} is a directory -- ignored\n"));
                }
                st.warn();
                return;
            }
            let mut names: Vec<String> = match ops::list_dir(&fs, path) {
                Ok(v) => v.into_iter().map(|e| e.name).filter(|n| n != "." && n != "..").collect(),
                Err(e) => {
                    ctx.eprint(&alloc::format!("gzip: {path}: {e}\n"));
                    st.error();
                    return;
                }
            };
            names.sort();
            for n in names {
                if ctx.should_stop() {
                    return;
                }
                do_path(ctx, o, &super::join(path, &n), st, totals, false);
            }
        }
        FileType::Regular => {
            if o.list {
                list_file(ctx, o, path, st, totals);
            } else if o.decompress {
                decompress_file(ctx, o, path, &m, st);
            } else {
                compress_file(ctx, o, path, &m, st);
            }
        }
        _ => {
            if !o.quiet {
                ctx.eprint(&alloc::format!("gzip: {path} is not a directory or a regular file - ignored\n"));
            }
            st.warn();
        }
    }
}

/// Refuse to clobber an existing output unless `-f`.
fn may_write(ctx: &mut Ctx, o: &Opts, fs: &FsCtx, out: &str, st: &mut Status) -> bool {
    if lstat(fs, out).is_err() {
        return true;
    }
    if o.force {
        return ops::unlink(fs, out).is_ok() || lstat(fs, out).is_err();
    }
    if super::stdin_is_tty(ctx) {
        ctx.eprint(&alloc::format!("gzip: {out} already exists; do you wish to overwrite (y or n)? "));
        if super::read_answer(ctx).is_some_and(|a| a.starts_with('y') || a.starts_with('Y')) {
            return ops::unlink(fs, out).is_ok();
        }
        ctx.eprint("\tnot overwritten\n");
    } else {
        ctx.eprint(&alloc::format!("gzip: {out} already exists;\tnot overwritten\n"));
    }
    st.warn();
    false
}

/// Give the output the input's mode, owner and times; then drop the input.
fn finish_replace(ctx: &mut Ctx, o: &Opts, fs: &FsCtx, src: &str, dst: &str, m: &crate::fs::Metadata, mtime: i64) {
    if ctx.cred().is_root() {
        let _ = ops::chown(fs, dst, Some(m.uid), Some(m.gid), true);
    }
    let _ = ops::chmod(fs, dst, m.perm & 0o7777, true);
    let _ = ops::utimes(fs, dst, Some(m.atime), Some(crate::fs::Timespec::from_secs(mtime)), true);
    if !o.keep {
        let _ = ops::unlink(fs, src);
    }
}

fn compress_file(ctx: &mut Ctx, o: &Opts, path: &str, m: &crate::fs::Metadata, st: &mut Status) {
    let fs = ctx.fs();
    if !o.stdout && path.ends_with(o.suffix.as_str()) {
        if !o.quiet {
            ctx.eprint(&alloc::format!("gzip: {path} already has {} suffix -- unchanged\n", o.suffix));
        }
        st.warn();
        return;
    }
    let input = match open_read(&fs, path) {
        Ok(f) => f,
        Err(e) => {
            ctx.eprint(&alloc::format!("gzip: {path}: {e}\n"));
            st.error();
            return;
        }
    };
    let out_name = alloc::format!("{path}{}", o.suffix);
    let header = gz::Header {
        name: if o.save_name { Some(basename(path).to_string()) } else { None },
        mtime: if o.save_name { m.mtime.sec.clamp(0, u32::MAX as i64) as u32 } else { 0 },
        ..Default::default()
    };
    if o.verbose {
        ctx.eprint(&alloc::format!("{path}:\t"));
    }
    let sink: FileSink = if o.stdout {
        ctx.flush();
        FileSink(ctx.stdout())
    } else {
        if !may_write(ctx, o, &fs, &out_name, st) {
            return;
        }
        match create_file(&fs, &out_name, 0o600) {
            Ok(f) => FileSink(f),
            Err(e) => {
                ctx.eprint(&alloc::format!("gzip: {out_name}: {e}\n"));
                st.error();
                return;
            }
        }
    };
    let mut enc = GzEncoder::new(sink, o.level, &header);
    let overhead = enc.overhead() as i64;
    let r = ar::copy(&mut FileSource(input), &mut enc).and_then(|_| enc.finish());
    match r {
        Ok((_, bytes_in, bytes_out)) => {
            if o.verbose {
                let (i, out) = (bytes_in as i64, bytes_out as i64);
                let mut msg = ratio(i - (out - overhead), i);
                if !o.stdout {
                    msg.push_str(&alloc::format!(" -- {} {out_name}", if o.keep { "created" } else { "replaced with" }));
                }
                msg.push('\n');
                ctx.eprint(&msg);
            }
            if !o.stdout {
                finish_replace(ctx, o, &fs, path, &out_name, m, m.mtime.sec);
            }
        }
        Err(e) => {
            if !o.stdout {
                let _ = ops::unlink(&fs, &out_name);
            }
            if !quiet_io(&e) {
                ctx.eprint(&alloc::format!("gzip: {path}: {}\n", gz_msg(&e)));
            }
            st.error();
        }
    }
}

fn decompress_file(ctx: &mut Ctx, o: &Opts, path: &str, m: &crate::fs::Metadata, st: &mut Status) {
    let fs = ctx.fs();
    let writes_file = !o.stdout && !o.test;
    let mut out_name = match strip_suffix(path, &o.suffix) {
        Some(n) => n,
        None if writes_file => {
            if !o.quiet {
                ctx.eprint(&alloc::format!("gzip: {path}: unknown suffix -- ignored\n"));
            }
            st.warn();
            return;
        }
        None => String::new(),
    };
    let input = match open_read(&fs, path) {
        Ok(f) => f,
        Err(e) => {
            ctx.eprint(&alloc::format!("gzip: {path}: {e}\n"));
            st.error();
            return;
        }
    };
    let mut dec = GzDecoder::new(FileSource(input));
    let header = match dec.read_header() {
        Ok(h) => h.clone(),
        Err(e) => {
            ctx.eprint(&alloc::format!("gzip: {path}: {}\n", gz_msg(&e)));
            st.error();
            return;
        }
    };
    if writes_file && o.restore_name {
        if let Some(n) = header.name.as_deref().map(basename).filter(|n| !n.is_empty() && *n != "/" && *n != "." && *n != "..") {
            let dir = &path[..path.len() - basename(path).len()];
            out_name = alloc::format!("{dir}{n}");
        }
    }
    if o.verbose {
        ctx.eprint(&alloc::format!("{path}:\t"));
    }
    let r = if o.test {
        ar::copy(&mut dec, &mut ar::Discard::default())
    } else if o.stdout {
        ctx.flush();
        ar::copy(&mut dec, &mut FileSink(ctx.stdout()))
    } else {
        if !may_write(ctx, o, &fs, &out_name, st) {
            return;
        }
        match create_file(&fs, &out_name, 0o600) {
            Ok(f) => ar::copy(&mut dec, &mut FileSink(f)),
            Err(e) => {
                ctx.eprint(&alloc::format!("gzip: {out_name}: {e}\n"));
                st.error();
                return;
            }
        }
    };
    match r {
        Ok(_) => {
            if o.verbose {
                let mut msg = String::new();
                if o.test {
                    msg.push_str(" OK");
                } else {
                    let (i, out) = (dec.total_in() as i64, dec.total_out() as i64);
                    msg.push_str(&ratio(out - (i - dec.overhead() as i64), out));
                    if writes_file {
                        msg.push_str(&alloc::format!(" -- {} {out_name}", if o.keep { "created" } else { "replaced with" }));
                    }
                }
                msg.push('\n');
                ctx.eprint(&msg);
            }
            report_trailing(ctx, o, path, dec.trailing(), st);
            if writes_file {
                let mtime = if o.restore_name && header.mtime != 0 { header.mtime as i64 } else { m.mtime.sec };
                finish_replace(ctx, o, &fs, path, &out_name, m, mtime);
            }
        }
        Err(e) => {
            if writes_file {
                let _ = ops::unlink(&fs, &out_name);
            }
            if o.verbose {
                ctx.eprint("\n");
            }
            if !quiet_io(&e) {
                ctx.eprint(&alloc::format!("gzip: {path}: {}\n", gz_msg(&e)));
            }
            st.error();
        }
    }
}

const COL: usize = 19;

fn list_file(ctx: &mut Ctx, o: &Opts, path: &str, st: &mut Status, t: &mut ListTotals) {
    let fs = ctx.fs();
    let f = match open_read(&fs, path) {
        Ok(f) => f,
        Err(e) => {
            ctx.eprint(&alloc::format!("gzip: {path}: {e}\n"));
            st.error();
            return;
        }
    };
    let size = f.stat().map(|m| m.size).unwrap_or(0);
    let mut dec = GzDecoder::new(FileSource(f.clone()));
    let header = match dec.read_header() {
        Ok(h) => h.clone(),
        Err(e) => {
            ctx.eprint(&alloc::format!("gzip: {path}: {}\n", gz_msg(&e)));
            st.error();
            return;
        }
    };
    // Like GNU gzip: CRC and size come from the trailer at the end of the file.
    let mut tr = [0u8; 8];
    let got = if size >= 8 { f.pread(size - 8, &mut tr).map_err(io_err) } else { Ok(0) };
    let (crc, bytes_out) = match got {
        Ok(8) => (u32::from_le_bytes([tr[0], tr[1], tr[2], tr[3]]), u32::from_le_bytes([tr[4], tr[5], tr[6], tr[7]]) as i64),
        _ => {
            ctx.eprint(&alloc::format!("gzip: {path}: unexpected end of file\n"));
            st.error();
            return;
        }
    };
    let bytes_in = size as i64;
    let header_bytes = dec.overhead() as i64;
    if !t.printed_header {
        t.printed_header = true;
        if o.verbose {
            ctx.print("method  crc     date  time  ");
        }
        if !o.quiet {
            out!(ctx, "{:>COL$} {:>COL$}  ratio uncompressed_name\n", "compressed", "uncompressed");
        }
    }
    if o.verbose {
        let tm = crate::time::civil::from_unix(header.mtime as i64);
        out!(ctx, "defla {crc:08x} {}{:>3} {:02}:{:02} ", crate::time::civil::MONTHS[(tm.month - 1) as usize], tm.day, tm.hour, tm.min);
    }
    let name = strip_suffix(path, &o.suffix).unwrap_or_else(|| path.to_string());
    out!(ctx, "{bytes_in:>COL$} {bytes_out:>COL$} {} {name}\n", ratio(bytes_out - (bytes_in - header_bytes), bytes_out));
    t.files += 1;
    t.total_in += bytes_in;
    t.total_out += bytes_out;
    t.header_bytes = header_bytes;
}

fn list_totals(ctx: &mut Ctx, o: &Opts, t: &ListTotals) {
    if o.verbose {
        ctx.print("                            ");
    }
    out!(
        ctx,
        "{:>COL$} {:>COL$} {} (totals)\n",
        t.total_in,
        t.total_out,
        ratio(t.total_out - (t.total_in - t.header_bytes), t.total_out)
    );
}
