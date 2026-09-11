//! Archivers and compressors: `gzip`/`gunzip`/`zcat`, `tar`, `zip`/`unzip`.
//!
//! The formats live in the `fastros-archive` crate; this module maps them
//! onto the VFS and reproduces the behaviour and output of GNU gzip, GNU tar
//! and Info-ZIP. One security difference is deliberate: extraction refuses
//! member names with `..` and never writes through a symbolic link that the
//! same archive created (the classic "symlink then file" escape).

pub mod gzip;
pub mod tar;
pub mod zip;

use crate::errno::Errno;
use crate::fs::file::{flags, File};
use crate::fs::ops::{self, Ctx as FsCtx};
use crate::fs::{FileType, Metadata, Timespec};
use crate::shell::ctx::Ctx;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use fastros_archive as ar;

/// Map a kernel error into the archive crate's error (keeps `strerror` text).
pub(crate) fn io_err(e: Errno) -> ar::Error {
    ar::Error::Io(e.desc())
}

/// Stop long operations on Ctrl-C and let other tasks run between chunks
/// (the kernel is not preemptive).
fn checkpoint() -> ar::Result<()> {
    if crate::proc::interrupted() {
        return Err(io_err(Errno::EINTR));
    }
    crate::sched::cond_resched();
    Ok(())
}

/// Sequential source over a kernel file.
pub(crate) struct FileSource(pub Arc<dyn File>);

impl ar::Read for FileSource {
    fn read(&mut self, buf: &mut [u8]) -> ar::Result<usize> {
        checkpoint()?;
        self.0.read(buf).map_err(io_err)
    }
}

/// Sink over a kernel file.
pub(crate) struct FileSink(pub Arc<dyn File>);

impl ar::Write for FileSink {
    fn write_all(&mut self, buf: &[u8]) -> ar::Result<()> {
        checkpoint()?;
        self.0.write_all(buf).map_err(io_err)
    }
}

/// Random access over a kernel file (zip central directories).
pub(crate) struct FileAt {
    f: Arc<dyn File>,
    size: u64,
}

impl FileAt {
    pub fn new(f: Arc<dyn File>) -> Result<FileAt, Errno> {
        let size = f.stat()?.size;
        Ok(FileAt { f, size })
    }
}

impl ar::ReadAt for FileAt {
    fn size(&self) -> u64 {
        self.size
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> ar::Result<usize> {
        checkpoint()?;
        let n = buf.len().min(self.size.saturating_sub(off) as usize);
        self.f.pread(off, &mut buf[..n]).map_err(io_err)
    }
}

/// Replays bytes already read (format sniffing) before the rest of a source.
pub(crate) struct Replay<R> {
    head: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R: ar::Read> Replay<R> {
    /// Read up to `n` bytes from `inner` for inspection.
    pub fn sniff(mut inner: R, n: usize) -> ar::Result<Replay<R>> {
        let mut head = alloc::vec![0u8; n];
        let mut got = 0;
        while got < n {
            let k = inner.read(&mut head[got..])?;
            if k == 0 {
                break;
            }
            got += k;
        }
        head.truncate(got);
        Ok(Replay { head, pos: 0, inner })
    }

    pub fn head(&self) -> &[u8] {
        &self.head
    }
}

impl<R: ar::Read> ar::Read for Replay<R> {
    fn read(&mut self, buf: &mut [u8]) -> ar::Result<usize> {
        if self.pos < self.head.len() {
            let n = buf.len().min(self.head.len() - self.pos);
            buf[..n].copy_from_slice(&self.head[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

// ── filesystem helpers shared by the extractors ────────────────────────────

pub(crate) fn join(dir: &str, name: &str) -> String {
    if name.is_empty() {
        return String::from(dir);
    }
    if dir.is_empty() || dir == "." {
        return String::from(name);
    }
    if dir.ends_with('/') {
        alloc::format!("{dir}{name}")
    } else {
        alloc::format!("{dir}/{name}")
    }
}

pub(crate) fn basename(p: &str) -> &str {
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "/";
    }
    t.rsplit('/').next().unwrap_or(t)
}

pub(crate) fn open_read(fs: &FsCtx, path: &str) -> Result<Arc<dyn File>, Errno> {
    ops::open(fs, path, flags::O_RDONLY, 0)
}

/// Create (or truncate) a regular file for writing, never following a
/// symbolic link at the final component.
pub(crate) fn create_file(fs: &FsCtx, path: &str, mode: u16) -> Result<Arc<dyn File>, Errno> {
    ops::open(fs, path, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC | flags::O_NOFOLLOW, mode)
}

pub(crate) fn lstat(fs: &FsCtx, path: &str) -> Result<Metadata, Errno> {
    ops::stat(fs, path, false)
}

pub(crate) fn umask(ctx: &Ctx) -> u16 {
    ctx.proc.fs.lock().umask
}

/// Remove whatever non-directory is at `path` so a new node can take it.
pub(crate) fn clear_path(fs: &FsCtx, path: &str) -> Result<(), Errno> {
    match lstat(fs, path) {
        Ok(m) if m.kind == FileType::Directory => Err(Errno::EISDIR),
        Ok(_) => ops::unlink(fs, path),
        Err(Errno::ENOENT) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Set a file's times (atime = now, like GNU tar and Info-ZIP).
pub(crate) fn set_mtime(fs: &FsCtx, path: &str, mtime: i64, follow: bool) {
    let _ = ops::utimes(fs, path, Some(Timespec::now()), Some(Timespec::from_secs(mtime)), follow);
}

/// Paths of symbolic links created during one extraction. Nothing is ever
/// written through them, so a hostile archive cannot plant `x -> /etc` and
/// then write `x/passwd`.
#[derive(Default)]
pub(crate) struct LinkGuard {
    links: BTreeSet<String>,
}

impl LinkGuard {
    pub fn add(&mut self, rel: &str) {
        self.links.insert(String::from(rel.trim_end_matches('/')));
    }

    /// Does `rel` (relative to the destination) pass through one of our links?
    pub fn crosses(&self, rel: &str) -> bool {
        let mut cur = String::new();
        let parts: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
        for (i, c) in parts.iter().enumerate() {
            if i + 1 == parts.len() {
                break;
            }
            if !cur.is_empty() {
                cur.push('/');
            }
            cur.push_str(c);
            if self.links.contains(&cur) {
                return true;
            }
        }
        false
    }

    /// A link created earlier replaced by a later member is no longer ours.
    pub fn forget(&mut self, rel: &str) {
        self.links.remove(rel.trim_end_matches('/'));
    }
}

/// `-rwxr-sr-t` for a full or permission-only mode with a type letter.
pub(crate) fn perm_string(letter: char, mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(letter);
    let bit = |b: u32, c: char| if mode & b != 0 { c } else { '-' };
    let special = |x: bool, sp: bool, on: char, off: char| match (x, sp) {
        (true, true) => on,
        (false, true) => off,
        (true, false) => 'x',
        (false, false) => '-',
    };
    s.push(bit(0o400, 'r'));
    s.push(bit(0o200, 'w'));
    s.push(special(mode & 0o100 != 0, mode & 0o4000 != 0, 's', 'S'));
    s.push(bit(0o040, 'r'));
    s.push(bit(0o020, 'w'));
    s.push(special(mode & 0o010 != 0, mode & 0o2000 != 0, 's', 'S'));
    s.push(bit(0o004, 'r'));
    s.push(bit(0o002, 'w'));
    s.push(special(mode & 0o001 != 0, mode & 0o1000 != 0, 't', 'T'));
    s
}

/// `YYYY-MM-DD HH:MM` (UTC), the GNU tar / Info-ZIP listing time.
pub(crate) fn listing_time(t: i64) -> String {
    let tm = crate::time::civil::from_unix(t);
    alloc::format!("{:04}-{:02}-{:02} {:02}:{:02}", tm.year, tm.month, tm.day, tm.hour, tm.min)
}

/// GNU `--quoting-style=escape` for names in listings and messages.
pub(crate) fn quote_name(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            '\r' => o.push_str("\\r"),
            c if (c as u32) < 0x20 || c as u32 == 0x7F => o.push_str(&alloc::format!("\\{:03o}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// Is standard input a terminal (interactive prompts)?
pub(crate) fn stdin_is_tty(ctx: &Ctx) -> bool {
    ctx.stdin_tty().is_some()
}

/// Read one line from standard input (for overwrite prompts); `None` at EOF.
pub(crate) fn read_answer(ctx: &mut Ctx) -> Option<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match ctx.read_stdin(&mut b) {
            Ok(1) => {
                if b[0] == b'\n' {
                    break;
                }
                line.push(b[0]);
            }
            _ => {
                if line.is_empty() {
                    return None;
                }
                break;
            }
        }
    }
    Some(String::from_utf8_lossy(&line).into_owned())
}
