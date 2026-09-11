//! Terminals: a Linux-compatible line discipline (`n_tty`) between a
//! terminal driver (SSH channel, serial port) and processes.
//!
//! Input path  (driver → `receive`): CR/NL mapping, signal characters
//! (^C → SIGINT to the foreground process group), canonical line editing
//! (erase, word-erase, kill, EOF, literal-next, reprint) and echo.
//! Output path (process → `write`): `OPOST|ONLCR` turns `\n` into `\r\n`,
//! which is what keeps every program's output aligned on a raw SSH pty.

use crate::errno::{Errno, KResult};
use crate::fs::file::{flags, File, Poll};
use crate::fs::{FileType, Metadata, Timespec};
use crate::sync::{SpinLock, WaitQueue, WaitResult};
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub mod consts {
    // c_iflag
    pub const ISTRIP: u32 = 0x020;
    pub const INLCR: u32 = 0x040;
    pub const IGNCR: u32 = 0x080;
    pub const ICRNL: u32 = 0x100;
    pub const IXON: u32 = 0x400;
    pub const IUTF8: u32 = 0x4000;
    // c_oflag
    pub const OPOST: u32 = 0x01;
    pub const ONLCR: u32 = 0x04;
    pub const OCRNL: u32 = 0x08;
    // c_cflag
    pub const B38400: u32 = 0x0F;
    pub const CS8: u32 = 0x30;
    pub const CREAD: u32 = 0x80;
    pub const HUPCL: u32 = 0x400;
    // c_lflag
    pub const ISIG: u32 = 0x001;
    pub const ICANON: u32 = 0x002;
    pub const ECHO: u32 = 0x008;
    pub const ECHOE: u32 = 0x010;
    pub const ECHOK: u32 = 0x020;
    pub const ECHONL: u32 = 0x040;
    pub const NOFLSH: u32 = 0x080;
    pub const ECHOCTL: u32 = 0x200;
    pub const ECHOKE: u32 = 0x800;
    pub const IEXTEN: u32 = 0x8000;
    // c_cc indices
    pub const VINTR: usize = 0;
    pub const VQUIT: usize = 1;
    pub const VERASE: usize = 2;
    pub const VKILL: usize = 3;
    pub const VEOF: usize = 4;
    pub const VTIME: usize = 5;
    pub const VMIN: usize = 6;
    pub const VSUSP: usize = 10;
    pub const VEOL: usize = 11;
    pub const VREPRINT: usize = 12;
    pub const VWERASE: usize = 14;
    pub const VLNEXT: usize = 15;
    pub const VEOL2: usize = 16;
    pub const NCCS: usize = 19;
    // ioctls
    pub const TCGETS: u32 = 0x5401;
    pub const TCSETS: u32 = 0x5402;
    pub const TCSETSW: u32 = 0x5403;
    pub const TCSETSF: u32 = 0x5404;
    pub const TCFLSH: u32 = 0x540B;
    pub const TIOCSCTTY: u32 = 0x540E;
    pub const TIOCGPGRP: u32 = 0x540F;
    pub const TIOCSPGRP: u32 = 0x5410;
    pub const TIOCOUTQ: u32 = 0x5411;
    pub const TIOCGWINSZ: u32 = 0x5413;
    pub const TIOCSWINSZ: u32 = 0x5414;
    pub const FIONREAD: u32 = 0x541B;
    pub const TIOCNOTTY: u32 = 0x5422;
    pub const TIOCGSID: u32 = 0x5429;
}
use consts::*;

/// Kernel `struct termios` (the `TCGETS` layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub line: u8,
    pub cc: [u8; NCCS],
}

impl Default for Termios {
    fn default() -> Self {
        let mut cc = [0u8; NCCS];
        cc[VINTR] = 0x03;
        cc[VQUIT] = 0x1C;
        cc[VERASE] = 0x7F;
        cc[VKILL] = 0x15;
        cc[VEOF] = 0x04;
        cc[VTIME] = 0;
        cc[VMIN] = 1;
        cc[8] = 0x11; // VSTART
        cc[9] = 0x13; // VSTOP
        cc[VSUSP] = 0x1A;
        cc[VREPRINT] = 0x12;
        cc[13] = 0x0F; // VDISCARD
        cc[VWERASE] = 0x17;
        cc[VLNEXT] = 0x16;
        Termios {
            iflag: ICRNL | IUTF8,
            oflag: OPOST | ONLCR,
            cflag: B38400 | CS8 | CREAD | HUPCL,
            lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
            line: 0,
            cc,
        }
    }
}

impl Termios {
    pub fn canonical(&self) -> bool {
        self.lflag & ICANON != 0
    }
    /// `cfmakeraw`: no processing at all.
    pub fn make_raw(&mut self) {
        self.iflag &= !(ICRNL | INLCR | IGNCR | ISTRIP | IXON);
        self.oflag &= !OPOST;
        self.lflag &= !(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
        self.cc[VMIN] = 1;
        self.cc[VTIME] = 0;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WinSize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

/// The device side of a terminal.
pub trait TtyDriver: Send + Sync {
    /// Send processed output. May block (flow control) unless `echo` is set,
    /// in which case it must not block (it runs in the driver's own context).
    fn write(&self, data: &[u8], echo: bool) -> KResult<()>;
    /// Bytes queued towards the device and not yet sent.
    fn pending(&self) -> usize {
        0
    }
}

struct Ldisc {
    /// Canonical mode: completed lines (an empty line is an EOF marker).
    lines: VecDeque<Vec<u8>>,
    /// Canonical mode: the line being edited.
    edit: Vec<u8>,
    /// Raw mode input, and leftovers from canonical reads.
    raw: VecDeque<u8>,
    literal_next: bool,
}

pub struct Tty {
    pub name: String,
    driver: Arc<dyn TtyDriver>,
    termios: SpinLock<Termios>,
    winsize: SpinLock<WinSize>,
    ld: SpinLock<Ldisc>,
    pub read_wq: WaitQueue,
    fg_pgrp: AtomicU32,
    session: AtomicU32,
    hung_up: AtomicBool,
}

const MAX_LINE: usize = 4095;
const MAX_QUEUED: usize = 64 * 1024;

impl Tty {
    pub fn new(name: &str, driver: Arc<dyn TtyDriver>, ws: WinSize) -> Arc<Tty> {
        Arc::new(Tty {
            name: String::from(name),
            driver,
            termios: SpinLock::new(Termios::default()),
            winsize: SpinLock::new(ws),
            ld: SpinLock::new(Ldisc { lines: VecDeque::new(), edit: Vec::new(), raw: VecDeque::new(), literal_next: false }),
            read_wq: WaitQueue::new(),
            fg_pgrp: AtomicU32::new(0),
            session: AtomicU32::new(0),
            hung_up: AtomicBool::new(false),
        })
    }

    pub fn termios(&self) -> Termios {
        *self.termios.lock()
    }

    pub fn set_termios(&self, t: Termios) {
        let was_canon = self.termios.lock().canonical();
        *self.termios.lock() = t;
        if was_canon && !t.canonical() {
            // Hand everything typed so far to raw readers.
            let mut ld = self.ld.lock();
            let lines: Vec<Vec<u8>> = ld.lines.drain(..).collect();
            for l in lines {
                ld.raw.extend(l);
            }
            let edit = core::mem::take(&mut ld.edit);
            ld.raw.extend(edit);
        }
        self.read_wq.wake_all();
    }

    pub fn winsize(&self) -> WinSize {
        *self.winsize.lock()
    }

    pub fn set_winsize(&self, ws: WinSize) {
        let changed = {
            let mut w = self.winsize.lock();
            let c = *w != ws;
            *w = ws;
            c
        };
        if changed {
            self.signal_fg(crate::proc::signal::SIGWINCH);
        }
    }

    pub fn fg_pgrp(&self) -> u32 {
        self.fg_pgrp.load(Ordering::Relaxed)
    }
    pub fn set_fg_pgrp(&self, pg: u32) {
        self.fg_pgrp.store(pg, Ordering::Relaxed);
    }
    pub fn session(&self) -> u32 {
        self.session.load(Ordering::Relaxed)
    }
    pub fn set_session(&self, sid: u32) {
        self.session.store(sid, Ordering::Relaxed);
    }

    fn signal_fg(&self, sig: u32) {
        let pg = self.fg_pgrp();
        if pg != 0 {
            let _ = crate::proc::kill(&crate::proc::kernel(), -(pg as i64), sig);
        }
    }

    /// The terminal went away (SSH disconnect): SIGHUP the session, wake readers.
    pub fn hangup(&self) {
        if self.hung_up.swap(true, Ordering::AcqRel) {
            return;
        }
        let sid = self.session();
        if sid != 0 {
            for p in crate::proc::all() {
                if p.sid.load(Ordering::Relaxed) == sid {
                    p.signal(crate::proc::signal::SIGHUP);
                }
            }
        }
        self.read_wq.wake_all();
    }

    pub fn is_hung_up(&self) -> bool {
        self.hung_up.load(Ordering::Acquire)
    }

    // ── output ──────────────────────────────────────────────────────────

    fn process_output(t: &Termios, data: &[u8], out: &mut Vec<u8>) {
        if t.oflag & OPOST == 0 {
            out.extend_from_slice(data);
            return;
        }
        for &b in data {
            match b {
                b'\n' if t.oflag & ONLCR != 0 => out.extend_from_slice(b"\r\n"),
                b'\r' if t.oflag & OCRNL != 0 => out.push(b'\n'),
                _ => out.push(b),
            }
        }
    }

    /// Process output from a program.
    pub fn write(&self, data: &[u8]) -> KResult<usize> {
        if self.is_hung_up() {
            return Err(Errno::EIO);
        }
        let t = self.termios();
        let mut out = Vec::with_capacity(data.len() + data.len() / 8);
        Self::process_output(&t, data, &mut out);
        self.driver.write(&out, false)?;
        Ok(data.len())
    }

    fn echo(&self, t: &Termios, bytes: &[u8]) {
        let mut out = Vec::with_capacity(bytes.len() + 2);
        Self::process_output(t, bytes, &mut out);
        let _ = self.driver.write(&out, true);
    }

    /// Echo one input character the way `n_tty` does (`^C` for controls).
    fn echo_char(&self, t: &Termios, c: u8) {
        if t.lflag & ECHO == 0 {
            if c == b'\n' && t.lflag & ECHONL != 0 {
                self.echo(t, b"\n");
            }
            return;
        }
        if t.lflag & ECHOCTL != 0 && (c < 0x20 && c != b'\t' && c != b'\n' || c == 0x7F) {
            self.echo(t, &[b'^', c ^ 0x40]);
        } else {
            self.echo(t, &[c]);
        }
    }

    /// Visible width of an echoed character (for erase).
    fn echo_width(t: &Termios, c: u8) -> usize {
        if t.lflag & ECHOCTL != 0 && (c < 0x20 && c != b'\t' || c == 0x7F) {
            2
        } else if c & 0xC0 == 0x80 {
            0 // UTF-8 continuation byte
        } else {
            1
        }
    }

    // ── input ───────────────────────────────────────────────────────────

    /// Feed bytes typed on the terminal.
    pub fn receive(&self, data: &[u8]) {
        let t = self.termios();
        for &b in data {
            self.receive_byte(&t, b);
        }
        self.read_wq.wake_all();
    }

    fn receive_byte(&self, t: &Termios, mut c: u8) {
        if t.iflag & ISTRIP != 0 {
            c &= 0x7F;
        }
        let literal = {
            let mut ld = self.ld.lock();
            core::mem::replace(&mut ld.literal_next, false)
        };
        if !literal {
            if c == b'\r' {
                if t.iflag & IGNCR != 0 {
                    return;
                }
                if t.iflag & ICRNL != 0 {
                    c = b'\n';
                }
            } else if c == b'\n' && t.iflag & INLCR != 0 {
                c = b'\r';
            }
            if t.lflag & ISIG != 0 {
                let sig = if c == t.cc[VINTR] {
                    Some(crate::proc::signal::SIGINT)
                } else if c == t.cc[VQUIT] {
                    Some(crate::proc::signal::SIGQUIT)
                } else if c == t.cc[VSUSP] {
                    Some(crate::proc::signal::SIGTSTP)
                } else {
                    None
                };
                if let Some(sig) = sig {
                    if t.lflag & NOFLSH == 0 {
                        let mut ld = self.ld.lock();
                        ld.edit.clear();
                        ld.lines.clear();
                        ld.raw.clear();
                    }
                    self.echo_char(t, c);
                    if sig != crate::proc::signal::SIGTSTP {
                        self.signal_fg(sig);
                    }
                    return;
                }
            }
        }
        if !t.canonical() {
            let mut ld = self.ld.lock();
            if ld.raw.len() < MAX_QUEUED {
                ld.raw.push_back(c);
            }
            drop(ld);
            self.echo_char(t, c);
            return;
        }
        if !literal {
            if t.lflag & IEXTEN != 0 && c == t.cc[VLNEXT] {
                self.ld.lock().literal_next = true;
                if t.lflag & ECHO != 0 {
                    self.echo(t, b"^\x08");
                }
                return;
            }
            if c == t.cc[VERASE] || c == 0x08 {
                self.erase(t, false);
                return;
            }
            if t.lflag & IEXTEN != 0 && c == t.cc[VWERASE] {
                self.erase(t, true);
                return;
            }
            if c == t.cc[VKILL] {
                loop {
                    if self.ld.lock().edit.is_empty() {
                        break;
                    }
                    self.erase(t, false);
                }
                return;
            }
            if t.lflag & IEXTEN != 0 && c == t.cc[VREPRINT] {
                let line = self.ld.lock().edit.clone();
                self.echo_char(t, c);
                self.echo(t, b"\n");
                self.echo(t, &line);
                return;
            }
            if c == t.cc[VEOF] {
                let mut ld = self.ld.lock();
                let line = core::mem::take(&mut ld.edit);
                ld.lines.push_back(line); // empty = EOF marker
                return;
            }
            if c == b'\n' || (c != 0 && (c == t.cc[VEOL] || c == t.cc[VEOL2])) {
                let mut ld = self.ld.lock();
                let mut line = core::mem::take(&mut ld.edit);
                line.push(c);
                ld.lines.push_back(line);
                drop(ld);
                self.echo_char(t, c);
                return;
            }
        }
        let mut ld = self.ld.lock();
        if ld.edit.len() < MAX_LINE {
            ld.edit.push(c);
            drop(ld);
            self.echo_char(t, c);
        } else {
            drop(ld);
            self.echo(t, b"\x07"); // bell: line full
        }
    }

    fn erase(&self, t: &Termios, word: bool) {
        let mut removed: Vec<u8> = Vec::new();
        {
            let mut ld = self.ld.lock();
            if word {
                while ld.edit.last().is_some_and(|&c| c == b' ' || c == b'\t') {
                    removed.push(ld.edit.pop().expect("checked"));
                }
                while ld.edit.last().is_some_and(|&c| c != b' ' && c != b'\t') {
                    removed.push(ld.edit.pop().expect("checked"));
                }
            } else {
                // Remove one whole UTF-8 character.
                while let Some(c) = ld.edit.pop() {
                    removed.push(c);
                    if c & 0xC0 != 0x80 {
                        break;
                    }
                }
            }
        }
        if t.lflag & ECHO != 0 && t.lflag & ECHOE != 0 {
            let cols: usize = removed.iter().map(|&c| Self::echo_width(t, c)).sum();
            for _ in 0..cols {
                self.echo(t, b"\x08 \x08");
            }
        }
    }

    /// Read input as a program sees it.
    pub fn read(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let t = self.termios();
        let deadline = if !t.canonical() && t.cc[VMIN] == 0 {
            Some(crate::time::now_ns() + t.cc[VTIME] as u64 * 100_000_000)
        } else {
            None
        };
        let mut take = |ld: &mut Ldisc| -> Option<usize> {
            if !ld.raw.is_empty() {
                let n = buf.len().min(ld.raw.len());
                for (i, b) in ld.raw.drain(..n).enumerate() {
                    buf[i] = b;
                }
                return Some(n);
            }
            if t.canonical() {
                if let Some(mut line) = ld.lines.pop_front() {
                    if line.is_empty() {
                        return Some(0); // EOF
                    }
                    let n = buf.len().min(line.len());
                    buf[..n].copy_from_slice(&line[..n]);
                    if n < line.len() {
                        line.drain(..n);
                        ld.lines.push_front(line);
                    }
                    return Some(n);
                }
            }
            None
        };
        loop {
            if let Some(n) = take(&mut self.ld.lock()) {
                return Ok(n);
            }
            if self.is_hung_up() {
                return Ok(0);
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            let r = self.read_wq.wait_until_interruptible(
                || {
                    let ld = self.ld.lock();
                    (!ld.raw.is_empty() || (t.canonical() && !ld.lines.is_empty()) || self.is_hung_up()).then_some(())
                },
                deadline,
            );
            match r {
                Ok(()) => {}
                Err(WaitResult::TimedOut) => return Ok(0),
                Err(WaitResult::Interrupted) => return Err(Errno::EINTR),
            }
        }
    }

    pub fn input_ready(&self) -> bool {
        let ld = self.ld.lock();
        !ld.raw.is_empty() || (self.termios().canonical() && !ld.lines.is_empty())
    }

    pub fn flush_input(&self) {
        let mut ld = self.ld.lock();
        ld.raw.clear();
        ld.lines.clear();
        ld.edit.clear();
    }

    pub fn output_pending(&self) -> usize {
        self.driver.pending()
    }

    fn ioctl(self: &Arc<Self>, req: u32, arg: usize) -> KResult<usize> {
        use crate::uaccess::{read_obj, write_obj};
        match req {
            TCGETS => write_obj(arg, &self.termios()).map(|_| 0),
            TCSETS | TCSETSW | TCSETSF => {
                let t: Termios = read_obj(arg)?;
                if req == TCSETSF {
                    self.flush_input();
                }
                self.set_termios(t);
                Ok(0)
            }
            TIOCGWINSZ => write_obj(arg, &self.winsize()).map(|_| 0),
            TIOCSWINSZ => {
                let ws: WinSize = read_obj(arg)?;
                self.set_winsize(ws);
                Ok(0)
            }
            TIOCGPGRP => write_obj(arg, &(self.fg_pgrp() as i32)).map(|_| 0),
            TIOCSPGRP => {
                let pg: i32 = read_obj(arg)?;
                self.set_fg_pgrp(pg as u32);
                Ok(0)
            }
            TIOCGSID => write_obj(arg, &(self.session() as i32)).map(|_| 0),
            FIONREAD => {
                let ld = self.ld.lock();
                let n = ld.raw.len() + ld.lines.iter().map(|l| l.len()).sum::<usize>();
                drop(ld);
                write_obj(arg, &(n as i32)).map(|_| 0)
            }
            TIOCOUTQ => write_obj(arg, &(self.output_pending() as i32)).map(|_| 0),
            TCFLSH => {
                if arg == 0 || arg == 2 {
                    self.flush_input();
                }
                Ok(0)
            }
            TIOCSCTTY => {
                let me = crate::proc::current();
                *me.ctty.lock() = Some(self.clone());
                self.set_session(me.sid.load(Ordering::Relaxed));
                self.set_fg_pgrp(me.pgid.load(Ordering::Relaxed));
                Ok(0)
            }
            TIOCNOTTY => {
                *crate::proc::current().ctty.lock() = None;
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        }
    }
}

/// An open terminal.
pub struct TtyFile {
    tty: Arc<Tty>,
    flags: AtomicU32,
}

impl TtyFile {
    pub fn new(tty: Arc<Tty>, flags: u32) -> Arc<TtyFile> {
        Arc::new(TtyFile { tty, flags: AtomicU32::new(flags) })
    }
}

impl File for TtyFile {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        self.tty.read(buf, self.flags.load(Ordering::Relaxed) & flags::O_NONBLOCK != 0)
    }
    fn write(&self, buf: &[u8]) -> KResult<usize> {
        self.tty.write(buf)
    }
    fn stat(&self) -> KResult<Metadata> {
        let now = Timespec::now();
        Ok(Metadata {
            dev: 0,
            ino: 0,
            kind: FileType::CharDevice,
            perm: 0o620,
            nlink: 1,
            uid: 0,
            gid: 5,
            size: 0,
            blocks: 0,
            blksize: 1024,
            rdev: crate::fs::makedev(136, 0),
            atime: now,
            mtime: now,
            ctime: now,
        })
    }
    fn ioctl(&self, req: u32, arg: usize) -> KResult<usize> {
        self.tty.ioctl(req, arg)
    }
    fn poll(&self) -> Poll {
        let mut p = Poll::OUT;
        if self.tty.input_ready() {
            p = p | Poll::IN;
        }
        if self.tty.is_hung_up() {
            p = p | Poll::HUP | Poll::IN;
        }
        p
    }
    fn wait_queue(&self) -> Option<&WaitQueue> {
        Some(&self.tty.read_wq)
    }
    fn tty(&self) -> Option<Arc<Tty>> {
        Some(self.tty.clone())
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn set_flags(&self, f: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !flags::SETFL_MASK) | (f & flags::SETFL_MASK), Ordering::Relaxed);
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ── pseudo-terminal numbering (/dev/pts/N) ─────────────────────────────────

static PTS: SpinLock<Vec<Option<alloc::sync::Weak<Tty>>>> = SpinLock::new(Vec::new());

/// Allocate the lowest free pts number and create the terminal.
pub fn alloc_pty(driver: Arc<dyn TtyDriver>, ws: WinSize) -> (u32, Arc<Tty>) {
    let mut pts = PTS.lock();
    let idx = pts.iter().position(|s| s.as_ref().is_none_or(|w| w.strong_count() == 0)).unwrap_or(pts.len());
    let tty = Tty::new(&alloc::format!("pts/{idx}"), driver, ws);
    if idx == pts.len() {
        pts.push(Some(Arc::downgrade(&tty)));
    } else {
        pts[idx] = Some(Arc::downgrade(&tty));
    }
    (idx as u32, tty)
}

/// Live pseudo-terminals (for `who`, /dev/pts).
pub fn ptys() -> Vec<Arc<Tty>> {
    PTS.lock().iter().filter_map(|w| w.as_ref().and_then(|w| w.upgrade())).collect()
}
