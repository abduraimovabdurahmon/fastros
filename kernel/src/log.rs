//! Kernel log: every message goes to the serial console and into a ring
//! buffer that `dmesg` / `journalctl -k` / `/proc/kmsg` read back.

use crate::sync::SpinLock;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Level {
    Emerg = 0,
    Alert = 1,
    Crit = 2,
    Err = 3,
    Warn = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Level {
    pub fn name(self) -> &'static str {
        match self {
            Level::Emerg => "emerg",
            Level::Alert => "alert",
            Level::Crit => "crit",
            Level::Err => "err",
            Level::Warn => "warn",
            Level::Notice => "notice",
            Level::Info => "info",
            Level::Debug => "debug",
        }
    }
    pub fn from_u8(v: u8) -> Level {
        match v {
            0 => Level::Emerg,
            1 => Level::Alert,
            2 => Level::Crit,
            3 => Level::Err,
            4 => Level::Warn,
            5 => Level::Notice,
            6 => Level::Info,
            _ => Level::Debug,
        }
    }
}

/// Messages above this level are kept in the ring but not echoed to serial.
static CONSOLE_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static SEQ: AtomicU64 = AtomicU64::new(0);

pub fn set_console_level(l: Level) {
    CONSOLE_LEVEL.store(l as u8, Ordering::Relaxed);
}

const RING_BYTES: usize = 256 * 1024;

/// One record per message: header + text, stored contiguously.
#[derive(Clone)]
pub struct Record {
    pub seq: u64,
    pub time_ns: u64,
    pub level: Level,
    pub facility: &'static str,
    pub text: String,
}

struct Ring {
    records: alloc::collections::VecDeque<Record>,
    bytes: usize,
}

static RING: SpinLock<Ring> = SpinLock::new(Ring { records: alloc::collections::VecDeque::new(), bytes: 0 });
/// Boot-time scratch for messages logged before the heap exists.
static EARLY: SpinLock<EarlyBuf> = SpinLock::new(EarlyBuf { buf: [0; 4096], len: 0 });
static HEAP_READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

struct EarlyBuf {
    buf: [u8; 4096],
    len: usize,
}

struct LineWriter<'a> {
    out: &'a mut dyn FnMut(&[u8]),
}
impl Write for LineWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        (self.out)(s.as_bytes());
        Ok(())
    }
}

/// Format `[ssss.uuuuuu] ` for a monotonic timestamp.
pub fn fmt_timestamp(ns: u64) -> String {
    let mut s = String::new();
    let _ = write!(s, "[{:5}.{:06}]", ns / 1_000_000_000, (ns / 1000) % 1_000_000);
    s
}

pub fn log(level: Level, facility: &'static str, args: fmt::Arguments) {
    let now = crate::time::now_ns();
    let echo = level as u8 <= CONSOLE_LEVEL.load(Ordering::Relaxed);
    if !HEAP_READY.load(Ordering::Acquire) {
        // Before the heap: serial + a fixed buffer, copied into the ring later.
        let mut early = EARLY.lock();
        let mut w = LineWriter {
            out: &mut |b: &[u8]| {
                crate::drivers::serial::write(b);
                let e = &mut *early;
                let n = b.len().min(e.buf.len() - e.len);
                e.buf[e.len..e.len + n].copy_from_slice(&b[..n]);
                e.len += n;
            },
        };
        let _ = write!(w, "[{:5}.{:06}] {}: {}\n", now / 1_000_000_000, (now / 1000) % 1_000_000, facility, args);
        return;
    }
    let mut text = String::new();
    let _ = write!(text, "{}", args);
    if echo {
        let _g = crate::drivers::serial::LOCK.lock();
        let mut w = LineWriter { out: &mut |b: &[u8]| crate::drivers::serial::write_raw(b) };
        let _ = write!(w, "[{:5}.{:06}] {}: {}\n", now / 1_000_000_000, (now / 1000) % 1_000_000, facility, text);
    }
    push(Record { seq: SEQ.fetch_add(1, Ordering::Relaxed), time_ns: now, level, facility, text });
}

fn push(r: Record) {
    let mut ring = RING.lock();
    ring.bytes += r.text.len() + 48;
    ring.records.push_back(r);
    while ring.bytes > RING_BYTES {
        match ring.records.pop_front() {
            Some(old) => ring.bytes -= old.text.len() + 48,
            None => break,
        }
    }
}

/// Switch from the early buffer to the heap-backed ring.
pub fn heap_ready() {
    let early: Vec<u8> = {
        let e = EARLY.lock();
        e.buf[..e.len].to_vec()
    };
    HEAP_READY.store(true, Ordering::Release);
    for line in early.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let text = String::from_utf8_lossy(line);
        // Early lines already carry "[ts] facility: " — keep the text after it.
        let body = text.split_once("] ").map(|(_, b)| b).unwrap_or(&text);
        let (facility, msg) = body.split_once(": ").unwrap_or(("kernel", body));
        let facility: &'static str = match facility {
            "boot" => "boot",
            "mm" => "mm",
            "cpu" => "cpu",
            _ => "kernel",
        };
        push(Record {
            seq: SEQ.fetch_add(1, Ordering::Relaxed),
            time_ns: 0,
            level: Level::Info,
            facility,
            text: String::from(msg),
        });
    }
}

/// Copy of the log records (oldest first).
pub fn records() -> Vec<Record> {
    RING.lock().records.iter().cloned().collect()
}

pub fn clear() {
    let mut r = RING.lock();
    r.records.clear();
    r.bytes = 0;
}

#[macro_export]
macro_rules! kinfo {
    ($fac:literal, $($a:tt)*) => { $crate::log::log($crate::log::Level::Info, $fac, format_args!($($a)*)) };
}
#[macro_export]
macro_rules! knotice {
    ($fac:literal, $($a:tt)*) => { $crate::log::log($crate::log::Level::Notice, $fac, format_args!($($a)*)) };
}
#[macro_export]
macro_rules! kwarn {
    ($fac:literal, $($a:tt)*) => { $crate::log::log($crate::log::Level::Warn, $fac, format_args!($($a)*)) };
}
#[macro_export]
macro_rules! kerr {
    ($fac:literal, $($a:tt)*) => { $crate::log::log($crate::log::Level::Err, $fac, format_args!($($a)*)) };
}
#[macro_export]
macro_rules! kdebug {
    ($fac:literal, $($a:tt)*) => { $crate::log::log($crate::log::Level::Debug, $fac, format_args!($($a)*)) };
}
