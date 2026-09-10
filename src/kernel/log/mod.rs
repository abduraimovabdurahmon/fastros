//! Kernel ring buffer log — equivalent to Linux's printk ring buffer.
//!
//! Stores log entries in a circular buffer. The `journalctl` shell command
//! reads and displays the entries.
//!
//! Linux equivalent: kernel/printk/printk.c  kernel/printk/printk_ringbuf.c

// ── Log levels (same values as Linux) ────────────────────────────────────────

#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum Level {
    Emergency = 0, // system is unusable
    Alert     = 1, // action must be taken immediately
    Critical  = 2, // critical conditions
    Error     = 3, // error conditions
    Warning   = 4, // warning conditions
    Notice    = 5, // normal but significant condition
    Info      = 6, // informational
    Debug     = 7, // debug-level messages
}

impl Level {
    pub fn as_str(self) -> &'static [u8] {
        match self {
            Level::Emergency => b"EMERG  ",
            Level::Alert     => b"ALERT  ",
            Level::Critical  => b"CRIT   ",
            Level::Error     => b"ERROR  ",
            Level::Warning   => b"WARNING",
            Level::Notice    => b"NOTICE ",
            Level::Info      => b"INFO   ",
            Level::Debug     => b"DEBUG  ",
        }
    }
}

// ── Log entry ─────────────────────────────────────────────────────────────────

const MSG_LEN: usize = 120;

#[derive(Copy, Clone)]
pub struct Entry {
    pub seq:     u64,
    pub ticks:   u64,  // uptime in scheduler ticks at log time
    pub level:   Level,
    pub msg:     [u8; MSG_LEN],
    pub msg_len: usize,
}

impl Entry {
    const fn empty() -> Self {
        Self {
            seq: 0, ticks: 0,
            level: Level::Info,
            msg: [0; MSG_LEN],
            msg_len: 0,
        }
    }
}

// ── Ring buffer ───────────────────────────────────────────────────────────────

const RING_SIZE: usize = 512;

static mut RING:  [Entry; RING_SIZE] = [const { Entry::empty() }; RING_SIZE];
static mut HEAD:  usize = 0;   // oldest entry index
static mut TAIL:  usize = 0;   // next write index
static mut SEQ:   u64   = 0;
static mut COUNT: usize = 0;   // entries currently in ring (≤ RING_SIZE)

/// Write a log entry at the given level. Also writes to serial.
pub fn log(level: Level, msg: &[u8]) {
    let ticks = unsafe { SEQ }; // use sequence as monotonic timestamp
    unsafe {
        let idx = TAIL % RING_SIZE;
        let entry = &mut RING[idx];
        entry.seq     = SEQ;
        entry.ticks   = ticks;
        entry.level   = level;
        let n = msg.len().min(MSG_LEN);
        entry.msg[..n].copy_from_slice(&msg[..n]);
        entry.msg_len = n;

        SEQ  += 1;
        TAIL += 1;
        if COUNT < RING_SIZE {
            COUNT += 1;
        } else {
            HEAD += 1; // oldest entry overwritten
        }
    }

    // Mirror to serial (like printk → console)
    let pfx = match level {
        Level::Error | Level::Critical | Level::Emergency | Level::Alert
            => b"[E] ",
        Level::Warning => b"[W] ",
        Level::Debug   => b"[D] ",
        _              => b"[I] ",
    };
    crate::drivers::char::serial::write(pfx);
    crate::drivers::char::serial::write(msg);
    crate::drivers::char::serial::write(b"\n");
}

/// Convenience wrappers matching Linux severity levels.
pub fn info(msg: &[u8])    { log(Level::Info,    msg); }
pub fn warn(msg: &[u8])    { log(Level::Warning, msg); }
pub fn error(msg: &[u8])   { log(Level::Error,   msg); }
pub fn debug(msg: &[u8])   { log(Level::Debug,   msg); }
pub fn notice(msg: &[u8])  { log(Level::Notice,  msg); }

// ── Reader API ────────────────────────────────────────────────────────────────

/// Total entries ever written (monotonic).
pub fn total_seq() -> u64 { unsafe { SEQ } }

/// Number of entries currently held in the ring.
pub fn count() -> usize { unsafe { COUNT } }

/// Read entry at position `pos` (0 = oldest). Returns None if out of range.
pub fn get(pos: usize) -> Option<Entry> {
    unsafe {
        if pos >= COUNT { return None; }
        let idx = (HEAD + pos) % RING_SIZE;
        Some(RING[idx])
    }
}

/// Filter level: returns all entries with level ≤ max_level (more severe ≤ value).
pub fn get_filtered(pos: usize, max_level: Level) -> Option<Entry> {
    let e = get(pos)?;
    if e.level as u8 <= max_level as u8 { Some(e) } else { None }
}
