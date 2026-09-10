//! Command history — stores the last N commands entered in the shell.
//!
//! Design:
//!   - Fixed-size ring of up to HISTORY_MAX entries, each up to LINE_MAX bytes.
//!   - Newest entry is always at index `(head - 1 + HISTORY_MAX) % HISTORY_MAX`.
//!   - `get(0)` = newest, `get(1)` = one before, etc. (like bash $HISTCMD).
//!   - Thread-safe: wrapped in a SpinLock.
//!
//! Used by:
//!   - `readline::LineEditor` — Up/Down arrows recall/navigate history.
//!   - `command::history::HistoryCommand` — prints the history list.

use crate::kernel::sync::spinlock::SpinLock;

pub const HISTORY_MAX: usize = 100;
pub const LINE_MAX:    usize = 256;

pub struct History {
    entries: [[u8; LINE_MAX]; HISTORY_MAX],
    lens:    [usize; HISTORY_MAX],
    count:   usize,   // total entries ever added (capped at HISTORY_MAX)
    head:    usize,   // index where the NEXT entry will be written
}

impl History {
    pub const fn new() -> Self {
        Self {
            entries: [[0u8; LINE_MAX]; HISTORY_MAX],
            lens:    [0usize; HISTORY_MAX],
            count:   0,
            head:    0,
        }
    }

    /// Add a command line.  Ignores empty lines or duplicates of the last entry.
    pub fn push(&mut self, line: &[u8]) {
        if line.is_empty() { return; }
        // Avoid duplicating the most recent entry
        if self.count > 0 {
            let last = (self.head + HISTORY_MAX - 1) % HISTORY_MAX;
            if &self.entries[last][..self.lens[last]] == line { return; }
        }
        let len = line.len().min(LINE_MAX);
        self.entries[self.head][..len].copy_from_slice(&line[..len]);
        self.lens[self.head] = len;
        self.head = (self.head + 1) % HISTORY_MAX;
        if self.count < HISTORY_MAX { self.count += 1; }
    }

    /// Get entry by age: 0 = most recent, 1 = one before, etc.
    /// Returns `None` if `age >= count`.
    pub fn get(&self, age: usize) -> Option<&[u8]> {
        if age >= self.count { return None; }
        let idx = (self.head + HISTORY_MAX - 1 - age) % HISTORY_MAX;
        Some(&self.entries[idx][..self.lens[idx]])
    }

    /// Total number of stored entries (≤ HISTORY_MAX).
    pub fn len(&self) -> usize { self.count }

    /// Iterate from oldest to newest.
    pub fn iter_oldest_first(&self) -> HistoryIter<'_> {
        HistoryIter { hist: self, idx: 0 }
    }
}

pub struct HistoryIter<'a> {
    hist: &'a History,
    idx:  usize,
}
impl<'a> Iterator for HistoryIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.hist.count { return None; }
        // oldest = (head - count + idx) % HISTORY_MAX
        let age = self.hist.count - 1 - self.idx;
        self.idx += 1;
        self.hist.get(age)
    }
}

// ── Global singleton ──────────────────────────────────────────────────────────

static HISTORY_LOCK: SpinLock  = SpinLock::new();
static mut HISTORY:  History   = History::new();

/// Push a line into the global history (called by the shell REPL).
pub fn push(line: &[u8]) {
    HISTORY_LOCK.lock();
    unsafe { HISTORY.push(line); }
    HISTORY_LOCK.unlock();
}

/// Get entry by age from the global history.
/// Caller must call `unlock()` after using the returned slice.
/// For simplicity: copies into a fixed buffer.
pub fn get(age: usize, out: &mut [u8; LINE_MAX]) -> Option<usize> {
    HISTORY_LOCK.lock();
    let result = unsafe {
        HISTORY.get(age).map(|s| {
            let len = s.len().min(LINE_MAX);
            out[..len].copy_from_slice(&s[..len]);
            len
        })
    };
    HISTORY_LOCK.unlock();
    result
}

/// Number of stored entries.
pub fn count() -> usize {
    HISTORY_LOCK.lock();
    let c = unsafe { HISTORY.len() };
    HISTORY_LOCK.unlock();
    c
}

/// Call `f` with a reference to the global history (locked).
pub fn with<F: FnOnce(&History)>(f: F) {
    HISTORY_LOCK.lock();
    unsafe { f(&HISTORY); }
    HISTORY_LOCK.unlock();
}
