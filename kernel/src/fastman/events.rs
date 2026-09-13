//! A small in-memory event log for `fastman events` (Docker's daemon events).
//!
//! Lifecycle points in the runtime record an event here; `fastman events`
//! streams them. The log is a bounded ring — recent history plus live events —
//! so it never grows without bound and needs no on-disk state.

use crate::sync::SpinLock;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// One recorded event.
#[derive(Clone)]
pub struct Event {
    pub seq: u64,
    pub time: u64,
    /// Docker action: create, start, die, kill, stop, destroy, health_status, …
    pub action: String,
    /// The subject — a container name, or an image reference.
    pub actor: String,
}

const CAP: usize = 256;
static LOG: SpinLock<VecDeque<Event>> = SpinLock::new(VecDeque::new());
static SEQ: AtomicU64 = AtomicU64::new(0);

/// Record an event. Cheap and lock-brief so it is safe on hot lifecycle paths.
pub fn record(action: &str, actor: &str) {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    let ev = Event { seq, time: crate::time::unix_now(), action: action.to_string(), actor: actor.to_string() };
    let mut log = LOG.lock();
    if log.len() >= CAP {
        log.pop_front();
    }
    log.push_back(ev);
    // Wake any `fastman events` reader blocked in poll.
    crate::net::wake_pollers();
}

/// Every buffered event with `seq` greater than `after`.
pub fn since(after: u64) -> Vec<Event> {
    LOG.lock().iter().filter(|e| e.seq > after).cloned().collect()
}
