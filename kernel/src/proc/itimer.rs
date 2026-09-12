//! `ITIMER_REAL` interval timers (`setitimer`/`getitimer`/`alarm`).
//!
//! Real-time timers fire SIGALRM on wall-clock elapsed time, regardless of
//! whether the process was scheduled. postgres arms one for statement timeouts,
//! deadlock detection and the authentication timeout, so a database is unusable
//! without it. Timers are checked once per scheduler tick from
//! [`crate::sched::timer_tick`]; the resolution is therefore one tick, which is
//! finer than any timeout postgres sets.
//!
//! `ITIMER_VIRTUAL`/`ITIMER_PROF` (which count CPU time, not wall time) are
//! accepted but never fire — nothing that runs here relies on them.

use crate::proc::Pid;
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[derive(Clone, Copy)]
struct RealTimer {
    /// Absolute monotonic deadline (ns). 0 is never stored (that means disarmed).
    deadline_ns: u64,
    /// Auto-reload period (ns); 0 = one-shot.
    interval_ns: u64,
}

static REAL: SpinLock<BTreeMap<Pid, RealTimer>> = SpinLock::new(BTreeMap::new());

/// Arm (or, with `value_ns == 0`, disarm) the process's `ITIMER_REAL`.
/// Returns the previous `(remaining_ns, interval_ns)` for `setitimer`'s old-value.
pub fn set_real(pid: Pid, value_ns: u64, interval_ns: u64) -> (u64, u64) {
    let now = crate::time::now_ns();
    let mut map = REAL.lock();
    let old = map.get(&pid).map(|t| (t.deadline_ns.saturating_sub(now), t.interval_ns)).unwrap_or((0, 0));
    if value_ns == 0 {
        map.remove(&pid);
    } else {
        map.insert(pid, RealTimer { deadline_ns: now + value_ns, interval_ns });
    }
    old
}

/// Current `(remaining_ns, interval_ns)` of the process's `ITIMER_REAL`.
pub fn get_real(pid: Pid) -> (u64, u64) {
    let now = crate::time::now_ns();
    REAL.lock().get(&pid).map(|t| (t.deadline_ns.saturating_sub(now), t.interval_ns)).unwrap_or((0, 0))
}

/// Drop a process's timer when it exits, so a reused pid never inherits it.
pub fn clear(pid: Pid) {
    REAL.lock().remove(&pid);
}

/// Fire every real timer whose deadline has passed. Called from the timer IRQ
/// (interrupts already off, so locking here cannot deadlock against a holder).
/// Expired one-shots are removed; periodic ones re-arm to the next multiple of
/// their interval that is still in the future, so a burst of missed ticks
/// collapses into a single SIGALRM rather than a storm.
pub fn tick(now: u64) {
    let mut fired: Vec<Pid> = Vec::new();
    {
        let mut map = REAL.lock();
        map.retain(|&pid, t| {
            if now < t.deadline_ns {
                return true;
            }
            fired.push(pid);
            if t.interval_ns == 0 {
                return false; // one-shot: drop it
            }
            let missed = (now - t.deadline_ns) / t.interval_ns + 1;
            t.deadline_ns += missed * t.interval_ns;
            true
        });
    }
    for pid in fired {
        if let Some(p) = crate::proc::find(pid) {
            p.signal(crate::proc::signal::SIGALRM);
        }
    }
}
