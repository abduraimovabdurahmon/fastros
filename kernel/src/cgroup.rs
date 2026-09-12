//! Per-container resource limits (a small cgroups-v1-style layer).
//!
//! A container may cap its number of tasks (`--pids-limit`) and its private
//! resident memory (`-m`/`--memory`). Limits are enforced where the resource is
//! acquired: task creation fails with EAGAIN over the pid cap, and a page
//! commit fails with ENOMEM over the memory cap (the faulting access then gets
//! SIGSEGV, exactly like a real OOM). Keyed by container id; the host and
//! containers with no limits are unaffected.

use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};

pub const PAGE: u64 = 4096;

pub struct Cgroup {
    /// 0 = unlimited.
    mem_limit_pages: AtomicU64,
    pids_limit: AtomicU32,
    /// Live counters.
    mem_pages: AtomicI64,
    pids: AtomicU32,
}

static CGROUPS: SpinLock<BTreeMap<String, Arc<Cgroup>>> = SpinLock::new(BTreeMap::new());

/// Register (or update) a container's limits. `mem_bytes`/`pids` of 0 = no cap.
pub fn create(cid: &str, mem_bytes: u64, pids: u32) {
    let cg = get(cid).unwrap_or_else(|| {
        let cg = Arc::new(Cgroup {
            mem_limit_pages: AtomicU64::new(0),
            pids_limit: AtomicU32::new(0),
            mem_pages: AtomicI64::new(0),
            pids: AtomicU32::new(0),
        });
        CGROUPS.lock().insert(cid.to_string(), cg.clone());
        cg
    });
    cg.mem_limit_pages.store(mem_bytes.div_ceil(PAGE), Ordering::Relaxed);
    cg.pids_limit.store(pids, Ordering::Relaxed);
}

pub fn get(cid: &str) -> Option<Arc<Cgroup>> {
    CGROUPS.lock().get(cid).cloned()
}

pub fn remove(cid: &str) {
    CGROUPS.lock().remove(cid);
}

/// Charge one task to a container. Returns false (caller fails with EAGAIN) if
/// it would exceed the pid limit.
pub fn try_add_pid(cid: &str) -> bool {
    let Some(cg) = get(cid) else { return true };
    let limit = cg.pids_limit.load(Ordering::Relaxed);
    loop {
        let cur = cg.pids.load(Ordering::Acquire);
        if limit != 0 && cur >= limit {
            return false;
        }
        if cg.pids.compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return true;
        }
    }
}

pub fn sub_pid(cid: &str, n: u32) {
    if let Some(cg) = get(cid) {
        let mut cur = cg.pids.load(Ordering::Acquire);
        loop {
            let new = cur.saturating_sub(n);
            match cg.pids.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
    }
}

/// Charge one committed page. Returns false (caller returns ENOMEM) over cap.
pub fn try_charge_page(cid: &str) -> bool {
    let Some(cg) = get(cid) else { return true };
    let limit = cg.mem_limit_pages.load(Ordering::Relaxed);
    if limit == 0 {
        return true;
    }
    if cg.mem_pages.fetch_add(1, Ordering::AcqRel) as u64 >= limit {
        cg.mem_pages.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    true
}

pub fn uncharge_pages(cid: &str, n: u64) {
    if n == 0 {
        return;
    }
    if let Some(cg) = get(cid) {
        cg.mem_pages.fetch_sub(n as i64, Ordering::AcqRel);
    }
}

/// (used, limit) memory in bytes and (pids, limit) — for `stats`/observability.
pub fn usage(cid: &str) -> Option<(u64, u64, u32, u32)> {
    let cg = get(cid)?;
    Some((
        cg.mem_pages.load(Ordering::Relaxed).max(0) as u64 * PAGE,
        cg.mem_limit_pages.load(Ordering::Relaxed) * PAGE,
        cg.pids.load(Ordering::Relaxed),
        cg.pids_limit.load(Ordering::Relaxed),
    ))
}
