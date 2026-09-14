//! Linux asynchronous I/O (`libaio`): io_setup / io_submit / io_getevents /
//! io_destroy / io_cancel.
//!
//! Backed synchronously: each submitted `iocb` is performed at io_submit time
//! and its result queued for io_getevents. That is a valid AIO implementation
//! (completions simply happen eagerly) and lets libaio consumers — nginx,
//! postgres — run instead of failing io_setup with ENOSYS.

use crate::errno::{Errno, KResult};
use crate::proc;
use crate::sync::SpinLock;
use crate::uaccess;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use core::sync::atomic::{AtomicU64, Ordering};

const IOCB_CMD_PREAD: u16 = 0;
const IOCB_CMD_PWRITE: u16 = 1;
const IOCB_CMD_FSYNC: u16 = 2;
const IOCB_CMD_FDSYNC: u16 = 3;
const IOCB_CMD_NOOP: u16 = 6;
const IOCB_FLAG_RESFD: u32 = 1;

/// One AIO context: a completion queue owned by a process.
struct Ctx {
    owner: u32,
    done: VecDeque<[u8; 32]>, // io_event structs
}

static CTXS: SpinLock<BTreeMap<u64, Ctx>> = SpinLock::new(BTreeMap::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

/// `io_setup(nr_events, ctxp)` — allocate a context; write its id to `*ctxp`.
pub fn io_setup(nr_events: u32, ctxp: usize) -> KResult<usize> {
    if nr_events == 0 || ctxp == 0 {
        return Err(Errno::EINVAL);
    }
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    uaccess::write_obj(ctxp, &id)?;
    CTXS.lock().insert(id, Ctx { owner: proc::current().pid, done: VecDeque::new() });
    Ok(0)
}

/// `io_destroy(ctx)`.
pub fn io_destroy(id: usize) -> KResult<usize> {
    let id = id as u64;
    let mut m = CTXS.lock();
    match m.get(&id) {
        Some(c) if c.owner == proc::current().pid => {
            m.remove(&id);
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

fn owns(id: u64) -> bool {
    CTXS.lock().get(&id).map(|c| c.owner == proc::current().pid).unwrap_or(false)
}

/// `io_submit(ctx, nr, iocbpp)` — run each iocb now, queue its completion.
pub fn io_submit(id: usize, nr: i64, iocbpp: usize) -> KResult<usize> {
    let id = id as u64;
    if !owns(id) {
        return Err(Errno::EINVAL);
    }
    if nr < 0 {
        return Err(Errno::EINVAL);
    }
    let mut submitted = 0usize;
    for i in 0..nr as usize {
        let iocb_ptr: u64 = uaccess::read_obj(iocbpp + i * 8)?;
        if iocb_ptr == 0 {
            break;
        }
        let mut raw = [0u8; 64];
        uaccess::copy_from(iocb_ptr as usize, &mut raw)?;
        let (event, resfd) = execute(&raw, iocb_ptr);
        {
            let mut m = CTXS.lock();
            match m.get_mut(&id) {
                Some(c) => c.done.push_back(event),
                None => return Err(Errno::EINVAL),
            }
        }
        if let Some(fd) = resfd {
            notify_eventfd(fd);
        }
        submitted += 1;
    }
    if submitted == 0 && nr > 0 {
        // Linux returns EINVAL if it couldn't submit even the first iocb.
        return Err(Errno::EINVAL);
    }
    Ok(submitted)
}

/// `io_getevents(ctx, min_nr, nr, events, timeout)` — copy ready completions.
/// Completions are eager, so this returns immediately with whatever is queued
/// (never blocks forever, even if `min_nr` exceeds what is available).
pub fn io_getevents(id: usize, _min_nr: i64, nr: i64, events: usize, _timeout: usize) -> KResult<usize> {
    let id = id as u64;
    if nr < 0 || events == 0 {
        return Err(Errno::EINVAL);
    }
    // Drain up to `nr` events under the lock, then copy out without holding it
    // (uaccess may fault/sleep).
    let batch: alloc::vec::Vec<[u8; 32]> = {
        let mut m = CTXS.lock();
        let Some(c) = m.get_mut(&id) else { return Err(Errno::EINVAL) };
        if c.owner != proc::current().pid {
            return Err(Errno::EINVAL);
        }
        let take = (nr as usize).min(c.done.len());
        c.done.drain(..take).collect()
    };
    for (i, ev) in batch.iter().enumerate() {
        uaccess::copy_to(events + i * 32, ev)?;
    }
    Ok(batch.len())
}

/// `io_cancel` — everything completes synchronously, so there is nothing to
/// cancel.
pub fn io_cancel(_id: usize, _iocb: usize, _result: usize) -> KResult<usize> {
    Err(Errno::EINVAL)
}

/// Perform one iocb and build its 32-byte `io_event` (data, obj, res, res2).
fn execute(raw: &[u8; 64], iocb_ptr: u64) -> ([u8; 32], Option<i32>) {
    let data = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let opcode = u16::from_le_bytes(raw[16..18].try_into().unwrap());
    let fd = u32::from_le_bytes(raw[20..24].try_into().unwrap()) as i32;
    let buf = u64::from_le_bytes(raw[24..32].try_into().unwrap()) as usize;
    let nbytes = u64::from_le_bytes(raw[32..40].try_into().unwrap()) as usize;
    let offset = i64::from_le_bytes(raw[40..48].try_into().unwrap());
    let flags = u32::from_le_bytes(raw[56..60].try_into().unwrap());
    let resfd = if flags & IOCB_FLAG_RESFD != 0 { Some(u32::from_le_bytes(raw[60..64].try_into().unwrap()) as i32) } else { None };

    let res: i64 = match perform(opcode, fd, buf, nbytes, offset) {
        Ok(n) => n as i64,
        Err(e) => -(e as i32 as i64),
    };

    let mut ev = [0u8; 32];
    ev[0..8].copy_from_slice(&data.to_le_bytes()); // data
    ev[8..16].copy_from_slice(&iocb_ptr.to_le_bytes()); // obj (the iocb)
    ev[16..24].copy_from_slice(&res.to_le_bytes()); // res
    // ev[24..32] = res2 = 0
    (ev, resfd)
}

fn perform(opcode: u16, fd: i32, buf: usize, nbytes: usize, offset: i64) -> KResult<usize> {
    let f = proc::current().fds.lock().get(fd)?;
    match opcode {
        IOCB_CMD_PREAD => {
            let mut kbuf = vec![0u8; nbytes.min(64 << 20)];
            let n = f.pread(offset as u64, &mut kbuf)?;
            uaccess::copy_to(buf, &kbuf[..n])?;
            Ok(n)
        }
        IOCB_CMD_PWRITE => {
            let mut kbuf = vec![0u8; nbytes.min(64 << 20)];
            uaccess::copy_from(buf, &mut kbuf)?;
            f.pwrite(offset as u64, &kbuf)
        }
        IOCB_CMD_FSYNC | IOCB_CMD_FDSYNC => {
            f.sync()?;
            Ok(0)
        }
        IOCB_CMD_NOOP => Ok(0),
        _ => Err(Errno::EINVAL),
    }
}

/// Signal an `eventfd` (as libaio does via `aio_resfd`) so an epoll waiter wakes.
fn notify_eventfd(fd: i32) {
    if let Ok(f) = proc::current().fds.lock().get(fd) {
        let one: u64 = 1;
        let _ = f.write(&one.to_le_bytes());
    }
}
