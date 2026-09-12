//! System V shared memory (`shmget`/`shmat`/`shmdt`/`shmctl`).
//!
//! Enough of the API for a database: postgres always creates a small System V
//! segment as a cross-postmaster interlock (it reads `shm_nattch` to detect a
//! second postmaster on the same data directory) alongside its main mmap-based
//! shared memory. Segments are backed by a shared-anonymous object
//! ([`crate::mm::aspace::SharedAnon`]), so attaching the same id in different
//! processes shares the pages; a futex on that memory then works cross-process.

use crate::errno::{Errno, KResult};
use crate::mm::aspace::SharedAnon;
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_EXCL: i32 = 0o2000;

const IPC_RMID: i32 = 0;
const IPC_STAT: i32 = 2;
const SHM_RDONLY: i32 = 0o10000;

struct ShmSeg {
    id: i32,
    key: i32,
    size: usize,
    mode: u16,
    cpid: u32,
    obj: Arc<SharedAnon>,
    nattch: AtomicUsize,
    removed: core::sync::atomic::AtomicBool,
}

/// id → segment.
static SEGS: SpinLock<BTreeMap<i32, Arc<ShmSeg>>> = SpinLock::new(BTreeMap::new());

/// One live attachment.
struct Attach {
    pid: u32,
    addr: usize,
    shmid: i32,
    size: usize,
}
/// Live attachments, so a segment's `nattch` can be decremented when a process
/// detaches — or exits without detaching (the common case for a crash/kill).
static ATTACH: SpinLock<Vec<Attach>> = SpinLock::new(Vec::new());
static NEXT_ID: AtomicI32 = AtomicI32::new(1);

fn current_space() -> KResult<Arc<crate::mm::aspace::AddressSpace>> {
    crate::proc::current_aspace().ok_or(Errno::EACCES)
}

/// Drop `nattch` for one shmid; delete the segment if it hit zero and was
/// already marked removed (IPC_RMID).
fn detach_seg(shmid: i32) {
    // Bind the lookup out of the lock first: an `if let SEGS.lock()...` would
    // hold the guard across the whole block, and the inner remove would deadlock.
    let seg = SEGS.lock().get(&shmid).cloned();
    if let Some(seg) = seg {
        if seg.nattch.fetch_sub(1, Ordering::AcqRel) == 1 && seg.removed.load(Ordering::Relaxed) {
            SEGS.lock().remove(&shmid);
        }
    }
}

/// Release every System V shm attachment held by a process that is exiting.
/// Without this a killed process (a postgres backend, or initdb's `--single`
/// phases) would leave `nattch > 0` forever, and the next postmaster would
/// refuse to start ("pre-existing shared memory block ... still in use").
pub fn exit_process(pid: u32) {
    let mut mine = Vec::new();
    {
        let mut att = ATTACH.lock();
        let mut i = 0;
        while i < att.len() {
            if att[i].pid == pid {
                let a = att.remove(i);
                mine.push(a.shmid);
            } else {
                i += 1;
            }
        }
    }
    for shmid in mine {
        detach_seg(shmid);
    }
}

pub fn shmget(key: i32, size: usize, shmflg: i32) -> KResult<usize> {
    let mut segs = SEGS.lock();
    if key != IPC_PRIVATE {
        if let Some(seg) = segs.values().find(|s| s.key == key && !s.removed.load(Ordering::Relaxed)) {
            if shmflg & IPC_CREAT != 0 && shmflg & IPC_EXCL != 0 {
                return Err(Errno::EEXIST);
            }
            if size != 0 && seg.size < size {
                return Err(Errno::EINVAL);
            }
            return Ok(seg.id as usize);
        }
        if shmflg & IPC_CREAT == 0 {
            return Err(Errno::ENOENT);
        }
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let seg = Arc::new(ShmSeg {
        id,
        key,
        size: crate::mm::align_up(size.max(1), crate::mm::PAGE_SIZE),
        mode: (shmflg & 0o777) as u16,
        cpid: crate::proc::current().pid,
        obj: SharedAnon::new(),
        nattch: AtomicUsize::new(0),
        removed: core::sync::atomic::AtomicBool::new(false),
    });
    segs.insert(id, seg);
    Ok(id as usize)
}

pub fn shmat(shmid: i32, addr: usize, shmflg: i32) -> KResult<usize> {
    let seg = SEGS.lock().get(&shmid).cloned().ok_or(Errno::EINVAL)?;
    let sp = current_space()?;
    let pid = crate::proc::current().pid;
    let prot = if shmflg & SHM_RDONLY != 0 {
        crate::mm::aspace::Prot::READ
    } else {
        crate::mm::aspace::Prot::READ | crate::mm::aspace::Prot::WRITE
    };
    let va = sp.attach_shared(addr, seg.size, prot, seg.obj.clone())?;
    seg.nattch.fetch_add(1, Ordering::AcqRel);
    ATTACH.lock().push(Attach { pid, addr: va, shmid, size: seg.size });
    Ok(va)
}

pub fn shmdt(addr: usize) -> KResult<usize> {
    let sp = current_space()?;
    let pid = crate::proc::current().pid;
    let (shmid, size) = {
        let mut att = ATTACH.lock();
        let idx = att.iter().position(|a| a.pid == pid && a.addr == addr).ok_or(Errno::EINVAL)?;
        let a = att.remove(idx);
        (a.shmid, a.size)
    };
    let _ = sp.unmap(addr, size);
    detach_seg(shmid);
    Ok(0)
}

/// Linux x86_64 `struct shmid_ds` (112 bytes): shm_segsz@48, shm_nattch@88.
pub fn shmctl(shmid: i32, cmd: i32, buf: usize) -> KResult<usize> {
    let seg = SEGS.lock().get(&shmid).cloned().ok_or(Errno::EINVAL)?;
    match cmd {
        IPC_STAT => {
            let mut b = [0u8; 112];
            b[0..4].copy_from_slice(&seg.key.to_le_bytes()); // ipc_perm.__key
            b[20..22].copy_from_slice(&seg.mode.to_le_bytes()); // ipc_perm.mode
            b[48..56].copy_from_slice(&(seg.size as u64).to_le_bytes()); // shm_segsz
            b[80..84].copy_from_slice(&seg.cpid.to_le_bytes()); // shm_cpid
            b[88..96].copy_from_slice(&(seg.nattch.load(Ordering::Relaxed) as u64).to_le_bytes()); // shm_nattch
            crate::uaccess::copy_to(buf, &b)?;
            Ok(0)
        }
        IPC_RMID => {
            seg.removed.store(true, Ordering::Relaxed);
            if seg.nattch.load(Ordering::Relaxed) == 0 {
                SEGS.lock().remove(&shmid);
            }
            Ok(0)
        }
        _ => Ok(0),
    }
}
