//! Memory system calls: mmap, munmap, mprotect, brk, arch_prctl.

use crate::arch::x86_64::cpu;
use crate::errno::{Errno, KResult};
use crate::mm::aspace::Prot;
use crate::proc;

// mmap flags.
const MAP_SHARED: u32 = 0x01;
const MAP_PRIVATE: u32 = 0x02;
const MAP_FIXED: u32 = 0x10;
const MAP_ANONYMOUS: u32 = 0x20;

const PROT_READ: u32 = 1;
const PROT_WRITE: u32 = 2;
const PROT_EXEC: u32 = 4;

fn prot_from(bits: u32) -> Prot {
    let mut p = Prot::NONE;
    if bits & PROT_READ != 0 {
        p = p | Prot::READ;
    }
    if bits & PROT_WRITE != 0 {
        p = p | Prot::WRITE;
    }
    if bits & PROT_EXEC != 0 {
        p = p | Prot::EXEC;
    }
    // A mapping with no access is still reserved; treat as read so it's backed.
    p
}

pub fn mmap(addr: u64, len: usize, prot: u32, flags: u32, fd: i32, off: u64) -> KResult<usize> {
    let space = proc::current_aspace().ok_or(Errno::ENOMEM)?;
    if len == 0 {
        return Err(Errno::EINVAL);
    }
    if flags & (MAP_SHARED | MAP_PRIVATE) == 0 {
        return Err(Errno::EINVAL);
    }
    let p = prot_from(prot);
    let p = if p == Prot::NONE { Prot::READ } else { p };
    let file = if flags & MAP_ANONYMOUS == 0 && fd >= 0 {
        // Private file mapping (what the dynamic linker uses). A shared file
        // mapping is treated as private for now (fine for read-only code).
        let f = proc::current().fds.lock().get(fd)?;
        Some((f, off))
    } else {
        None
    };
    // MAP_SHARED|MAP_ANONYMOUS is genuinely shared (across fork): a database's
    // main shared memory. A shared *file* mapping stays private for now.
    let shared = flags & MAP_SHARED != 0 && flags & MAP_ANONYMOUS != 0;
    space.mmap(addr as usize, len, p, flags & MAP_FIXED != 0, file, shared)
}

pub fn munmap(addr: usize, len: usize) -> KResult<usize> {
    let space = proc::current_aspace().ok_or(Errno::EINVAL)?;
    space.unmap(addr, len)?;
    Ok(0)
}

pub fn mprotect(addr: usize, len: usize, prot: u32) -> KResult<usize> {
    let space = proc::current_aspace().ok_or(Errno::EINVAL)?;
    space.protect(addr, len, prot_from(prot))?;
    Ok(0)
}

pub fn brk(addr: usize) -> KResult<usize> {
    let space = proc::current_aspace().ok_or(Errno::ENOMEM)?;
    Ok(space.brk(addr))
}

const ARCH_SET_FS: u32 = 0x1002;
const ARCH_SET_GS: u32 = 0x1001;
const ARCH_GET_FS: u32 = 0x1003;
const ARCH_GET_GS: u32 = 0x1004;

/// `arch_prctl`: the FS base is the thread pointer (musl/glibc TLS). Set it in
/// the MSR now; it is saved/restored across context switches per task.
pub fn arch_prctl(code: u32, addr: u64) -> KResult<usize> {
    match code {
        ARCH_SET_FS => {
            proc::set_current_fs_base(addr);
            unsafe { cpu::wrmsr(cpu::MSR_FS_BASE, addr) };
            Ok(0)
        }
        ARCH_SET_GS => {
            unsafe { cpu::wrmsr(cpu::MSR_KERNEL_GS_BASE, addr) };
            Ok(0)
        }
        ARCH_GET_FS => {
            let v = unsafe { cpu::rdmsr(cpu::MSR_FS_BASE) };
            crate::uaccess::write_obj(addr as usize, &v)?;
            Ok(0)
        }
        ARCH_GET_GS => {
            let v = unsafe { cpu::rdmsr(cpu::MSR_KERNEL_GS_BASE) };
            crate::uaccess::write_obj(addr as usize, &v)?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}
