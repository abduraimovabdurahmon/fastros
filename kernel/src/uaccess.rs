//! Copying data across the kernel/user boundary.
//!
//! Native kernel commands pass kernel pointers to file operations (e.g. a
//! `TIOCGWINSZ` buffer on their stack); Linux-ABI programs pass user
//! pointers. A user pointer is validated page by page against the current
//! address space (present, user-accessible, writable when writing) before the
//! copy runs inside an SMAP window, so a bad pointer yields EFAULT instead of
//! a kernel fault — and a user program can never smuggle in a kernel address.

use crate::errno::{Errno, KResult};
use crate::mm::{PHYS_OFFSET, USER_END, USER_START};

fn is_kernel(addr: usize) -> bool {
    addr >= PHYS_OFFSET
}

/// Validate `[addr, addr+len)` for the current context.
fn check(addr: usize, len: usize, write: bool) -> KResult<()> {
    if len == 0 {
        return Ok(());
    }
    let end = addr.checked_add(len).ok_or(Errno::EFAULT)?;
    if is_kernel(addr) {
        // Only kernel-mode (native) callers may hand in kernel pointers.
        return if crate::usermode::current_is_user() { Err(Errno::EFAULT) } else { Ok(()) };
    }
    if addr < USER_START || end > USER_END {
        return Err(Errno::EFAULT);
    }
    crate::usermode::check_user_range(addr, len, write)
}

pub fn copy_to(addr: usize, src: &[u8]) -> KResult<()> {
    check(addr, src.len(), true)?;
    if is_kernel(addr) {
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), addr as *mut u8, src.len()) };
        return Ok(());
    }
    // A user pointer is copied page-by-page through the physical direct map,
    // never by dereferencing the user virtual address in the kernel: each page
    // is faulted in (allocated, or swapped back from disk) immediately before it
    // is written, so the kernel can never take an unresolvable fault on a
    // demand-zero or swapped-out user page (which has no fault fixup).
    crate::proc::current_aspace().ok_or(Errno::EFAULT)?.write(addr, src)
}

pub fn copy_from(addr: usize, dst: &mut [u8]) -> KResult<()> {
    check(addr, dst.len(), false)?;
    if is_kernel(addr) {
        unsafe { core::ptr::copy_nonoverlapping(addr as *const u8, dst.as_mut_ptr(), dst.len()) };
        return Ok(());
    }
    crate::proc::current_aspace().ok_or(Errno::EFAULT)?.read(addr, dst)
}

pub fn write_obj<T: Copy>(addr: usize, v: &T) -> KResult<()> {
    let bytes = unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) };
    copy_to(addr, bytes)
}

pub fn read_obj<T: Copy>(addr: usize) -> KResult<T> {
    let mut v = core::mem::MaybeUninit::<T>::uninit();
    let bytes = unsafe { core::slice::from_raw_parts_mut(v.as_mut_ptr() as *mut u8, core::mem::size_of::<T>()) };
    copy_from(addr, bytes)?;
    Ok(unsafe { v.assume_init() })
}
