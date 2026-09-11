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
    crate::arch::cpu::stac();
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), addr as *mut u8, src.len()) };
    crate::arch::cpu::clac();
    Ok(())
}

pub fn copy_from(addr: usize, dst: &mut [u8]) -> KResult<()> {
    check(addr, dst.len(), false)?;
    crate::arch::cpu::stac();
    unsafe { core::ptr::copy_nonoverlapping(addr as *const u8, dst.as_mut_ptr(), dst.len()) };
    crate::arch::cpu::clac();
    Ok(())
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
