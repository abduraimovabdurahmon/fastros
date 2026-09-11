//! The user-mode boundary: whether the current task runs a user program and
//! whether a user pointer is valid in its address space.

use crate::errno::{Errno, KResult};

/// Is the current task executing (or in a syscall from) a user program?
pub fn current_is_user() -> bool {
    crate::proc::current_aspace().is_some()
}

/// Validate a user buffer against the current address space. The copy itself
/// (in `uaccess`) faults missing pages in; this rejects addresses that are
/// not backed by a mapping with the right permission, so a bad pointer is
/// EFAULT rather than a kernel fault.
pub fn check_user_range(addr: usize, len: usize, write: bool) -> KResult<()> {
    if len == 0 {
        return Ok(());
    }
    let space = crate::proc::current_aspace().ok_or(Errno::EFAULT)?;
    if space.verify(addr, len, write) {
        Ok(())
    } else {
        Err(Errno::EFAULT)
    }
}
