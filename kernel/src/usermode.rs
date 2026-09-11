//! User-mode (Linux ABI) execution context.
//!
//! Placeholder boundary for the user-space layer: until a task runs user
//! code there is no user address space, so every user pointer is invalid.

use crate::errno::{Errno, KResult};

/// Is the current task executing a user-mode program?
pub fn current_is_user() -> bool {
    false
}

/// Validate a user buffer against the current address space.
pub fn check_user_range(_addr: usize, _len: usize, _write: bool) -> KResult<()> {
    Err(Errno::EFAULT)
}
