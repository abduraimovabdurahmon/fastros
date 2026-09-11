//! Page-fault handling.

use crate::arch::trap::TrapFrame;

/// Try to resolve a page fault. Returns true if execution can continue.
pub fn handle(tf: &mut TrapFrame, addr: usize) -> bool {
    if tf.from_user() {
        // User address spaces arrive with the process layer.
        return false;
    }
    if let Some(owner) = super::vmalloc::guard_owner(addr) {
        let (lo, hi) = crate::sched::with_current(|t| t.stack_bounds());
        if (lo..hi).contains(&owner) || owner == lo {
            crate::panic::stack_overflow(tf, addr);
        }
        crate::panic::guard_hit(tf, addr, owner);
    }
    false
}
