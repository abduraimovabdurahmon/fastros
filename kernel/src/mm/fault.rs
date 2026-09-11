//! Page-fault handling.

use crate::arch::trap::TrapFrame;

/// Try to resolve a page fault. Returns true if execution can continue.
pub fn handle(tf: &mut TrapFrame, addr: usize) -> bool {
    if tf.from_user() {
        return super::aspace::handle_user_fault(tf, addr);
    }
    // A kernel access to a user address (uaccess copy): resolve it too.
    if addr < super::USER_END && super::aspace::handle_user_fault(tf, addr) {
        return true;
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
