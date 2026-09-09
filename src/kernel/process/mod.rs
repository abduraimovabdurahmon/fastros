//! Process & thread management
//!
//! Lifecycle: Created → Ready → Running → Blocked → Zombie → Dead

pub mod process;
pub mod scheduler;
pub mod thread;

pub fn init() {
    scheduler::init();
}
