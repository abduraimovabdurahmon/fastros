//! CPU feature detection and control (x86_64)

pub mod cpuid;
pub mod msr;
pub mod syscall;
pub mod timer;

/// Initialize CPU-level features after GDT+IDT are loaded.
pub fn init() {
    // Set up SYSCALL/SYSRET fast path
    syscall::init();
    // Configure PIT timer at 100 Hz
    timer::init(100);
}
