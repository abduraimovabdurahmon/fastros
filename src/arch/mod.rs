//! LAYER 0 — Architecture-specific code
//!
//! Each subdirectory corresponds to one CPU architecture.
//! Only ONE is compiled at a time based on the build target.
//!
//! CAN IMPORT:   nothing (this is the bottom layer)
//! CANNOT IMPORT: hal/, kernel/, drivers/, fs/, libs/

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

/// Called from kernel_main() to perform early CPU initialization.
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    x86_64::init();
}

/// Set the function called on every timer tick (100 Hz).
pub fn set_timer_hook(f: fn()) {
    #[cfg(target_arch = "x86_64")]
    x86_64::set_timer_hook(f);
}

/// Set the page-fault handler.
pub fn set_page_fault_hook(f: fn(u64, bool, bool, bool, u64) -> bool) {
    #[cfg(target_arch = "x86_64")]
    x86_64::set_page_fault_hook(f);
}
