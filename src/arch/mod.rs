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
