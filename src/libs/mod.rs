//! Internal no_std utility libraries
//!
//! Pure data structures and algorithms with NO OS dependencies.
//! Can be used by ANY layer (arch → userspace).
//!
//! CAN IMPORT:   nothing (only core::)
//! CANNOT IMPORT: arch/, hal/, kernel/, drivers/, fs/

pub mod collections;
pub mod fmt;
