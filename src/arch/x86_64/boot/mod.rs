//! Early boot: GDT setup
//!
//! The assembly entry (arch/x86_64/boot.s) sets up a minimal GDT.
//! This module installs the final, permanent GDT used at runtime.

pub mod gdt;

pub fn init_gdt() {
    gdt::load();
}
