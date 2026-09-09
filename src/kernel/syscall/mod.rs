//! System Call interface
//!
//! Entry via SYSCALL instruction (MSR_LSTAR points to syscall_entry in arch/).
//! Dispatch table maps syscall numbers to handler functions.
//!
//! Calling convention (Linux-compatible):
//!   rax = syscall number
//!   rdi, rsi, rdx, r10, r8, r9 = arguments
//!   rax = return value

pub mod handler;
pub mod numbers;
