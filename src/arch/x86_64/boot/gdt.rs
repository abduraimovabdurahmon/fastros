//! Global Descriptor Table (GDT)
//!
//! x86_64 still requires a GDT for:
//!   - Privilege level separation (ring 0 kernel vs ring 3 user)
//!   - TSS (Task State Segment) for stack switching on interrupts
//!   - SYSCALL/SYSRET instruction support

// TODO: Implement GDT with kernel code, kernel data, user code, user data, TSS segments.

pub fn load() {
    // TODO: build and load GDT via lgdt instruction
}
