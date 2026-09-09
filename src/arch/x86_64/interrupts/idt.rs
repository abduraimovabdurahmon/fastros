//! Interrupt Descriptor Table (IDT)
//!
//! Maps interrupt vectors (0–255) to handler functions.
//!
//! Vectors 0–31:  CPU exceptions (divide by zero, page fault, etc.)
//! Vectors 32–47: Hardware IRQs (remapped from PIC)
//! Vectors 48+:   Software interrupts / syscalls

// TODO: Define IDT entry structure (128-bit gate descriptor).
// TODO: Install exception handlers (0=divide error, 14=page fault, etc.).
// TODO: Load IDT via `lidt` instruction.

pub fn load() {
    // TODO: load IDT
}
