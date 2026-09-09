//! PS/2 Keyboard Driver
//!
//! Receives scancodes on IRQ 1 (mapped to vector 0x21).
//! Converts PS/2 Set 1 scancodes to ASCII / key events.
//!
//! Data port:    0x60
//! Status port:  0x64

// TODO: Register IRQ 1 handler via hal::InterruptController.
// TODO: Read scancode from port 0x60 in handler.
// TODO: Implement scancode → key event translation table.
// TODO: Feed key events into a ring buffer for userspace reads.
