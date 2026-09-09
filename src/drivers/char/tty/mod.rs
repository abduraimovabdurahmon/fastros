//! TTY (Teletypewriter) Abstraction
//!
//! Sits between the keyboard driver (input) and the VGA/framebuffer (output).
//! Provides:
//!   - Line discipline (echo, backspace, Ctrl+C → SIGINT, etc.)
//!   - Read/write file descriptor interface to userspace
//!   - ANSI escape code processing (cursor movement, colors)

// TODO: Implement TtyDevice { input_buf: RingBuffer, output_buf: RingBuffer }
// TODO: Implement line discipline (canonical mode: buffer until Enter)
// TODO: Connect keyboard driver → TTY input, TTY output → VGA driver
