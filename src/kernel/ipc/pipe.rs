//! Anonymous Pipes
//!
//! Unidirectional byte stream between two processes (or threads).
//! Classic Unix: write-end → [ring buffer] → read-end
//!
//! Backed by a fixed-size kernel ring buffer (libs::collections::ring_buffer).

// TODO: Implement Pipe { read_end: Fd, write_end: Fd, buffer: RingBuffer }
// TODO: pipe() syscall creates a pair of file descriptors.
