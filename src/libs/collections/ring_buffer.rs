//! Fixed-capacity ring buffer (FIFO queue)
//!
//! Lock-free single-producer single-consumer (SPSC) implementation.
//! Used by: serial driver output, keyboard scancode buffer, pipe buffers, TTY.

pub struct RingBuffer<const N: usize> {
    buf:  [u8; N],
    head: usize, // next read position
    tail: usize, // next write position
    len:  usize,
}

impl<const N: usize> RingBuffer<N> {
    pub const fn new() -> Self {
        Self { buf: [0; N], head: 0, tail: 0, len: 0 }
    }

    pub fn is_empty(&self) -> bool { self.len == 0 }
    pub fn is_full(&self)  -> bool { self.len == N }
    pub fn len(&self)      -> usize { self.len }
    pub fn capacity(&self) -> usize { N }

    /// Push one byte. Returns false if buffer is full.
    pub fn push(&mut self, byte: u8) -> bool {
        if self.is_full() { return false; }
        self.buf[self.tail] = byte;
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        true
    }

    /// Pop one byte. Returns None if buffer is empty.
    pub fn pop(&mut self) -> Option<u8> {
        if self.is_empty() { return None; }
        let byte = self.buf[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(byte)
    }

    /// Peek at the next byte without removing it.
    pub fn peek(&self) -> Option<u8> {
        if self.is_empty() { None } else { Some(self.buf[self.head]) }
    }
}
