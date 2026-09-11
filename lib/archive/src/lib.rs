//! Archive and compression formats: gzip (RFC 1952) over raw deflate
//! (RFC 1951), tar (ustar, GNU long names, pax) and zip (stored/deflate,
//! zip64 read path).
//!
//! Everything streams through the small [`Read`]/[`Write`]/[`ReadAt`] traits
//! below, so the same code serves kernel files, network streams (container
//! image layers) and in-memory buffers. Decoders never panic on malformed
//! input and never produce more data than the archive declares; extraction
//! paths are checked with [`path::sanitize`] before anything touches a
//! filesystem.
//!
//! No allocation happens on the stack beyond a few hundred bytes: the kernel
//! runs every command on a 64 KiB stack, so all windows and tables live on
//! the heap.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod crc32;
pub mod deflate;
pub mod gzip;
pub mod inflate;
pub mod path;
pub mod tar;
pub mod time;
pub mod zip;

use alloc::vec::Vec;
use core::fmt;

/// Why an archive operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The underlying source or sink failed (`strerror` text).
    Io(&'static str),
    /// The input ended in the middle of a structure.
    UnexpectedEof,
    /// Not this format at all (bad magic).
    BadMagic,
    /// The data violates the format.
    Corrupt(&'static str),
    /// A checksum did not match.
    Checksum { expected: u32, actual: u32 },
    /// Decoded length disagrees with the declared length.
    Length,
    /// A valid feature this implementation does not handle.
    Unsupported(&'static str),
    /// A value does not fit the format (e.g. > 4 GiB in plain zip).
    TooLarge(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(s) => f.write_str(s),
            Error::UnexpectedEof => f.write_str("unexpected end of file"),
            Error::BadMagic => f.write_str("not in the expected format"),
            Error::Corrupt(s) => write!(f, "invalid data: {s}"),
            Error::Checksum { expected, actual } => write!(f, "checksum error (stored {expected:08x}, computed {actual:08x})"),
            Error::Length => f.write_str("length error"),
            Error::Unsupported(s) => write!(f, "unsupported: {s}"),
            Error::TooLarge(s) => write!(f, "too large: {s}"),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// A byte source read front to back.
pub trait Read {
    /// Read up to `buf.len()` bytes; `Ok(0)` only at the end of the data.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
}

/// A byte sink.
pub trait Write {
    fn write_all(&mut self, buf: &[u8]) -> Result<()>;
}

/// Random-access source (zip archives are read from the end).
pub trait ReadAt {
    fn size(&self) -> u64;
    /// Read at `off`; may return fewer bytes, `Ok(0)` only at the end.
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize>;
}

impl Read for &[u8] {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = buf.len().min(self.len());
        buf[..n].copy_from_slice(&self[..n]);
        *self = &self[n..];
        Ok(n)
    }
}

impl<T: Read + ?Sized> Read for &mut T {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        (**self).read(buf)
    }
}

impl Write for Vec<u8> {
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.extend_from_slice(buf);
        Ok(())
    }
}

impl<T: Write + ?Sized> Write for &mut T {
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        (**self).write_all(buf)
    }
}

impl ReadAt for [u8] {
    fn size(&self) -> u64 {
        self.len() as u64
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize> {
        if off >= self.len() as u64 {
            return Ok(0);
        }
        let off = off as usize;
        let n = buf.len().min(self.len() - off);
        buf[..n].copy_from_slice(&self[off..off + n]);
        Ok(n)
    }
}

impl ReadAt for Vec<u8> {
    fn size(&self) -> u64 {
        self.as_slice().size()
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize> {
        self.as_slice().read_at(off, buf)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn size(&self) -> u64 {
        (**self).size()
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize> {
        (**self).read_at(off, buf)
    }
}

/// Fill `buf` completely or fail with [`Error::UnexpectedEof`].
pub fn read_exact<R: Read + ?Sized>(r: &mut R, mut buf: &mut [u8]) -> Result<()> {
    while !buf.is_empty() {
        let n = r.read(buf)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Like [`read_exact`] but distinguishes a clean end before the first byte:
/// `Ok(false)` if nothing at all could be read.
pub fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        let n = r.read(&mut buf[got..])?;
        if n == 0 {
            return if got == 0 { Ok(false) } else { Err(Error::UnexpectedEof) };
        }
        got += n;
    }
    Ok(true)
}

/// Fill `buf` from `off` or fail with [`Error::UnexpectedEof`].
pub fn read_exact_at<R: ReadAt + ?Sized>(r: &R, mut off: u64, mut buf: &mut [u8]) -> Result<()> {
    while !buf.is_empty() {
        let n = r.read_at(off, buf)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        off += n as u64;
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Copy everything from `r` to `w`; returns the byte count.
pub fn copy<R: Read + ?Sized, W: Write + ?Sized>(r: &mut R, w: &mut W) -> Result<u64> {
    let mut buf = alloc::vec![0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        w.write_all(&buf[..n])?;
        total += n as u64;
    }
}

/// A sink that only counts (for `gzip -t`, `tar -t` of data, …).
#[derive(Default)]
pub struct Discard(pub u64);

impl Write for Discard {
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.0 += buf.len() as u64;
        Ok(())
    }
}
