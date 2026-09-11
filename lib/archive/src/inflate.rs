//! Streaming raw-deflate decoder on top of `miniz_oxide`'s core
//! decompressor, with a heap-allocated 32 KiB history ring (the stream
//! wrapper in miniz_oxide keeps its dictionary inline, which would not fit
//! a small kernel stack).

use crate::{Error, Result};
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use miniz_oxide::inflate::core::{decompress, inflate_flags, DecompressorOxide};
use miniz_oxide::inflate::TINFLStatus;

const DICT: usize = 32 * 1024;

pub struct Inflater {
    d: Box<DecompressorOxide>,
    dict: Vec<u8>,
    /// Where the next `decompress` call writes in `dict`.
    dict_pos: usize,
    /// Decoded bytes not yet handed to the caller: `dict[avail_start..][..avail_len]`.
    avail_start: usize,
    avail_len: usize,
    done: bool,
}

impl Default for Inflater {
    fn default() -> Self {
        Self::new()
    }
}

impl Inflater {
    pub fn new() -> Inflater {
        Inflater { d: Box::default(), dict: vec![0; DICT], dict_pos: 0, avail_start: 0, avail_len: 0, done: false }
    }

    /// Start a new stream.
    pub fn reset(&mut self) {
        self.d.init();
        self.dict_pos = 0;
        self.avail_start = 0;
        self.avail_len = 0;
        self.done = false;
    }

    /// The final block was decoded and every byte handed out.
    pub fn is_finished(&self) -> bool {
        self.done && self.avail_len == 0
    }

    fn drain(&mut self, out: &mut [u8], written: &mut usize) {
        let n = self.avail_len.min(out.len() - *written);
        out[*written..*written + n].copy_from_slice(&self.dict[self.avail_start..self.avail_start + n]);
        *written += n;
        self.avail_start += n;
        self.avail_len -= n;
    }

    /// Decode from `input` into `out`; returns (input consumed, output
    /// written). `more_input` says whether data may follow `input`: when it
    /// is false, running out of input is an error. After the end of the
    /// stream nothing more is consumed, so `input[consumed..]` is whatever
    /// follows the deflate data (e.g. the gzip trailer).
    pub fn inflate(&mut self, input: &[u8], out: &mut [u8], more_input: bool) -> Result<(usize, usize)> {
        let mut consumed = 0;
        let mut written = 0;
        let mut starved = false;
        loop {
            self.drain(out, &mut written);
            if self.avail_len > 0 || written == out.len() || self.done || starved {
                return Ok((consumed, written));
            }
            let flags = if more_input { inflate_flags::TINFL_FLAG_HAS_MORE_INPUT } else { 0 };
            let (status, in_n, out_n) = decompress(&mut self.d, &input[consumed..], &mut self.dict, self.dict_pos, flags);
            consumed += in_n;
            self.avail_start = self.dict_pos;
            self.avail_len = out_n;
            self.dict_pos = (self.dict_pos + out_n) & (DICT - 1);
            match status {
                TINFLStatus::Done => self.done = true,
                TINFLStatus::HasMoreOutput => {}
                TINFLStatus::NeedsMoreInput => starved = true,
                TINFLStatus::FailedCannotMakeProgress => return Err(Error::UnexpectedEof),
                _ => return Err(Error::Corrupt("invalid compressed data")),
            }
        }
    }
}

/// Decode a complete raw-deflate buffer, refusing to produce more than
/// `limit` bytes.
pub fn decompress_all(data: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut inf = Inflater::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32 * 1024];
    let mut pos = 0;
    loop {
        let (c, w) = inf.inflate(&data[pos..], &mut buf, false)?;
        pos += c;
        if out.len() + w > limit {
            return Err(Error::TooLarge("decompressed data exceeds the limit"));
        }
        out.extend_from_slice(&buf[..w]);
        if inf.is_finished() {
            return Ok(out);
        }
        if c == 0 && w == 0 {
            return Err(Error::UnexpectedEof);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_miniz_output_in_tiny_steps() {
        let data: Vec<u8> = (0..200_000u32).map(|i| ((i * 31) % 251) as u8 ^ (i >> 9) as u8).collect();
        let c = miniz_oxide::deflate::compress_to_vec(&data, 6);
        // One input byte and 7 output bytes at a time: stresses every resume path.
        let mut inf = Inflater::new();
        let mut out = Vec::new();
        let mut pos = 0;
        let mut buf = [0u8; 7];
        while !inf.is_finished() {
            let end = (pos + 1).min(c.len());
            let (n, w) = inf.inflate(&c[pos..end], &mut buf, end < c.len()).unwrap();
            pos += n;
            out.extend_from_slice(&buf[..w]);
        }
        assert_eq!(pos, c.len());
        assert!(out == data);
    }

    #[test]
    fn stops_exactly_at_stream_end() {
        let mut c = miniz_oxide::deflate::compress_to_vec(b"hello hello hello", 9);
        let len = c.len();
        c.extend_from_slice(b"TRAILER!");
        let mut inf = Inflater::new();
        let mut buf = [0u8; 64];
        let (n, w) = inf.inflate(&c, &mut buf, false).unwrap();
        assert_eq!(n, len);
        assert_eq!(&buf[..w], b"hello hello hello");
        assert!(inf.is_finished());
    }

    #[test]
    fn truncation_and_garbage_never_panic() {
        let data: Vec<u8> = (0..50_000u32).map(|i| (i % 97) as u8).collect();
        let c = miniz_oxide::deflate::compress_to_vec(&data, 6);
        for cut in (0..c.len()).step_by(37) {
            assert!(decompress_all(&c[..cut], usize::MAX).is_err(), "cut at {cut}");
        }
        let mut x = 99u32;
        for _ in 0..200 {
            let g: Vec<u8> = (0..300)
                .map(|_| {
                    x = x.wrapping_mul(1103515245).wrapping_add(12345);
                    (x >> 16) as u8
                })
                .collect();
            let _ = decompress_all(&g, 1 << 20);
        }
    }

    #[test]
    fn limit_is_enforced() {
        let c = miniz_oxide::deflate::compress_to_vec(&vec![0u8; 1 << 20], 9);
        assert!(matches!(decompress_all(&c, 1000), Err(Error::TooLarge(_))));
    }
}
