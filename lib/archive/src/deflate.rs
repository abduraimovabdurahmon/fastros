//! Deflate encoder (RFC 1951).
//!
//! The classic zlib design: a 2×32 KiB sliding window with hash chains,
//! lazy match evaluation tuned by level (zlib's configuration table), and
//! per block a choice between stored, fixed-Huffman and dynamic-Huffman
//! encodings, whichever is smallest. Code lengths are built with the
//! Moffat–Katajainen in-place algorithm and length-limited to 15 bits
//! (7 for the code-length code).
//!
//! All state is heap-allocated (the window, hash tables and the symbol
//! buffer): the encoder is safe to use on small kernel stacks.

use alloc::vec;
use alloc::vec::Vec;

const W: usize = 32 * 1024;
const WMASK: usize = W - 1;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;
const MAX_DIST: usize = W - MIN_LOOKAHEAD;
const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const NIL: usize = 0;
/// Matches of length 3 this far back cost more than three literals.
const TOO_FAR: usize = 4096;
/// Symbols per block before it is flushed.
const SYM_BUF: usize = 16 * 1024 - 1;
/// Slack after the window so match heuristics may peek past the data.
const WINDOW_ALLOC: usize = 2 * W + MAX_MATCH + 8;
const MATCH: u32 = 1 << 31;

const LIT_CODES: usize = 286;
const DIST_CODES: usize = 30;
const CL_CODES: usize = 19;
const END_BLOCK: usize = 256;

const LEN_BASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
/// Order in which code-length code lengths are sent.
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Length (minus 3) → length code index (0..=28).
const fn make_len_code() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut lm = 0;
    while lm < 256 {
        let len = lm as u16 + 3;
        let mut c = 28;
        while LEN_BASE[c] > len {
            c -= 1;
        }
        t[lm] = c as u8;
        lm += 1;
    }
    t
}
static LEN_CODE: [u8; 256] = make_len_code();

/// Distance (minus 1, 0..32767) → distance code.
fn dist_code(d: usize) -> usize {
    if d < 4 {
        d
    } else {
        let b = (usize::BITS - 1 - d.leading_zeros()) as usize;
        2 * b + ((d >> (b - 1)) & 1)
    }
}

/// zlib's per-level tuning: (good_length, max_lazy, nice_length, max_chain).
const CONFIG: [(usize, usize, usize, usize); 10] = [
    (0, 0, 0, 0),
    (4, 4, 8, 4),
    (4, 5, 16, 8),
    (4, 6, 32, 32),
    (4, 4, 16, 16),
    (8, 16, 32, 32),
    (8, 16, 128, 128),
    (8, 32, 128, 256),
    (32, 128, 258, 1024),
    (32, 258, 258, 4096),
];

struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitWriter {
    fn put(&mut self, value: u32, bits: u32) {
        debug_assert!(bits <= 32);
        let v = if bits >= 32 { value as u64 } else { (value as u64) & ((1u64 << bits) - 1) };
        self.acc |= v << self.n;
        self.n += bits;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    fn align(&mut self) {
        if self.n > 0 {
            self.out.push(self.acc as u8);
            self.acc = 0;
            self.n = 0;
        }
    }
}

/// Streaming deflate compressor.
pub struct Deflater {
    level: u8,
    good: usize,
    lazy: usize,
    nice: usize,
    chain: usize,
    window: Vec<u8>,
    head: Vec<u16>,
    prev: Vec<u16>,
    strstart: usize,
    lookahead: usize,
    block_start: isize,
    match_start: usize,
    match_length: usize,
    prev_length: usize,
    match_available: bool,
    syms: Vec<u32>,
    lit_freq: [u32; LIT_CODES],
    dist_freq: [u32; DIST_CODES],
    bits: BitWriter,
    finished: bool,
}

impl Deflater {
    /// A compressor at `level` 0 (store) to 9 (best); larger values clamp to 9.
    pub fn new(level: u8) -> Deflater {
        let level = level.min(9);
        let (good, lazy, nice, chain) = CONFIG[level as usize];
        Deflater {
            level,
            good,
            lazy,
            nice,
            chain,
            window: vec![0; WINDOW_ALLOC],
            head: vec![0; HASH_SIZE],
            prev: vec![0; W],
            strstart: 0,
            lookahead: 0,
            block_start: 0,
            match_start: 0,
            match_length: MIN_MATCH - 1,
            prev_length: MIN_MATCH - 1,
            match_available: false,
            syms: Vec::with_capacity(SYM_BUF + 1),
            lit_freq: [0; LIT_CODES],
            dist_freq: [0; DIST_CODES],
            bits: BitWriter { out: Vec::new(), acc: 0, n: 0 },
            finished: false,
        }
    }

    pub fn level(&self) -> u8 {
        self.level
    }

    /// Compress `input`, appending whatever output is ready to `out`.
    pub fn write(&mut self, mut input: &[u8], out: &mut Vec<u8>) {
        assert!(!self.finished, "Deflater::write after finish");
        while !input.is_empty() {
            if self.strstart >= W + MAX_DIST {
                self.slide();
            }
            let end = self.strstart + self.lookahead;
            let n = (2 * W - end).min(input.len());
            self.window[end..end + n].copy_from_slice(&input[..n]);
            self.lookahead += n;
            input = &input[n..];
            self.compress(false);
        }
        out.append(&mut self.bits.out);
    }

    /// Flush everything and write the final block. Further writes panic.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        if !self.finished {
            self.compress(true);
            if self.match_available {
                let b = self.window[self.strstart - 1];
                self.tally_lit(b);
                self.match_available = false;
            }
            self.flush_block(true);
            self.bits.align();
            self.finished = true;
        }
        out.append(&mut self.bits.out);
    }

    fn slide(&mut self) {
        self.window.copy_within(W..2 * W, 0);
        self.match_start = self.match_start.saturating_sub(W);
        self.strstart -= W;
        self.block_start -= W as isize;
        for h in self.head.iter_mut().chain(self.prev.iter_mut()) {
            *h = if *h as usize >= W { *h - W as u16 } else { NIL as u16 };
        }
    }

    fn hash(&self, p: usize) -> usize {
        let w = &self.window;
        let v = w[p] as u32 | (w[p + 1] as u32) << 8 | (w[p + 2] as u32) << 16;
        (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
    }

    /// Insert the string at `p` and return the previous head of its chain.
    fn insert(&mut self, p: usize) -> usize {
        let h = self.hash(p);
        let old = self.head[h];
        self.prev[p & WMASK] = old;
        self.head[h] = p as u16;
        old as usize
    }

    fn longest_match(&mut self, mut cur: usize) -> usize {
        let mut chain = self.chain;
        if self.prev_length >= self.good {
            chain >>= 2;
        }
        let scan = self.strstart;
        let max_len = MAX_MATCH.min(self.lookahead);
        let nice = self.nice.min(max_len);
        let mut best = self.prev_length;
        if best >= max_len {
            return max_len;
        }
        let limit = scan.saturating_sub(MAX_DIST);
        let w = &self.window;
        loop {
            let m = cur;
            if w[m + best] == w[scan + best] && w[m] == w[scan] && w[m + 1] == w[scan + 1] {
                let mut len = 2;
                while len < max_len && w[m + len] == w[scan + len] {
                    len += 1;
                }
                if len > best {
                    self.match_start = m;
                    best = len;
                    if len >= nice {
                        break;
                    }
                }
            }
            cur = self.prev[m & WMASK] as usize;
            chain -= 1;
            if cur <= limit || cur >= m || chain == 0 {
                break;
            }
        }
        best.min(self.lookahead)
    }

    fn tally_lit(&mut self, b: u8) {
        self.syms.push(b as u32);
        self.lit_freq[b as usize] += 1;
    }

    fn tally_match(&mut self, dist: usize, len: usize) {
        debug_assert!((1..=W).contains(&dist) && (MIN_MATCH..=MAX_MATCH).contains(&len));
        let lm = len - MIN_MATCH;
        self.syms.push(MATCH | ((dist as u32 - 1) << 8) | lm as u32);
        self.lit_freq[257 + LEN_CODE[lm] as usize] += 1;
        self.dist_freq[dist_code(dist - 1)] += 1;
    }

    fn compress(&mut self, flush: bool) {
        loop {
            if self.lookahead == 0 || (self.lookahead < MIN_LOOKAHEAD && !flush) {
                return;
            }
            if self.level == 0 {
                let b = self.window[self.strstart];
                self.tally_lit(b);
                self.strstart += 1;
                self.lookahead -= 1;
                // Stored blocks may be as long as the window keeps them.
                if self.syms.len() >= MAX_DIST {
                    self.flush_block(false);
                }
                continue;
            }
            let mut hash_head = NIL;
            if self.lookahead >= MIN_MATCH {
                hash_head = self.insert(self.strstart);
            }
            self.prev_length = self.match_length;
            let prev_match = self.match_start;
            self.match_length = MIN_MATCH - 1;
            if hash_head != NIL && self.prev_length < self.lazy && self.strstart - hash_head <= MAX_DIST {
                self.match_length = self.longest_match(hash_head);
                if self.match_length == MIN_MATCH && self.strstart - self.match_start > TOO_FAR {
                    self.match_length = MIN_MATCH - 1;
                }
            }
            if self.prev_length >= MIN_MATCH && self.match_length <= self.prev_length {
                // The previous match is at least as good: emit it.
                let max_insert = self.strstart + self.lookahead - MIN_MATCH;
                self.tally_match(self.strstart - 1 - prev_match, self.prev_length);
                self.lookahead -= self.prev_length - 1;
                let mut n = self.prev_length - 2;
                while n > 0 {
                    self.strstart += 1;
                    if self.strstart <= max_insert {
                        self.insert(self.strstart);
                    }
                    n -= 1;
                }
                self.match_available = false;
                self.match_length = MIN_MATCH - 1;
                self.strstart += 1;
                if self.syms.len() >= SYM_BUF {
                    self.flush_block(false);
                }
            } else if self.match_available {
                let b = self.window[self.strstart - 1];
                self.tally_lit(b);
                if self.syms.len() >= SYM_BUF {
                    self.flush_block(false);
                }
                self.strstart += 1;
                self.lookahead -= 1;
            } else {
                self.match_available = true;
                self.strstart += 1;
                self.lookahead -= 1;
            }
        }
    }

    fn flush_block(&mut self, last: bool) {
        self.lit_freq[END_BLOCK] += 1;
        let stored_len = (self.strstart as isize - self.block_start) as usize;
        let stored_ok = self.block_start >= 0;

        let lit_lens = build_lengths(&self.lit_freq, 15);
        let dist_lens = build_lengths(&self.dist_freq, 15);
        let hlit = (257..LIT_CODES).rev().find(|&i| lit_lens[i] != 0).map_or(257, |i| i + 1).max(257);
        let hdist = (0..DIST_CODES).rev().find(|&i| dist_lens[i] != 0).map_or(1, |i| i + 1);
        let mut seq = Vec::with_capacity(hlit + hdist);
        seq.extend_from_slice(&lit_lens[..hlit]);
        seq.extend_from_slice(&dist_lens[..hdist]);
        let rle = rle_lengths(&seq);
        let mut cl_freq = [0u32; CL_CODES];
        for &(s, _) in &rle {
            cl_freq[s as usize] += 1;
        }
        let cl_lens = build_lengths(&cl_freq, 7);
        let hclen = (0..CL_CODES).rev().find(|&i| cl_lens[CL_ORDER[i]] != 0).map_or(4, |i| i + 1).max(4);

        let mut dyn_bits = 3 + 5 + 5 + 4 + 3 * hclen as u64;
        for &(s, _) in &rle {
            dyn_bits += cl_lens[s as usize] as u64
                + match s {
                    16 => 2,
                    17 => 3,
                    18 => 7,
                    _ => 0,
                };
        }
        dyn_bits += self.data_bits(&lit_lens, &dist_lens);
        let fixed_bits = 3 + self.data_bits(&FIXED_LIT_LENS[..LIT_CODES], &FIXED_DIST_LENS);
        let chunks = stored_len.div_ceil(65535).max(1) as u64;
        let stored_bits = chunks * (3 + 7 + 32) + 8 * stored_len as u64;

        if stored_ok && (self.level == 0 || stored_bits <= fixed_bits.min(dyn_bits)) {
            self.emit_stored(self.block_start as usize, stored_len, last);
        } else if fixed_bits <= dyn_bits {
            self.bits.put(last as u32, 1);
            self.bits.put(1, 2);
            let lc = codes_from_lengths(&FIXED_LIT_LENS);
            let dc = codes_from_lengths(&FIXED_DIST_LENS);
            self.emit_symbols(&lc, &FIXED_LIT_LENS, &dc, &FIXED_DIST_LENS);
        } else {
            self.bits.put(last as u32, 1);
            self.bits.put(2, 2);
            self.bits.put((hlit - 257) as u32, 5);
            self.bits.put((hdist - 1) as u32, 5);
            self.bits.put((hclen - 4) as u32, 4);
            for &o in &CL_ORDER[..hclen] {
                self.bits.put(cl_lens[o] as u32, 3);
            }
            let cl_codes = codes_from_lengths(&cl_lens);
            for &(s, e) in &rle {
                let s = s as usize;
                self.bits.put(cl_codes[s] as u32, cl_lens[s] as u32);
                match s {
                    16 => self.bits.put(e as u32, 2),
                    17 => self.bits.put(e as u32, 3),
                    18 => self.bits.put(e as u32, 7),
                    _ => {}
                }
            }
            let lc = codes_from_lengths(&lit_lens);
            let dc = codes_from_lengths(&dist_lens);
            self.emit_symbols(&lc, &lit_lens, &dc, &dist_lens);
        }

        self.syms.clear();
        self.lit_freq = [0; LIT_CODES];
        self.dist_freq = [0; DIST_CODES];
        self.block_start = self.strstart as isize;
    }

    /// Bits the block's symbols take with the given code lengths.
    fn data_bits(&self, lit_lens: &[u8], dist_lens: &[u8]) -> u64 {
        let mut bits = 0u64;
        for (i, &f) in self.lit_freq.iter().enumerate() {
            bits += f as u64 * lit_lens[i] as u64;
            if i >= 257 {
                bits += f as u64 * LEN_EXTRA[i - 257] as u64;
            }
        }
        for (i, &f) in self.dist_freq.iter().enumerate() {
            bits += f as u64 * (dist_lens[i] as u64 + DIST_EXTRA[i] as u64);
        }
        bits
    }

    fn emit_symbols(&mut self, lc: &[u16], ll: &[u8], dc: &[u16], dl: &[u8]) {
        let bits = &mut self.bits;
        for &s in &self.syms {
            if s & MATCH == 0 {
                bits.put(lc[s as usize] as u32, ll[s as usize] as u32);
                continue;
            }
            let lm = (s & 0xFF) as usize;
            let d = ((s >> 8) & 0x7FFF) as usize;
            let c = LEN_CODE[lm] as usize;
            bits.put(lc[257 + c] as u32, ll[257 + c] as u32);
            if LEN_EXTRA[c] > 0 {
                bits.put((lm + MIN_MATCH - LEN_BASE[c] as usize) as u32, LEN_EXTRA[c] as u32);
            }
            let c = dist_code(d);
            bits.put(dc[c] as u32, dl[c] as u32);
            if DIST_EXTRA[c] > 0 {
                bits.put((d + 1 - DIST_BASE[c] as usize) as u32, DIST_EXTRA[c] as u32);
            }
        }
        bits.put(lc[END_BLOCK] as u32, ll[END_BLOCK] as u32);
    }

    fn emit_stored(&mut self, start: usize, len: usize, last: bool) {
        let data = &self.window[start..start + len];
        let bits = &mut self.bits;
        let n = len.div_ceil(65535).max(1);
        for i in 0..n {
            let chunk = &data[(i * 65535).min(len)..((i + 1) * 65535).min(len)];
            bits.put((last && i == n - 1) as u32, 1);
            bits.put(0, 2);
            bits.align();
            let l = chunk.len() as u16;
            bits.out.extend_from_slice(&l.to_le_bytes());
            bits.out.extend_from_slice(&(!l).to_le_bytes());
            bits.out.extend_from_slice(chunk);
        }
    }
}

const fn make_fixed_lit() -> [u8; 288] {
    let mut t = [0u8; 288];
    let mut i = 0;
    while i < 288 {
        t[i] = if i < 144 {
            8
        } else if i < 256 {
            9
        } else if i < 280 {
            7
        } else {
            8
        };
        i += 1;
    }
    t
}
static FIXED_LIT_LENS: [u8; 288] = make_fixed_lit();
static FIXED_DIST_LENS: [u8; 30] = [5; 30];

/// Run-length encode a code-length sequence with symbols 16/17/18.
/// Returns (symbol, extra-bits value) pairs.
fn rle_lengths(seq: &[u8]) -> Vec<(u8, u8)> {
    let mut out = Vec::with_capacity(seq.len());
    let mut i = 0;
    while i < seq.len() {
        let l = seq[i];
        let mut run = 1;
        while i + run < seq.len() && seq[i + run] == l {
            run += 1;
        }
        i += run;
        if l == 0 {
            let mut r = run;
            while r >= 11 {
                let k = r.min(138);
                out.push((18, (k - 11) as u8));
                r -= k;
            }
            if r >= 3 {
                out.push((17, (r - 3) as u8));
                r = 0;
            }
            for _ in 0..r {
                out.push((0, 0));
            }
        } else {
            out.push((l, 0));
            let mut r = run - 1;
            while r >= 3 {
                let k = r.min(6);
                out.push((16, (k - 3) as u8));
                r -= k;
            }
            for _ in 0..r {
                out.push((l, 0));
            }
        }
    }
    out
}

/// Huffman code lengths for `freqs`, limited to `limit` bits. At least two
/// symbols always get a code (a one-code tree is not decodable everywhere).
pub(crate) fn build_lengths(freqs: &[u32], limit: usize) -> Vec<u8> {
    let mut syms: Vec<(u32, u16)> = freqs.iter().enumerate().filter(|(_, &f)| f > 0).map(|(i, &f)| (f, i as u16)).collect();
    let mut s = 0u16;
    while syms.len() < 2 && (s as usize) < freqs.len() {
        if !syms.iter().any(|&(_, x)| x == s) {
            syms.push((1, s));
        }
        s += 1;
    }
    syms.sort_unstable();
    let mut a: Vec<u32> = syms.iter().map(|&(f, _)| f).collect();
    minimum_redundancy(&mut a);
    let mut num = vec![0u32; limit.max(a.len()) + 2];
    for &d in &a {
        num[d as usize] += 1;
    }
    enforce_max_code_size(&mut num, limit);
    let mut lens = vec![0u8; freqs.len()];
    let mut j = syms.len();
    for (l, &count) in num.iter().enumerate().take(limit + 1).skip(1) {
        for _ in 0..count {
            j -= 1;
            lens[syms[j].1 as usize] = l as u8;
        }
    }
    lens
}

/// Moffat–Katajainen: `a` holds weights sorted ascending; on return, `a[i]`
/// is the code length of the i-th symbol.
fn minimum_redundancy(a: &mut [u32]) {
    let n = a.len();
    if n == 0 {
        return;
    }
    if n == 1 {
        a[0] = 1;
        return;
    }
    a[0] += a[1];
    let mut root = 0usize;
    let mut leaf = 2usize;
    for next in 1..n - 1 {
        if leaf >= n || a[root] < a[leaf] {
            a[next] = a[root];
            a[root] = next as u32;
            root += 1;
        } else {
            a[next] = a[leaf];
            leaf += 1;
        }
        if leaf >= n || (root < next && a[root] < a[leaf]) {
            a[next] += a[root];
            a[root] = next as u32;
            root += 1;
        } else {
            a[next] += a[leaf];
            leaf += 1;
        }
    }
    a[n - 2] = 0;
    for next in (0..n.saturating_sub(2)).rev() {
        a[next] = a[a[next] as usize] + 1;
    }
    let mut avail: isize = 1;
    let mut used: isize = 0;
    let mut depth = 0u32;
    let mut root = n as isize - 2;
    let mut next = n as isize - 1;
    while avail > 0 {
        while root >= 0 && a[root as usize] == depth {
            used += 1;
            root -= 1;
        }
        while avail > used {
            a[next as usize] = depth;
            next -= 1;
            avail -= 1;
        }
        avail = 2 * used;
        depth += 1;
        used = 0;
    }
}

/// Fold codes deeper than `max` into `max` and restore the Kraft equality
/// (miniz's `tdefl_huffman_enforce_max_code_size`).
fn enforce_max_code_size(num: &mut [u32], max: usize) {
    let deeper: u32 = num[max + 1..].iter().sum();
    if deeper == 0 {
        return;
    }
    num[max] += deeper;
    for x in num[max + 1..].iter_mut() {
        *x = 0;
    }
    let mut total: u64 = 0;
    for i in 1..=max {
        total += (num[i] as u64) << (max - i);
    }
    while total > 1u64 << max {
        num[max] -= 1;
        for i in (1..max).rev() {
            if num[i] != 0 {
                num[i] -= 1;
                num[i + 1] += 2;
                break;
            }
        }
        total -= 1;
    }
}

/// Canonical codes (RFC 1951 §3.2.2), bit-reversed for LSB-first output.
pub(crate) fn codes_from_lengths(lens: &[u8]) -> Vec<u16> {
    let mut count = [0u16; 16];
    for &l in lens {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u16; 16];
    let mut code = 0u16;
    for bits in 1..16 {
        code = (code + count[bits - 1]) << 1;
        next[bits] = code;
    }
    let mut codes = vec![0u16; lens.len()];
    for (i, &l) in lens.iter().enumerate() {
        if l == 0 {
            continue;
        }
        let c = next[l as usize];
        next[l as usize] += 1;
        codes[i] = c.reverse_bits() >> (16 - l as u32);
    }
    codes
}

/// Compress a whole buffer.
pub fn compress(data: &[u8], level: u8) -> Vec<u8> {
    let mut d = Deflater::new(level);
    let mut out = Vec::new();
    d.write(data, &mut out);
    d.finish(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inflate;

    fn roundtrip(data: &[u8], level: u8) -> usize {
        let c = compress(data, level);
        let d = inflate::decompress_all(&c, usize::MAX).expect("inflate");
        assert_eq!(d.len(), data.len(), "level {level}");
        assert!(d == data, "level {level}: data differs");
        c.len()
    }

    fn pseudo_random(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    fn texty(n: usize) -> Vec<u8> {
        let words = ["the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog ", "FastROS ", "kernel\n"];
        let mut x = 12345u64;
        let mut v = Vec::new();
        while v.len() < n {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            v.extend_from_slice(words[(x >> 33) as usize % words.len()].as_bytes());
        }
        v.truncate(n);
        v
    }

    #[test]
    fn empty_and_tiny() {
        for level in 0..=9 {
            roundtrip(b"", level);
            roundtrip(b"a", level);
            roundtrip(b"ab", level);
            roundtrip(b"abc", level);
            roundtrip(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", level);
        }
    }

    #[test]
    fn all_levels_text_and_random() {
        let text = texty(300_000);
        let rnd = pseudo_random(200_000, 0x1234_5678_9abc_def1);
        for level in 0..=9 {
            let ct = roundtrip(&text, level);
            let cr = roundtrip(&rnd, level);
            if level > 0 {
                assert!(ct < text.len() / 3, "text should compress well at level {level}: {ct}");
            }
            // Incompressible data grows only by the stored-block headers:
            // 5 bytes per block (16 Ki symbols, or 32 KiB at level 0).
            let block = if level == 0 { MAX_DIST } else { SYM_BUF };
            assert!(cr <= rnd.len() + (rnd.len() / block + 1) * 5 + 2, "level {level}: {cr}");
        }
    }

    #[test]
    fn long_runs_and_window_edges() {
        let mut v = vec![0u8; 5 * W + 123];
        v.extend(pseudo_random(3 * W, 7));
        v.extend(vec![0xAA; 70_000]);
        v.extend(texty(2 * W + 5));
        for level in [0, 1, 6, 9] {
            roundtrip(&v, level);
        }
    }

    #[test]
    fn streaming_in_odd_chunks_matches_one_shot_output() {
        let data = texty(150_000);
        for level in [1, 6, 9] {
            let whole = compress(&data, level);
            let mut d = Deflater::new(level);
            let mut out = Vec::new();
            for chunk in data.chunks(777) {
                d.write(chunk, &mut out);
            }
            d.finish(&mut out);
            let back = inflate::decompress_all(&out, usize::MAX).unwrap();
            assert!(back == data);
            // Chunking only moves slide points; sizes stay close.
            assert!(out.len() < whole.len() + whole.len() / 20 + 64);
        }
    }

    #[test]
    fn skewed_frequencies_respect_the_length_limit() {
        // Fibonacci-like frequencies force very deep trees before limiting.
        let mut freqs = [0u32; 286];
        let (mut a, mut b) = (1u32, 1u32);
        for f in freqs.iter_mut().take(30) {
            *f = a;
            let c = a + b;
            a = b;
            b = c.min(1 << 24);
        }
        let lens = build_lengths(&freqs, 15);
        assert!(lens.iter().all(|&l| l <= 15));
        let kraft: u64 = lens.iter().filter(|&&l| l > 0).map(|&l| 1u64 << (15 - l)).sum();
        assert_eq!(kraft, 1 << 15, "tree must be complete");
    }

    #[test]
    fn dist_codes_match_the_table() {
        for d in 0..32768usize {
            let c = dist_code(d);
            let base = DIST_BASE[c] as usize;
            assert!(d + 1 >= base && d + 1 - base < (1 << DIST_EXTRA[c]), "dist {}", d + 1);
        }
        for lm in 0..256usize {
            let c = LEN_CODE[lm] as usize;
            let len = lm + 3;
            assert!(len >= LEN_BASE[c] as usize && len - (LEN_BASE[c] as usize) < (1 << LEN_EXTRA[c]).max(1));
        }
    }

    #[test]
    fn miniz_can_decode_our_output() {
        let data = texty(100_000);
        for level in [1, 5, 9] {
            let c = compress(&data, level);
            let d = miniz_oxide::inflate::decompress_to_vec(&c).unwrap();
            assert!(d == data);
        }
    }
}
