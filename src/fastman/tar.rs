//! POSIX ustar tar archive parser — no allocation, no external crates.
//!
//! Used to extract OCI/Docker image layers (each layer is a tar archive,
//! optionally gzip-compressed — decompression is handled upstream).
//!
//! Format (512-byte blocks):
//!   [Header 512 B][Data: ceil(size/512) * 512 B][Header][Data]...
//!   Two consecutive all-zero blocks mark end-of-archive.

pub const BLOCK: usize = 512;

/// Entry type flags (byte 156 of the header).
pub const TYPE_FILE:    u8 = b'0';
pub const TYPE_LINK:    u8 = b'1';  // hard link
pub const TYPE_SYMLINK: u8 = b'2';  // symbolic link
pub const TYPE_CHAR:    u8 = b'3';
pub const TYPE_BLOCK:   u8 = b'4';
pub const TYPE_DIR:     u8 = b'5';  // directory
pub const TYPE_FIFO:    u8 = b'6';
// GNU/pax extended headers — skipped transparently
pub const TYPE_GNU_LONG_NAME: u8 = b'L';
pub const TYPE_GNU_LONG_LINK: u8 = b'K';
pub const TYPE_PAX_GLOBAL:    u8 = b'g';
pub const TYPE_PAX_NEXT:      u8 = b'x';

// ── POSIX ustar header offsets ────────────────────────────────────────────────
//   0-99   : name
//   100-107: mode (octal)
//   108-115: uid  (octal)
//   116-123: gid  (octal)
//   124-135: size (octal)
//   136-147: mtime (octal)
//   148-155: checksum
//   156    : typeflag
//   157-256: linkname
//   257-262: magic ("ustar")
//   263-264: version
//   265-296: uname
//   297-328: gname
//   329-336: devmajor (octal)
//   337-344: devminor (octal)
//   345-499: prefix
//   500-511: padding

// ── Public types ─────────────────────────────────────────────────────────────

/// A single entry from a tar archive.
pub struct TarEntry<'a> {
    /// Full path (ustar prefix + "/" + name, or GNU name from LongName block).
    pub name:     [u8; 256],
    pub name_len: usize,
    /// Link target for symlinks.
    pub link:     [u8; 256],
    pub link_len: usize,
    /// Unpadded file size in bytes.
    pub size:     u64,
    /// Entry type (TYPE_FILE, TYPE_DIR, TYPE_SYMLINK, …).
    pub typeflag: u8,
    /// Unix permission bits (e.g. 0o755).
    pub mode:     u32,
    /// Raw file data (exactly `size` bytes — NOT block-padded).
    pub data:     &'a [u8],
}

impl<'a> TarEntry<'a> {
    pub fn name(&self)    -> &[u8] { &self.name[..self.name_len] }
    pub fn link_tgt(&self)-> &[u8] { &self.link[..self.link_len] }
    pub fn is_file(&self) -> bool  { self.typeflag == TYPE_FILE || self.typeflag == 0 }
    pub fn is_dir(&self)  -> bool  { self.typeflag == TYPE_DIR }
    pub fn is_symlink(&self) -> bool { self.typeflag == TYPE_SYMLINK }
}

/// Iterator over tar entries in a raw byte slice.
///
/// Transparently skips GNU/pax long-name headers and uses them to override
/// the name of the following entry.
pub struct TarIter<'a> {
    data:          &'a [u8],
    pos:           usize,
    /// Pending long name from a GNU `L` block.
    pending_name:     [u8; 256],
    pending_name_len: usize,
    /// Pending long linkname from a GNU `K` block.
    pending_link:     [u8; 256],
    pending_link_len: usize,
}

impl<'a> TarIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos:               0,
            pending_name:      [0; 256],
            pending_name_len:  0,
            pending_link:      [0; 256],
            pending_link_len:  0,
        }
    }
}

impl<'a> Iterator for TarIter<'a> {
    type Item = TarEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos + BLOCK > self.data.len() { return None; }

            let hdr = &self.data[self.pos..self.pos + BLOCK];

            // End-of-archive: two all-zero blocks
            if hdr.iter().all(|&b| b == 0) { return None; }

            let size        = octal_bytes(&hdr[124..136]);
            let data_blocks = (size + 511) / 512;
            let data_start  = self.pos + BLOCK;
            let data_end    = data_start + data_blocks as usize * BLOCK;

            if data_end > self.data.len() { return None; }

            let typeflag = if hdr[156] == 0 { b'0' } else { hdr[156] };
            self.pos = data_end;

            // ── GNU long-name / pax extended header — collect and continue ────
            match typeflag {
                TYPE_GNU_LONG_NAME => {
                    let n = (size as usize).min(255);
                    self.pending_name[..n].copy_from_slice(&self.data[data_start..data_start + n]);
                    self.pending_name_len = nul_trim(n, &self.pending_name);
                    continue;
                }
                TYPE_GNU_LONG_LINK => {
                    let n = (size as usize).min(255);
                    self.pending_link[..n].copy_from_slice(&self.data[data_start..data_start + n]);
                    self.pending_link_len = nul_trim(n, &self.pending_link);
                    continue;
                }
                TYPE_PAX_GLOBAL | TYPE_PAX_NEXT => { continue; }
                _ => {}
            }

            // ── Build full name ───────────────────────────────────────────────
            let (name, name_len) = if self.pending_name_len > 0 {
                let mut n = [0u8; 256];
                let l = self.pending_name_len;
                n[..l].copy_from_slice(&self.pending_name[..l]);
                self.pending_name_len = 0;
                (n, l)
            } else {
                ustar_name(hdr)
            };

            // ── Build link target ─────────────────────────────────────────────
            let (link, link_len) = if self.pending_link_len > 0 {
                let mut l = [0u8; 256];
                let ll = self.pending_link_len;
                l[..ll].copy_from_slice(&self.pending_link[..ll]);
                self.pending_link_len = 0;
                (l, ll)
            } else {
                let raw_link_len = nul_len(&hdr[157..257]).min(255);
                let mut l = [0u8; 256];
                l[..raw_link_len].copy_from_slice(&hdr[157..157 + raw_link_len]);
                (l, raw_link_len)
            };

            let mode = octal_bytes(&hdr[100..108]) as u32;

            return Some(TarEntry {
                name,
                name_len,
                link,
                link_len,
                size,
                typeflag,
                mode,
                data: &self.data[data_start..data_start + size as usize],
            });
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse an octal ASCII field (null/space terminated).
pub fn octal_bytes(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &c in b {
        match c {
            0 | b' ' => break,
            b'0'..=b'7' => v = v * 8 + (c - b'0') as u64,
            _ => break,
        }
    }
    v
}

/// Build ustar full path: prefix (bytes 345-499) + "/" + name (bytes 0-99).
fn ustar_name(hdr: &[u8]) -> ([u8; 256], usize) {
    let mut name     = [0u8; 256];
    let mut name_len = 0usize;

    let prefix_len = nul_len(&hdr[345..500]);
    if prefix_len > 0 {
        let n = prefix_len.min(255);
        name[..n].copy_from_slice(&hdr[345..345 + n]);
        name_len += n;
        if name_len < 255 {
            name[name_len] = b'/';
            name_len += 1;
        }
    }

    let nm_len = nul_len(&hdr[0..100]).min(255 - name_len);
    name[name_len..name_len + nm_len].copy_from_slice(&hdr[..nm_len]);
    name_len += nm_len;

    (name, name_len)
}

/// Length of a string up to first nul byte.
fn nul_len(b: &[u8]) -> usize {
    b.iter().position(|&c| c == 0).unwrap_or(b.len())
}

/// Trim trailing nul bytes, return actual string length.
fn nul_trim(max: usize, buf: &[u8; 256]) -> usize {
    let mut l = max;
    while l > 0 && buf[l - 1] == 0 { l -= 1; }
    l
}
