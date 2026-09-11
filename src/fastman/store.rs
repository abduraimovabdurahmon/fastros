//! fastman image store — in-memory catalogue of pulled images.
//!
//! Stores up to MAX_IMAGES entries.  No disk persistence yet; entries are
//! lost on reboot (a future version will persist to diskfs).

use super::types::{Manifest, LayerInfo, MAX_LAYERS};

pub const MAX_IMAGES: usize = 32;

// ── Stored image ──────────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
pub struct StoredImage {
    pub valid:      bool,
    /// Short image ID (first 12 chars of config digest, or generated).
    pub id:         [u8; 12],
    pub name:       [u8; 128],
    pub name_len:   usize,
    pub tag:        [u8; 64],
    pub tag_len:    usize,
    pub layers:     [LayerInfo; MAX_LAYERS],
    pub layer_count: usize,
    /// Sum of compressed layer sizes in bytes.
    pub total_size: u64,
}

impl StoredImage {
    const fn empty() -> Self {
        Self {
            valid:  false,
            id:     [0; 12],
            name:   [0; 128],
            name_len: 0,
            tag:    [0; 64],
            tag_len: 0,
            layers: [LayerInfo::empty(); MAX_LAYERS],
            layer_count: 0,
            total_size: 0,
        }
    }
    pub fn name(&self) -> &[u8] { &self.name[..self.name_len] }
    pub fn tag(&self)  -> &[u8] { &self.tag[..self.tag_len] }
    pub fn id(&self)   -> &[u8] { &self.id[..] }
}

// ── Static store ──────────────────────────────────────────────────────────────

static mut IMAGES: [StoredImage; MAX_IMAGES] = [const { StoredImage::empty() }; MAX_IMAGES];
static mut IMAGE_COUNT: usize = 0;

// ── Public API ────────────────────────────────────────────────────────────────

/// Save a pulled image to the store.  Returns the image ID.
pub fn save(name: &[u8], tag: &[u8], manifest: &Manifest) -> [u8; 12] {
    let id = make_id(manifest);

    unsafe {
        // Replace if name+tag already exists
        for i in 0..IMAGE_COUNT {
            let img = &IMAGES[i];
            if img.valid && img.name() == name && img.tag() == tag {
                IMAGES[i] = build_entry(name, tag, manifest, id);
                return id;
            }
        }
        // New entry
        if IMAGE_COUNT < MAX_IMAGES {
            IMAGES[IMAGE_COUNT] = build_entry(name, tag, manifest, id);
            IMAGE_COUNT += 1;
        }
    }
    id
}

fn build_entry(name: &[u8], tag: &[u8], manifest: &Manifest, id: [u8; 12]) -> StoredImage {
    let mut img = StoredImage::empty();
    img.valid = true;
    img.id    = id;

    let nl = name.len().min(127);
    img.name[..nl].copy_from_slice(&name[..nl]);
    img.name_len = nl;

    let tl = tag.len().min(63);
    img.tag[..tl].copy_from_slice(&tag[..tl]);
    img.tag_len = tl;

    img.layer_count = manifest.layer_count;
    for i in 0..manifest.layer_count {
        img.layers[i] = manifest.layers[i];
        img.total_size = img.total_size.saturating_add(manifest.layers[i].size);
    }
    img
}

/// List all stored images.
pub fn list() -> &'static [StoredImage] {
    unsafe { &IMAGES[..IMAGE_COUNT] }
}

/// Find an image by name and tag.
pub fn find(name: &[u8], tag: &[u8]) -> Option<&'static StoredImage> {
    unsafe {
        for i in 0..IMAGE_COUNT {
            let img = &IMAGES[i];
            if img.valid && img.name() == name && img.tag() == tag {
                return Some(img);
            }
        }
    }
    None
}

/// Remove an image by name+tag.  Returns true if found and removed.
pub fn remove(name: &[u8], tag: &[u8]) -> bool {
    unsafe {
        for i in 0..IMAGE_COUNT {
            if IMAGES[i].valid && IMAGES[i].name() == name && IMAGES[i].tag() == tag {
                IMAGES[i].valid = false;
                // Compact
                for j in i..IMAGE_COUNT - 1 { IMAGES[j] = IMAGES[j + 1]; }
                IMAGE_COUNT -= 1;
                return true;
            }
        }
    }
    false
}

// ── ID generation ─────────────────────────────────────────────────────────────

/// Generate a 12-char short ID from the manifest's first layer digest.
fn make_id(manifest: &Manifest) -> [u8; 12] {
    let mut id = [b'0'; 12];
    if manifest.layer_count > 0 {
        let d = manifest.layers[0].digest_str();
        // Skip "sha256:" prefix (7 chars) and take next 12 hex chars
        let start = if d.starts_with(b"sha256:") { 7 } else { 0 };
        let end   = (start + 12).min(d.len());
        let src   = &d[start..end];
        let n = src.len().min(12);
        id[..n].copy_from_slice(&src[..n]);
    }
    id
}

// ── Size formatter ────────────────────────────────────────────────────────────

/// Format bytes as human-readable string into `buf`.  Returns slice.
pub fn fmt_size(bytes: u64, buf: &mut [u8; 16]) -> &[u8] {
    let (val, unit) = if bytes >= 1_073_741_824 {
        (bytes / 1_073_741_824, b"GB" as &[u8])
    } else if bytes >= 1_048_576 {
        (bytes / 1_048_576, b"MB" as &[u8])
    } else if bytes >= 1024 {
        (bytes / 1024, b"KB" as &[u8])
    } else {
        (bytes, b"B" as &[u8])
    };

    let mut pos = 0usize;
    // Write number
    if val == 0 {
        buf[pos] = b'0'; pos += 1;
    } else {
        let mut tmp = [0u8; 12];
        let mut tp  = 12usize;
        let mut v   = val;
        while v > 0 { tp -= 1; tmp[tp] = b'0' + (v % 10) as u8; v /= 10; }
        let n = (12 - tp).min(16 - pos);
        buf[pos..pos + n].copy_from_slice(&tmp[tp..tp + n]);
        pos += n;
    }
    // Write unit
    let un = unit.len().min(16 - pos);
    buf[pos..pos + un].copy_from_slice(&unit[..un]);
    pos += un;
    &buf[..pos]
}
