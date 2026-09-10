//! FastROS Image Format
//!
//! FastROS does NOT use OCI/Docker image format.
//! A FastROS image is a single file:
//!
//!   [Header][Layer 0 (base)][Layer 1 (app)][Layer N][Metadata]
//!
//! - Layers are content-addressed (Blake3 hash).
//! - Layers are compressed (LZ4, built-in, no external crates).
//! - Images are signed (Ed25519, built-in).
//!
//! This keeps the image format simple and kernel-native.

/// Magic bytes at the start of every FastROS image file.
pub const IMAGE_MAGIC: [u8; 8] = *b"FASTROS\x01";

/// Image header on disk.
#[repr(C)]
pub struct ImageHeader {
    pub magic:       [u8; 8],
    pub version:     u32,
    pub layer_count: u32,
    pub name:        [u8; 128],
    pub tag:         [u8; 64],
    /// Blake3 hash of the image contents (excluding this field).
    pub content_hash: [u8; 32],
}

/// One layer inside an image.
#[repr(C)]
pub struct ImageLayer {
    pub hash:             [u8; 32],
    pub compressed_size:  u64,
    pub uncompressed_size: u64,
    pub offset:           u64,
}

/// In-memory representation of a loaded image.
pub struct Image {
    pub name:   [u8; 128],
    pub tag:    [u8; 64],
    pub layers: [ImageLayer; 16],
    pub layer_count: usize,
}

impl Image {
    /// Parse an image from raw bytes (e.g., loaded from disk).
    pub fn parse(_bytes: &[u8]) -> Option<Self> {
        // TODO: validate magic, checksum, parse header + layers
        None
    }
}
