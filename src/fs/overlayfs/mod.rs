//! OverlayFS — Union Filesystem for Container Root Filesystems
//!
//! Implements the VFS Inode trait over a stack of layers:
//!
//!   upper (writable) ← all container writes go here
//!   lower N          ← image layer N (read-only)
//!   ...
//!   lower 0          ← base image layer (read-only)
//!
//! On read: walk layers top-to-bottom, return first hit.
//! On write: copy file to upper (CoW), then write.
//! On delete: create a "whiteout" file in upper to mask lower layers.
//!
//! Used by container/overlay to mount each container's root filesystem.

/// A whiteout file masks a file that exists in a lower layer.
/// Named ".wh.<original_name>" in the upper layer.
pub const WHITEOUT_PREFIX: &[u8] = b".wh.";

pub struct OverlayInode {
    pub lower_count: usize,
    // TODO: array of lower-layer inode references
    // TODO: upper-layer inode reference (Option — None if not yet copied up)
}

impl OverlayInode {
    pub fn new(lower_count: usize) -> Self {
        Self { lower_count }
    }

    /// Look up a child by name across layers (upper first, then lower).
    pub fn lookup(&self, _name: &[u8]) -> Option<()> {
        // TODO: check upper, then each lower in order
        // TODO: if whiteout found in upper, return None (masked)
        None
    }

    /// Ensure a file exists in the upper layer (copy-up if needed).
    pub fn copy_up(&mut self) -> bool {
        // TODO: if already in upper, return true
        // TODO: allocate upper layer space, copy content from lower
        false
    }
}
