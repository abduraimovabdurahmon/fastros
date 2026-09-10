//! Overlay Filesystem for Containers
//!
//! Each container gets a layered filesystem view:
//!
//!   [upper layer]  ← writable (container writes go here)
//!       ↑
//!   [image layers] ← read-only (from image)
//!       ↑
//!   [lower layer]  ← host root or base image
//!
//! Copy-on-Write: files are copied to upper on first write.
//! On container delete, upper layer is discarded (ephemeral).
//! On commit, upper layer is saved as a new image layer.

use crate::container::runtime::ContainerId;

pub struct OverlayMount {
    pub container_id: ContainerId,
    /// Physical address / block device offset of the upper (writable) layer.
    pub upper_offset: u64,
    pub upper_size:   u64,
    /// Number of read-only lower layers (from image).
    pub lower_count:  usize,
    pub lower_offsets: [u64; 16],
}

impl OverlayMount {
    /// Mount an overlay for a container.
    pub fn mount(_container_id: ContainerId, _image_idx: usize) -> Option<Self> {
        // TODO: allocate upper layer (tmpfs block)
        // TODO: map image layers as lower
        // TODO: register with fs::vfs as the container's root
        None
    }

    /// Unmount and discard the upper layer (container stop/delete).
    pub fn unmount(self) {
        // TODO: flush upper writes
        // TODO: free upper layer storage
    }

    /// Commit the upper layer as a new image layer (container commit).
    pub fn commit(&self) -> Option<[u8; 32]> {
        // TODO: hash upper layer contents, write to image store
        None
    }
}
