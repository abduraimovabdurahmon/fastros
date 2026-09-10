//! LAYER 4 — File Systems
//!
//! VFS provides a unified interface over all concrete file systems.
//! All userspace file operations go through VFS, never directly to a FS.
//!
//! overlayfs is used by container/ to give each container its own root FS.
//!
//! CAN IMPORT:   kernel/, drivers/block, libs/
//! CANNOT IMPORT: arch/, hal/, container/, orchestrator/, userspace/

pub mod ext2;
pub mod fat32;
pub mod overlayfs;
pub mod tmpfs;
pub mod vfs;

pub fn init() {
    vfs::init();
    // Mount tmpfs as rootfs initially
    // tmpfs::mount("/");
}
