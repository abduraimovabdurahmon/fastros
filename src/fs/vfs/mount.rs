//! Mount table
//!
//! Tracks which file system is mounted at which path.
//! Example: "/" → tmpfs, "/dev" → devfs, "/mnt/disk" → ext2

pub trait FileSystem {
    /// Return the root inode of this file system.
    fn root_inode(&self) -> u64;

    /// Get an inode by number.
    fn get_inode(&self, inum: u64) -> Option<&dyn super::inode::Inode>;

    fn name(&self) -> &'static str;
}

pub struct MountEntry {
    pub path:       [u8; 256],
    pub path_len:   usize,
    pub filesystem: &'static dyn FileSystem,
}

// TODO: Implement global mount table (array of MountEntry).
// TODO: mount(path, filesystem) → add to table
// TODO: unmount(path) → remove from table
// TODO: resolve(path) → find which MountEntry covers this path

pub fn init_mount_table() {
    // TODO: Initialize the mount table.
}
