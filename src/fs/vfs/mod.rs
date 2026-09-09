//! Virtual File System (VFS)
//!
//! Abstraction layer that unifies all file systems under one interface.
//! Userspace sees a single unified directory tree regardless of which FS
//! is mounted where.
//!
//! Key concepts:
//!   Inode  — a file or directory (has metadata, no name)
//!   Dentry — a name → inode mapping (the "directory entry")
//!   Mount  — attaches a FS's root inode to a path in the VFS tree
//!   File   — an open handle to an inode (has offset, flags)

pub mod dentry;
pub mod inode;
pub mod mount;

pub fn init() {
    mount::init_mount_table();
}
