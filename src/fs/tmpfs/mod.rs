//! tmpfs — RAM-backed temporary file system
//!
//! Everything lives in kernel memory — no disk I/O.
//! Used as the initial root filesystem before a real disk FS is mounted.
//! Also used for /tmp, /dev, /proc-like paths.
//!
//! Fast, simple, lost on reboot.

// TODO: Implement TmpfsNode { kind: InodeType, data: Vec<u8> | children: Vec<(name, TmpfsNode)> }
// TODO: Implement Inode trait for TmpfsNode.
// TODO: Implement FileSystem trait for TmpFs.
