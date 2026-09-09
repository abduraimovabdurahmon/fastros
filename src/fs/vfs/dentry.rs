//! Directory Entry Cache (dcache)
//!
//! Maps path components to inodes to avoid disk lookups on every access.
//! Example: "/home/user/file" → 3 dentries: "home"→ino2, "user"→ino5, "file"→ino42

// TODO: Implement DentryCache with a hash map (path → inode_number).
// TODO: Implement lookup(path: &[u8]) -> Option<inode_number>
// TODO: Implement insert(path: &[u8], inode_number: u64)
// TODO: Implement evict(path: &[u8]) — for unlink, rename
