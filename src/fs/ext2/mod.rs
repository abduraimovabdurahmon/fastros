//! ext2 File System
//!
//! Classic Linux file system. Good learning target — well-documented spec.
//! Structure:
//!   Superblock → Block Groups → [block bitmap, inode bitmap, inode table, data blocks]
//!
//! Fixed inode size (128 bytes), 12 direct + 1 indirect + 1 double + 1 triple block pointers.
//! No journaling (ext3/4 add journaling on top).

// TODO: Parse superblock (magic=0xEF53, inode_count, block_count, etc.)
// TODO: Implement get_inode(inum) → read from inode table.
// TODO: Implement read_blocks(inode) → follow direct/indirect block pointers.
// TODO: Implement directory entry parsing (variable-length records).
