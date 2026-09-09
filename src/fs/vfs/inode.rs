//! VFS Inode trait
//!
//! An inode represents a file system object (file, directory, symlink, device).
//! Each concrete FS implements this trait.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeType {
    File,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

pub struct InodeMeta {
    pub inode_type: InodeType,
    pub size:       u64,
    pub uid:        u32,
    pub gid:        u32,
    pub mode:       u16,  // Unix permission bits
    pub created:    u64,  // Unix timestamp
    pub modified:   u64,
}

pub trait Inode {
    fn meta(&self) -> InodeMeta;

    /// Read bytes from a file inode at the given offset.
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError>;

    /// Write bytes to a file inode at the given offset.
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<usize, FsError>;

    /// List entries of a directory inode.
    fn readdir(&self, index: usize) -> Option<DirEntry>;

    /// Look up a child by name within a directory inode.
    fn lookup(&self, name: &[u8]) -> Option<u64>; // returns child inode number

    /// Create a new child in a directory.
    fn create(&mut self, name: &[u8], inode_type: InodeType) -> Result<u64, FsError>;

    /// Remove a child from a directory.
    fn unlink(&mut self, name: &[u8]) -> Result<(), FsError>;
}

pub struct DirEntry {
    pub inode_num: u64,
    pub name:      [u8; 256],
    pub name_len:  usize,
    pub entry_type: InodeType,
}

#[derive(Debug)]
pub enum FsError {
    NotFound,
    NotADirectory,
    NotAFile,
    PermissionDenied,
    NoSpace,
    IoError,
    InvalidArgument,
}
