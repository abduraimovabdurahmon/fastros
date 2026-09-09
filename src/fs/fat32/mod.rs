//! FAT32 File System
//!
//! Widely compatible (USB drives, SD cards, EFI System Partition).
//! Structure:
//!   MBR/GPT → Boot Sector → Reserved → FAT1 → FAT2 → Data clusters
//!
//! Key structures:
//!   BPB (BIOS Parameter Block) — geometry and FAT location
//!   FAT (File Allocation Table) — linked list of clusters per file
//!   Directory entries — 32-byte records with name, size, start cluster

// TODO: Parse BPB from boot sector.
// TODO: Implement fat_read_cluster(n) → next cluster number.
// TODO: Implement readdir() by scanning directory entries.
// TODO: Implement read_file() by following FAT chain.
// TODO: Implement write/create/delete.
