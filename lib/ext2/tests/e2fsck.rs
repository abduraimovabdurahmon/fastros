//! Cross-checks against e2fsprogs: every image this crate writes must pass
//! `e2fsck -fn`, and images made by `mke2fs` must work with this crate.
//! (e2fsprogs is installed in the fastros-dev container.)

use fastros_ext2::{format, Attr, Device, Error, Ext2, FormatOptions, Result, ROOT_INO, S_IFREG};
use std::process::Command;

struct Mem(Vec<u8>);

impl Device for Mem {
    fn read(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        let o = off as usize;
        buf.copy_from_slice(self.0.get(o..o + buf.len()).ok_or(Error::Io)?);
        Ok(())
    }
    fn write(&mut self, off: u64, buf: &[u8]) -> Result<()> {
        let o = off as usize;
        self.0.get_mut(o..o + buf.len()).ok_or(Error::Io)?.copy_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

fn clock() -> u32 {
    1_789_000_000
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("fastros-ext2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn fsck(img: &[u8], name: &str) {
    let p = tmp(name);
    std::fs::write(&p, img).unwrap();
    let out = Command::new("e2fsck").args(["-fn"]).arg(&p).output().expect("e2fsck installed");
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "e2fsck found problems in {name}:\n{text}");
}

fn debugfs(img: &[u8], name: &str, cmd: &str) -> String {
    let p = tmp(name);
    std::fs::write(&p, img).unwrap();
    let out = Command::new("debugfs").args(["-R", cmd]).arg(&p).output().expect("debugfs installed");
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn fresh(mb: usize) -> Mem {
    let mut dev = Mem(vec![0; mb << 20]);
    format(&mut dev, &FormatOptions { label: "fastros", uuid: [7; 16], now: clock(), bytes_per_inode: 16384 }).unwrap();
    dev
}

#[test]
fn mkfs_output_is_clean() {
    for mb in [1, 64, 200, 300] {
        let dev = fresh(mb);
        fsck(&dev.0, &format!("mkfs-{mb}.img"));
    }
}

#[test]
fn files_directories_links_survive_fsck() {
    let dev = fresh(64);
    let mut fs = Ext2::open(dev, clock).unwrap();
    let etc = fs.mkdir(ROOT_INO, "etc", 0o755, 0, 0).unwrap();
    let f = fs.create(etc, "hostname", S_IFREG | 0o644, 0, 0, 0).unwrap();
    fs.write(f, 0, b"fastros\n").unwrap();
    // A file big enough to need single and double indirect blocks.
    let big = fs.create(ROOT_INO, "big.bin", S_IFREG | 0o600, 1000, 1000, 0).unwrap();
    let data: Vec<u8> = (0..(5 << 20)).map(|i: u32| (i % 251) as u8).collect();
    assert_eq!(fs.write(big, 0, &data).unwrap(), data.len());
    let mut back = vec![0u8; data.len()];
    assert_eq!(fs.read(big, 0, &mut back).unwrap(), data.len());
    assert!(back == data);
    // Sparse write far out.
    let sparse = fs.create(ROOT_INO, "sparse", S_IFREG | 0o644, 0, 0, 0).unwrap();
    fs.write(sparse, 50 << 20, b"end").unwrap();
    let mut z = [1u8; 16];
    fs.read(sparse, 1 << 20, &mut z).unwrap();
    assert_eq!(z, [0u8; 16]);
    // Many entries → directory grows past one block.
    let many = fs.mkdir(ROOT_INO, "many", 0o755, 0, 0).unwrap();
    for i in 0..400 {
        fs.create(many, &format!("file-with-a-fairly-long-name-{i:04}"), S_IFREG | 0o644, 0, 0, 0).unwrap();
    }
    for i in (0..400).step_by(3) {
        fs.unlink(many, &format!("file-with-a-fairly-long-name-{i:04}"), false).unwrap();
    }
    fs.symlink(ROOT_INO, "short", "etc/hostname", 0, 0).unwrap();
    let long_target = "x/".repeat(60);
    fs.symlink(ROOT_INO, "long", &long_target, 0, 0).unwrap();
    let long_ino = fs.lookup(ROOT_INO, "long").unwrap();
    assert_eq!(fs.readlink(long_ino).unwrap(), long_target);
    fs.link(ROOT_INO, "hostname.hard", f).unwrap();
    let sub = fs.mkdir(etc, "sub", 0o700, 0, 0).unwrap();
    fs.rename(etc, "sub", ROOT_INO, "moved").unwrap();
    assert_eq!(fs.lookup(ROOT_INO, "moved").unwrap(), sub);
    fs.set_attr(big, &Attr { size: Some(123_456), ..Default::default() }).unwrap();
    fs.set_attr(big, &Attr { size: Some(10 << 20), ..Default::default() }).unwrap();
    let mut tail = [9u8; 64];
    fs.read(big, 123_456, &mut tail).unwrap();
    assert_eq!(tail, [0u8; 64], "extended region must read as zeros");
    fs.unmount().unwrap();
    let img = std::mem::replace(&mut fs.device().0, Vec::new());
    fsck(&img, "ops.img");
    assert_eq!(debugfs(&img, "ops-cat.img", "cat /etc/hostname"), "fastros\n");
    let ls = debugfs(&img, "ops-ls.img", "ls -l /");
    assert!(ls.contains("moved") && ls.contains("hostname.hard") && ls.contains("big.bin"), "{ls}");
}

#[test]
fn delete_everything_returns_all_space() {
    let dev = fresh(32);
    let mut fs = Ext2::open(dev, clock).unwrap();
    let before = fs.stats();
    let d = fs.mkdir(ROOT_INO, "d", 0o755, 0, 0).unwrap();
    for i in 0..50 {
        let f = fs.create(d, &format!("f{i}"), S_IFREG | 0o644, 0, 0, 0).unwrap();
        fs.write(f, 0, &vec![i as u8; 70_000]).unwrap();
    }
    for i in 0..50 {
        fs.unlink(d, &format!("f{i}"), false).unwrap();
    }
    fs.rmdir(ROOT_INO, "d").unwrap();
    let after = fs.stats();
    assert_eq!(before.free_blocks, after.free_blocks);
    assert_eq!(before.free_inodes, after.free_inodes);
    fs.unmount().unwrap();
    let img = std::mem::replace(&mut fs.device().0, Vec::new());
    fsck(&img, "empty.img");
}

#[test]
fn rename_over_and_errors() {
    let dev = fresh(16);
    let mut fs = Ext2::open(dev, clock).unwrap();
    let a = fs.create(ROOT_INO, "a", S_IFREG | 0o644, 0, 0, 0).unwrap();
    let _b = fs.create(ROOT_INO, "b", S_IFREG | 0o644, 0, 0, 0).unwrap();
    fs.rename(ROOT_INO, "a", ROOT_INO, "b").unwrap();
    assert_eq!(fs.lookup(ROOT_INO, "b").unwrap(), a);
    assert_eq!(fs.lookup(ROOT_INO, "a"), Err(Error::NotFound));
    let d = fs.mkdir(ROOT_INO, "d", 0o755, 0, 0).unwrap();
    fs.create(d, "x", S_IFREG | 0o644, 0, 0, 0).unwrap();
    assert_eq!(fs.rmdir(ROOT_INO, "d"), Err(Error::NotEmpty));
    assert_eq!(fs.create(ROOT_INO, "b", S_IFREG, 0, 0, 0), Err(Error::Exists));
    assert_eq!(fs.rename(ROOT_INO, "b", ROOT_INO, "d"), Err(Error::IsDir));
    fs.unmount().unwrap();
    let img = std::mem::replace(&mut fs.device().0, Vec::new());
    fsck(&img, "rename.img");
}

#[test]
fn works_on_mke2fs_images() {
    let p = tmp("mke2fs.img");
    std::fs::write(&p, vec![0u8; 48 << 20]).unwrap();
    let st = Command::new("mke2fs")
        .args(["-q", "-F", "-t", "ext2", "-b", "4096", "-O", "^resize_inode,^dir_index,^ext_attr", "-L", "linux"])
        .arg(&p)
        .status()
        .expect("mke2fs installed");
    assert!(st.success());
    let dev = Mem(std::fs::read(&p).unwrap());
    let mut fs = Ext2::open(dev, clock).unwrap();
    assert_eq!(fs.label(), "linux");
    assert!(fs.readdir(ROOT_INO).unwrap().iter().any(|e| e.name == "lost+found"));
    let f = fs.create(ROOT_INO, "hello.txt", S_IFREG | 0o644, 0, 0, 0).unwrap();
    fs.write(f, 0, b"hello from fastros\n").unwrap();
    let d = fs.mkdir(ROOT_INO, "dir", 0o755, 0, 0).unwrap();
    for i in 0..100 {
        let g = fs.create(d, &format!("n{i}"), S_IFREG | 0o644, 0, 0, 0).unwrap();
        fs.write(g, 0, &vec![b'z'; 9000]).unwrap();
    }
    fs.unmount().unwrap();
    let img = std::mem::replace(&mut fs.device().0, Vec::new());
    fsck(&img, "mke2fs-after.img");
    assert_eq!(debugfs(&img, "mke2fs-cat.img", "cat /hello.txt"), "hello from fastros\n");
}
