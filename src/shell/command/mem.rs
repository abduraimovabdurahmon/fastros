//! `mem` — show physical memory statistics from the PMM.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;

pub struct MemCommand;
pub static MEM: MemCommand = MemCommand;

impl Command for MemCommand {
    fn name(&self) -> &'static str { "mem" }
    fn description(&self) -> &'static str { "Show physical memory statistics" }

    fn execute(&self, _args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let free  = crate::kernel::memory::pmm::free_frame_count();
        let total = crate::kernel::memory::pmm::total_frame_count();
        let used  = total.saturating_sub(free);

        let free_mb  = (free  * 4096) / (1024 * 1024);
        let used_mb  = (used  * 4096) / (1024 * 1024);
        let total_mb = (total * 4096) / (1024 * 1024);

        io.write_bytes(b"Physical memory (4 KB frames):\n");

        io.write_bytes(b"  Total : ");
        io.write_u64(total as u64);
        io.write_bytes(b" frames  (");
        io.write_u64(total_mb as u64);
        io.write_bytes(b" MB)\n");

        io.write_bytes(b"  Used  : ");
        io.write_u64(used as u64);
        io.write_bytes(b" frames  (");
        io.write_u64(used_mb as u64);
        io.write_bytes(b" MB)\n");

        io.write_bytes(b"  Free  : ");
        io.write_u64(free as u64);
        io.write_bytes(b" frames  (");
        io.write_u64(free_mb as u64);
        io.write_bytes(b" MB)\n");
        0
    }
}
