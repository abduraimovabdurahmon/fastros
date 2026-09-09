# FastROS — Architecture

## Design Philosophy

FastROS is designed to solve the core architectural failures of Linux:

| Linux Problem                          | FastROS Solution                              |
|----------------------------------------|-----------------------------------------------|
| Monolithic — any bug crashes everything | Strict layer isolation via Rust visibility    |
| Global locks (BKL) — SMP bottleneck   | Per-subsystem state, no global mutable singletons |
| arch code scattered across subsystems  | `arch/` contains ONLY hardware-specific code  |
| No import rules — circular deps        | Enforced import direction (see Layer Rules)   |
| Drivers call kernel internals directly | Drivers use HAL traits only                   |
| No clear "who owns what"               | Every directory has one owner and one purpose |

---

## Layer Model

```
╔═══════════════════════════════════════════════════════════╗
║  LAYER 5 — userspace/          User programs, shell, init ║
╠═══════════════════════════════════════════════════════════╣
║  LAYER 4 — fs/                 File system implementations ║
╠═══════════════════════════════════════════════════════════╣
║  LAYER 3 — drivers/            Hardware drivers            ║
╠═══════════════════════════════════════════════════════════╣
║  LAYER 2 — kernel/             Core: memory, process, IPC  ║
╠═══════════════════════════════════════════════════════════╣
║  LAYER 1 — hal/                Hardware Abstraction Layer   ║
╠═══════════════════════════════════════════════════════════╣
║  LAYER 0 — arch/               CPU, paging, interrupts      ║
╚═══════════════════════════════════════════════════════════╝

        libs/  ──────────────────────► (any layer can use)
```

### Import Rules (STRICTLY ENFORCED)

```
arch/       → imports: nothing (no other layers)
hal/        → imports: arch/ only
kernel/     → imports: hal/, libs/
drivers/    → imports: hal/, kernel/, libs/
fs/         → imports: kernel/, drivers/block, libs/
userspace/  → imports: syscall interface only (no kernel internals)
libs/       → imports: nothing (pure no_std utilities)
```

**VIOLATION = compile error** — Rust `pub(super)` and `pub(crate)` enforce this.
Every internal symbol that should not cross a boundary is `pub(super)` or private.

---

## Full Directory Structure

```
fastros/
│
├── docs/                           # Architecture & decisions
│   ├── ARCHITECTURE.md             ← YOU ARE HERE
│   ├── MEMORY_MAP.md               # Physical & virtual memory layout
│   ├── SYSCALL_TABLE.md            # All syscall numbers and signatures
│   └── DRIVER_GUIDE.md            # How to write a new driver
│
├── arch/                           # [NON-RUST] Assembly & linker files
│   └── x86_64/
│       └── boot.s                  # Multiboot2, long mode, page tables
│
├── src/                            # [RUST] All Rust source code
│   ├── main.rs                     # kernel_main() — orchestrates boot sequence
│   │
│   ├── arch/                       # LAYER 0: Hardware-specific Rust code
│   │   └── x86_64/
│   │       ├── mod.rs
│   │       ├── boot/
│   │       │   ├── mod.rs          # GDT setup, early boot
│   │       │   └── gdt.rs          # Global Descriptor Table
│   │       ├── cpu/
│   │       │   ├── mod.rs
│   │       │   ├── cpuid.rs        # CPU feature detection
│   │       │   └── msr.rs          # Model Specific Registers
│   │       ├── memory/
│   │       │   ├── mod.rs
│   │       │   └── paging.rs       # PML4/PDP/PD/PT manipulation
│   │       ├── interrupts/
│   │       │   ├── mod.rs
│   │       │   ├── idt.rs          # Interrupt Descriptor Table
│   │       │   ├── pic.rs          # Legacy 8259 PIC
│   │       │   └── apic.rs         # Advanced PIC (LAPIC/IOAPIC)
│   │       └── io/
│   │           └── mod.rs          # in/out port instructions
│   │
│   ├── hal/                        # LAYER 1: Hardware Abstraction Layer
│   │   ├── mod.rs                  # Re-exports all traits
│   │   ├── cpu.rs                  # trait CpuInterface
│   │   ├── memory.rs               # trait MemoryInterface
│   │   ├── interrupt.rs            # trait InterruptController
│   │   └── io.rs                   # trait IoInterface
│   │
│   ├── kernel/                     # LAYER 2: Core kernel (arch-independent)
│   │   ├── mod.rs
│   │   ├── memory/
│   │   │   ├── mod.rs
│   │   │   ├── pmm/
│   │   │   │   ├── mod.rs          # Physical Memory Manager
│   │   │   │   └── bitmap.rs       # Bitmap frame allocator
│   │   │   ├── vmm/
│   │   │   │   ├── mod.rs          # Virtual Memory Manager
│   │   │   │   └── address_space.rs # Per-process address spaces
│   │   │   └── heap/
│   │   │       └── mod.rs          # Kernel heap (slab/buddy)
│   │   ├── process/
│   │   │   ├── mod.rs
│   │   │   ├── process.rs          # Process struct & lifecycle
│   │   │   ├── thread.rs           # Thread struct & state
│   │   │   └── scheduler/
│   │   │       ├── mod.rs          # trait Scheduler
│   │   │       └── round_robin.rs  # RR implementation
│   │   ├── syscall/
│   │   │   ├── mod.rs
│   │   │   ├── handler.rs          # Syscall dispatch table
│   │   │   └── numbers.rs          # Syscall number constants
│   │   ├── ipc/
│   │   │   ├── mod.rs
│   │   │   ├── pipe.rs             # Anonymous pipes
│   │   │   ├── signal.rs           # UNIX-like signals
│   │   │   └── shm.rs              # Shared memory regions
│   │   └── sync/
│   │       ├── mod.rs
│   │       ├── spinlock.rs         # Spin lock (no sleeping)
│   │       ├── mutex.rs            # Sleeping mutex
│   │       └── semaphore.rs        # Counting semaphore
│   │
│   ├── drivers/                    # LAYER 3: Hardware drivers
│   │   ├── mod.rs
│   │   ├── interface.rs            # trait Driver (all drivers implement)
│   │   ├── bus/
│   │   │   ├── mod.rs
│   │   │   └── pci/
│   │   │       ├── mod.rs          # PCI bus enumeration
│   │   │       └── config.rs       # PCI config space read/write
│   │   ├── char/                   # Character devices (stream I/O)
│   │   │   ├── mod.rs
│   │   │   ├── serial/
│   │   │   │   └── mod.rs          # UART 16550 (COM1-4)
│   │   │   ├── keyboard/
│   │   │   │   └── mod.rs          # PS/2 keyboard (IRQ1)
│   │   │   └── tty/
│   │   │       └── mod.rs          # TTY abstraction layer
│   │   ├── block/                  # Block devices (sector I/O)
│   │   │   ├── mod.rs
│   │   │   ├── ata/
│   │   │   │   └── mod.rs          # ATA/IDE (PIO & DMA)
│   │   │   └── nvme/
│   │   │       └── mod.rs          # NVMe over PCIe
│   │   ├── display/                # Video output
│   │   │   ├── mod.rs
│   │   │   ├── vga/
│   │   │   │   └── mod.rs          # VGA text mode (80x25)
│   │   │   └── framebuffer/
│   │   │       └── mod.rs          # Linear framebuffer (VESA/GOP)
│   │   └── net/                    # Network interface cards
│   │       ├── mod.rs
│   │       └── e1000/
│   │           └── mod.rs          # Intel E1000 / 82540EM (QEMU)
│   │
│   ├── fs/                         # LAYER 4: File systems
│   │   ├── mod.rs
│   │   ├── vfs/                    # Virtual FS — abstraction over all FSes
│   │   │   ├── mod.rs
│   │   │   ├── inode.rs            # trait Inode
│   │   │   ├── dentry.rs           # Directory entry cache
│   │   │   └── mount.rs            # Mount table
│   │   ├── fat32/
│   │   │   └── mod.rs              # FAT32 implementation
│   │   ├── ext2/
│   │   │   └── mod.rs              # ext2 implementation
│   │   └── tmpfs/
│   │       └── mod.rs              # RAM-backed tmpfs
│   │
│   └── libs/                       # LAYER *: Pure no_std utilities
│       ├── mod.rs
│       ├── collections/
│       │   ├── mod.rs
│       │   ├── list.rs             # Intrusive linked list
│       │   ├── bitmap.rs           # Bit array
│       │   └── ring_buffer.rs      # Fixed-size ring buffer
│       └── fmt/
│           └── mod.rs              # no_std write! formatting
│
├── userspace/                      # LAYER 5: User space programs
│   ├── init/
│   │   └── main.rs                 # PID 1 — system init
│   └── shell/
│       └── main.rs                 # Interactive shell
│
├── .cargo/
│   └── config.toml                 # Build target & linker config
├── arch/x86_64/boot.s              # Assembly entry (Multiboot2)
├── build.rs                        # Runs nasm, passes boot.o to linker
├── Cargo.toml
├── Dockerfile                      # Build environment
├── linker.ld                       # Kernel linker script
├── Makefile                        # Build & run shortcuts
└── rust-toolchain.toml             # Nightly + x86_64-unknown-none
```

---

## Naming Conventions

| File name       | Purpose                                      |
|-----------------|----------------------------------------------|
| `mod.rs`        | Module root — declares submodules, re-exports public API |
| `interface.rs`  | Trait definitions (the "contract" of the module) |
| `types.rs`      | Struct/enum definitions with no logic        |
| `<name>.rs`     | Implementation of one specific thing         |

---

## Adding a New Feature

### New Driver
1. Create `src/drivers/<category>/<name>/mod.rs`
2. Implement `drivers::interface::Driver` trait
3. Use only `hal::` and `kernel::` — never `arch::` directly
4. Register in `src/drivers/mod.rs`

### New File System
1. Create `src/fs/<name>/mod.rs`
2. Implement `fs::vfs::inode::Inode` and `fs::vfs::mount::FileSystem` traits
3. Register in `src/fs/mod.rs`

### New Syscall
1. Add constant to `src/kernel/syscall/numbers.rs`
2. Add handler function in `src/kernel/syscall/handler.rs`
3. Document in `docs/SYSCALL_TABLE.md`

### New Architecture (e.g., aarch64)
1. Create `src/arch/aarch64/` mirroring `x86_64/` structure
2. Implement all `hal/` traits for new arch
3. Add `arch/aarch64/boot.s`
4. Zero changes to `kernel/`, `drivers/`, `fs/` — that's the point

---

## Memory Map (x86_64)

```
0x0000_0000_0000_0000 — 0x0000_7FFF_FFFF_FFFF  User space (128 TB)
0xFFFF_8000_0000_0000 — 0xFFFF_8000_3FFF_FFFF  Physical memory direct map (1 GB)
0xFFFF_C000_0000_0000 — 0xFFFF_CFFF_FFFF_FFFF  Kernel heap
0xFFFF_FFFF_8000_0000 — 0xFFFF_FFFF_FFFF_FFFF  Kernel code & data
```
