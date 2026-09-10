# FastROS — Architecture

## Design Philosophy

FastROS is a container-native operating system. Containers and orchestration are
not add-ons — they are first-class kernel primitives.

| Linux Problem                          | FastROS Solution                              |
|----------------------------------------|-----------------------------------------------|
| Monolithic — any bug crashes everything | Strict layer isolation via Rust visibility    |
| Containers are userspace hacks         | Namespaces + cgroups are kernel objects       |
| Docker/K8s are separate installs       | Container runtime + orchestrator built into kernel |
| Network mesh requires Cilium/Calico    | Network mesh is a kernel layer               |
| arch code scattered across subsystems  | `arch/` contains ONLY hardware-specific code  |
| No import rules — circular deps        | Enforced import direction (see Layer Rules)   |

---

## Layer Model

```
╔═══════════════════════════════════════════════════════════════════════╗
║  LAYER 7 — orchestrator/    Node agent, scheduler, health, netmesh   ║
╠═══════════════════════════════════════════════════════════════════════╣
║  LAYER 6 — container/       Image format, runtime, overlay FS        ║
╠═══════════════════════════════════════════════════════════════════════╣
║  LAYER 5 — userspace/       Shell, init, user programs               ║
╠═══════════════════════════════════════════════════════════════════════╣
║  LAYER 4 — fs/              VFS + fat32, ext2, tmpfs, overlayfs      ║
╠═══════════════════════════════════════════════════════════════════════╣
║  LAYER 3 — drivers/         Hardware drivers (serial, vga, ata, e1000)║
╠═══════════════════════════════════════════════════════════════════════╣
║  LAYER 2 — kernel/          memory, process, namespace, cgroup,      ║
║                             sync, ipc, syscall                       ║
╠═══════════════════════════════════════════════════════════════════════╣
║  LAYER 1 — hal/             Hardware Abstraction Layer (traits)       ║
╠═══════════════════════════════════════════════════════════════════════╣
║  LAYER 0 — arch/            x86_64: cpu, paging, interrupts, io      ║
╚═══════════════════════════════════════════════════════════════════════╝

        libs/  ──────────────────────► (any layer can use)
```

### Import Rules (STRICTLY ENFORCED)

```
arch/         → imports: nothing
hal/          → imports: arch/ only
kernel/       → imports: hal/, libs/
drivers/      → imports: hal/, kernel/, libs/
fs/           → imports: kernel/, drivers/block, libs/
container/    → imports: kernel/, fs/, drivers/, hal/, libs/
orchestrator/ → imports: container/, kernel/, drivers/, hal/, libs/
userspace/    → imports: syscall interface only
libs/         → imports: nothing (pure no_std utilities)
```

**VIOLATION = compile error** — Rust `pub(super)` and `pub(crate)` enforce this.

---

## Full Directory Structure

```
fastros/
│
├── docs/
│   ├── ARCHITECTURE.md         ← YOU ARE HERE
│   ├── MEMORY_MAP.md
│   ├── SYSCALL_TABLE.md
│   └── DRIVER_GUIDE.md
│
├── arch/                       # [NON-RUST] Assembly & linker files
│   └── x86_64/
│       └── boot.s              # Multiboot2, long mode, page tables
│
├── src/
│   ├── main.rs                 # kernel_main() — boot sequence orchestrator
│   │
│   ├── arch/                   # LAYER 0: x86_64 hardware-specific Rust
│   │   └── x86_64/
│   │       ├── boot/           # GDT, early boot
│   │       ├── cpu/            # cpuid, msr
│   │       ├── memory/         # paging (PML4/PDP/PD/PT)
│   │       ├── interrupts/     # IDT, PIC, APIC
│   │       └── io/             # in/out port instructions
│   │
│   ├── hal/                    # LAYER 1: Hardware Abstraction Layer
│   │   ├── cpu.rs              # trait CpuInterface
│   │   ├── memory.rs           # trait MemoryInterface
│   │   ├── interrupt.rs        # trait InterruptController
│   │   └── io.rs               # trait IoInterface
│   │
│   ├── kernel/                 # LAYER 2: Core kernel (arch-independent)
│   │   ├── memory/
│   │   │   ├── pmm/            # Physical Memory Manager (bitmap)
│   │   │   ├── vmm/            # Virtual Memory Manager (address spaces)
│   │   │   └── heap/           # Kernel heap (slab/buddy)
│   │   ├── process/
│   │   │   ├── process.rs      # Process struct & lifecycle
│   │   │   ├── thread.rs       # Thread struct & state
│   │   │   └── scheduler/      # trait Scheduler + round-robin impl
│   │   ├── namespace/          # CONTAINER ISOLATION — kernel namespaces
│   │   │   ├── pid.rs          # PID namespace (each container has PID 1)
│   │   │   ├── mnt.rs          # Mount namespace (per-container FS tree)
│   │   │   ├── net.rs          # Network namespace (per-container net stack)
│   │   │   └── user.rs         # User namespace (UID/GID mapping)
│   │   ├── cgroup/             # CONTAINER ISOLATION — resource limits
│   │   │   ├── cpu.rs          # CPU quota (% of core)
│   │   │   └── memory.rs       # Memory limit + OOM killer
│   │   ├── syscall/
│   │   │   ├── handler.rs      # Syscall dispatch table
│   │   │   └── numbers.rs      # Syscall number constants
│   │   ├── ipc/
│   │   │   ├── pipe.rs         # Anonymous pipes
│   │   │   ├── signal.rs       # UNIX signals
│   │   │   └── shm.rs          # Shared memory
│   │   └── sync/
│   │       ├── spinlock.rs     # Spin lock
│   │       ├── mutex.rs        # Sleeping mutex
│   │       └── semaphore.rs    # Counting semaphore
│   │
│   ├── drivers/                # LAYER 3: Hardware drivers
│   │   ├── interface.rs        # trait Driver, CharDevice, BlockDevice, NetDevice
│   │   ├── bus/pci/            # PCI bus enumeration
│   │   ├── char/               # serial (UART), keyboard (PS/2), tty
│   │   ├── block/              # ATA/IDE, NVMe
│   │   ├── display/            # VGA text mode, framebuffer
│   │   └── net/                # Intel E1000 (QEMU NIC)
│   │
│   ├── fs/                     # LAYER 4: File systems
│   │   ├── vfs/                # VFS — inode, dentry, mount table
│   │   ├── fat32/              # FAT32
│   │   ├── ext2/               # ext2
│   │   ├── tmpfs/              # RAM-backed tmpfs
│   │   └── overlayfs/          # CONTAINER FS — union layers (CoW)
│   │
│   ├── container/              # LAYER 6: Built-in Container Runtime
│   │   ├── image/              # FastROS native image format (not OCI)
│   │   ├── runtime/            # Container lifecycle (create/start/stop/delete)
│   │   └── overlay/            # Overlay FS integration for container root FS
│   │
│   ├── orchestrator/           # LAYER 7: Built-in Orchestration
│   │   ├── agent/              # Node agent (resource reporting, heartbeat)
│   │   ├── scheduler/          # Container placement (bin-packing)
│   │   ├── health/             # Liveness/readiness checks, self-healing
│   │   ├── discovery/          # Service registry (replaces DNS/etcd)
│   │   └── netmesh/            # Network mesh (replaces Cilium/Calico)
│   │       ├── veth.rs         # Virtual ethernet pairs
│   │       ├── vxlan.rs        # Cross-node tunneling
│   │       └── policy.rs       # Network policies (allow/deny rules)
│   │
│   ├── userspace/              # LAYER 5: User space programs
│   │   ├── init/               # PID 1
│   │   └── shell/              # Interactive shell
│   │
│   └── libs/                   # LAYER *: Pure no_std utilities
│       ├── collections/        # list, bitmap, ring_buffer
│       └── fmt/                # no_std write! formatting
│
├── .cargo/config.toml          # Build target & linker config
├── arch/x86_64/boot.s          # Assembly entry (Multiboot2)
├── build.rs                    # Runs nasm, passes boot.o to linker
├── Cargo.toml
├── linker.ld                   # Kernel linker script
├── Makefile                    # Build & run shortcuts
└── rust-toolchain.toml         # Nightly + x86_64-unknown-none
```

---

## Container Isolation Stack

A FastROS container is a kernel object, not a userspace wrapper:

```
Container {
    id:     ContainerId,        // 128-bit random ID
    ns:     NsSet {             // kernel/namespace/
                pid,            //   own PID space (PID 1 inside)
                mnt,            //   own filesystem tree (overlayfs root)
                net,            //   own network stack (veth pair)
                user,           //   own UID/GID mapping
            },
    cgroup: Cgroup {            // kernel/cgroup/
                cpu_quota,      //   max CPU %
                mem_limit,      //   max RAM bytes (OOM kill on exceed)
            },
    image:  ImageRef,           // container/image/
    rootfs: OverlayMount,       // fs/overlayfs/ (upper=writable, lower=image)
}
```

## Network Mesh Stack

```
Container A (net ns A)               Container B (net ns B)
      |                                      |
   veth0 (container end)              veth0 (container end)
      |                                      |
   veth1 (host end) ─── bridge ─── veth1 (host end)
                           |
                       VXLAN tunnel (if cross-node)
                           |
                      Remote node bridge
```

---

## Naming Conventions

| File name       | Purpose                                       |
|-----------------|-----------------------------------------------|
| `mod.rs`        | Module root — declares submodules, re-exports |
| `interface.rs`  | Trait definitions                             |
| `types.rs`      | Struct/enum only (no logic)                   |
| `<name>.rs`     | One specific implementation                   |

---

## Memory Map (x86_64)

```
0x0000_0000_0000_0000 — 0x0000_7FFF_FFFF_FFFF  User space (128 TB)
0xFFFF_8000_0000_0000 — 0xFFFF_8000_3FFF_FFFF  Physical memory direct map (1 GB)
0xFFFF_C000_0000_0000 — 0xFFFF_CFFF_FFFF_FFFF  Kernel heap
0xFFFF_FFFF_8000_0000 — 0xFFFF_FFFF_FFFF_FFFF  Kernel code & data
```

---

## Adding a New Feature

### New Driver
1. Create `src/drivers/<category>/<name>/mod.rs`
2. Implement `drivers::interface::Driver` trait
3. Use only `hal::` and `kernel::` — never `arch::` directly

### New File System
1. Create `src/fs/<name>/mod.rs`
2. Implement `fs::vfs::inode::Inode` and `fs::vfs::mount::FileSystem` traits
3. Register in `src/fs/mod.rs`

### New Syscall
1. Add constant to `src/kernel/syscall/numbers.rs`
2. Add handler in `src/kernel/syscall/handler.rs`
3. Document in `docs/SYSCALL_TABLE.md`

### New Architecture (e.g., aarch64)
1. Create `src/arch/aarch64/` mirroring `x86_64/` structure
2. Implement all `hal/` traits for new arch
3. Add `arch/aarch64/boot.s`
4. Zero changes to `kernel/`, `container/`, `orchestrator/` — that's the point
