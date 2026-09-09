# FastROS — Vision

FastROS is a container-native operating system written entirely in Rust, from scratch.
No Linux kernel. No external runtime. Everything built into the OS itself.

## Goal

Build an operating system where containers and orchestration are not add-ons —
they are first-class citizens of the kernel itself.

Users install FastROS and get:
- Container runtime (no Docker, no Podman needed)
- Orchestration (no Kubernetes needed)
- Network mesh (no Cilium, no Calico needed)

All of it built into the kernel. All of it written in Rust.

## Why Rust

- Memory safety without GC — container isolation is guaranteed at compile time
- Zero-cost abstractions — no performance penalty for high-level design
- No garbage collector — predictable, low latency for thousands of containers
- Modern tooling — clean codebase, no legacy burden

## Architecture

```
Hardware
   |
FastROS Kernel (Rust, no_std)
   |
Process + Memory + Namespace + Cgroup     <- container isolation layer
   |
Built-in Container Runtime                <- replaces Docker / Podman
   |
Built-in Orchestration Layer              <- replaces Kubernetes
   |
Built-in Network Mesh                     <- replaces Cilium / Calico
   |
User Applications
```

## How it differs from existing solutions

| | Docker + K8s on Linux | Talos / Bottlerocket | FastROS |
|---|---|---|---|
| Kernel | Linux | Linux | Custom (Rust) |
| Container runtime | separate install | built-in | built-in |
| Orchestration | separate install | K8s on top | built-in |
| Language | C (kernel) | C (kernel) | Rust (everything) |
| Overhead | VM layer on macOS | minimal | zero |

## Roadmap

### Stage 1 — Kernel foundation (now)
- [x] Boot in 64-bit long mode
- [x] Serial output
- [ ] VGA text mode driver
- [ ] Keyboard driver
- [ ] Shell

### Stage 2 — Memory and processes
- [ ] Physical memory manager (PMM)
- [ ] Virtual memory manager (VMM)
- [ ] Kernel heap allocator
- [ ] Process scheduler

### Stage 3 — Isolation primitives
- [ ] Namespaces (PID, mount, network, user)
- [ ] Cgroups (CPU, memory limits)
- [ ] Syscall layer

### Stage 4 — Container runtime
- [ ] Image format (FastROS-native, not OCI)
- [ ] Container lifecycle (create, start, stop, delete)
- [ ] Filesystem isolation (overlay FS)

### Stage 5 — Orchestration
- [ ] Node agent
- [ ] Scheduler (place containers across nodes)
- [ ] Health checks and self-healing
- [ ] Service discovery

### Stage 6 — Network
- [ ] Virtual network interfaces
- [ ] Container-to-container networking
- [ ] Load balancing
- [ ] Network policies

### Stage 7 — Polish
- [ ] macOS-level stability and security
- [ ] Developer tooling (FastROS CLI)
- [ ] Documentation
