# FastROS

A container-native operating system written in Rust from scratch — see
[VISION.md](VISION.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Run it

The only requirement is Docker (Linux, macOS or Windows; amd64 or arm64).
The kernel is compiled and booted in QEMU inside the container — nothing is
installed on the host.

```sh
docker compose up -d --build      # build + boot
ssh root@localhost -p 2323        # the FastROS shell — password: root
docker compose down               # power off
```

The guest has an e1000 NIC on QEMU user networking (10.0.2.15, gateway
10.0.2.2) and its SSH server on port 22 is published as host port 2323.
Try `ping 10.0.2.2`, `ifconfig`, `netstat -r`, `htop`.

The only thing written on the host is `./disk/data.img`, the guest's
persistent disk: files created in the shell survive reboots and rebuilds.
Delete the `disk` folder to start from a blank disk.

| | |
|---|---|
| `docker compose logs -f` | serial console / kernel log, including the boot messages |
| `docker run --rm fastros test` | boot smoke test: logs in over SSH and checks the answer |
| `docker build --target kernel --output out .` | just the kernel ELF, as `out/fastros` |

`make help` lists the same commands as shortcuts.

### Settings

Environment variables, read by `docker compose` — put them in a `.env` file
next to `docker-compose.yml` to make them stick:

| Variable | Default | |
|---|---|---|
| `FASTROS_PORT` | `2323` | host port for SSH |
| `FASTROS_BIND` | `127.0.0.1` | host address; `0.0.0.0` makes it reachable from the network (the root password is `root`) |
| `FASTROS_RESTART` | `no` | `unless-stopped` brings it back after a host reboot |
| `FASTROS_MEM` | `256M` | guest RAM |
| `FASTROS_ACCEL` | `auto` | `kvm`, `tcg`, or `auto` (KVM when usable) |

QEMU emulates the CPU in software (TCG) by default, which works everywhere.
On a Linux x86_64 host, KVM can be used by passing the device in:
`docker run --device /dev/kvm ...` (`make test` does this when `/dev/kvm` exists).

### Building without Docker

`cargo build` works on any OS with `rustup` (it picks the toolchain from
`rust-toolchain.toml`) and NASM on `PATH` — or point `NASM=/path/to/nasm` at it.
The kernel is `target/x86_64-unknown-none/debug/fastros`.
