# syntax=docker/dockerfile:1
#
# FastROS in a container: build the kernel and boot it in QEMU.
# Needs nothing on the host but Docker (Linux, macOS, Windows; amd64 or arm64).
#
#   docker build -t fastros .
#   docker run --rm -d --name fastros -p 127.0.0.1:2323:22 -v "$PWD/disk:/var/lib/fastros" fastros
#   ssh root@localhost -p 2323                       # password: root
#   docker run --rm fastros test                     # boot + SSH login smoke test
#
# Kernel binary only:
#   docker build --target kernel --output out .      # -> out/fastros

ARG DEBIAN_IMAGE=debian:trixie-slim

# ── Toolchain: nasm + the Rust named in rust-toolchain.toml ─────────────────
FROM ${DEBIAN_IMAGE} AS toolchain
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gcc libc6-dev nasm \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal --default-toolchain none

WORKDIR /src
# Only the toolchain file, so this layer survives source edits.
COPY rust-toolchain.toml ./
RUN rustup toolchain install && rustc --version

# ── Build ────────────────────────────────────────────────────────────────────
FROM toolchain AS build
# debug | release
ARG PROFILE=debug
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    if [ "$PROFILE" = release ]; then cargo build --release; else cargo build; fi \
 && install -D "target/x86_64-unknown-none/$PROFILE/fastros" /out/fastros

# ── Kernel artifact only (used with --output) ────────────────────────────────
FROM scratch AS kernel
COPY --from=build /out/fastros /fastros

# ── Runtime: QEMU (default target) ───────────────────────────────────────────
FROM ${DEBIAN_IMAGE} AS runtime
ARG DEBIAN_FRONTEND=noninteractive
# openssh-client + sshpass: only for the `test` mode's SSH login.
RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-system-x86 openssh-client sshpass \
 && rm -rf /var/lib/apt/lists/*

ENV FASTROS_KERNEL=/opt/fastros/fastros \
    FASTROS_DISK=/var/lib/fastros/data.img \
    FASTROS_MEM=256M \
    FASTROS_ACCEL=auto

COPY --from=build /out/fastros /opt/fastros/fastros
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/fastros-run

# Guest SSH server, forwarded by QEMU user networking.
EXPOSE 22
ENTRYPOINT ["fastros-run"]
CMD ["run"]
