# FastROS development image: Rust toolchain + NASM + QEMU + test tools.
#
# Everything a development loop needs, so the host needs nothing but Docker:
#   docker build -f docker/dev.Dockerfile -t fastros-dev .
#   tools/dev.sh build | run | test | unit | shell
#
# Build artifacts live in the named volumes fastros-target / fastros-cargo,
# never in the source tree on the host.

ARG DEBIAN_IMAGE=debian:trixie-slim
FROM ${DEBIAN_IMAGE}
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gcc libc6-dev nasm \
      qemu-system-x86 qemu-utils \
      python3 python3-paramiko python3-pytest \
      openssh-client sshpass socat e2fsprogs procps iproute2 netcat-openbsd curl \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal --default-toolchain none

WORKDIR /src
COPY rust-toolchain.toml ./
RUN rustup toolchain install && rustc --version && cargo --version
