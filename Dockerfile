FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Build tools + QEMU
RUN apt-get update && apt-get install -y \
    curl \
    nasm \
    binutils \
    qemu-system-x86 \
    && rm -rf /var/lib/apt/lists/*

# Install Rust nightly
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain nightly --profile minimal

ENV PATH="/root/.cargo/bin:${PATH}"

# OS dev components
RUN rustup component add rust-src llvm-tools-preview && \
    rustup target add x86_64-unknown-none

WORKDIR /app
