# ── Build Stage ──────────────────────────────────────────────
FROM rust:latest AS builder

# Tools required for eBPF compilation
RUN apt-get update && apt-get install -y \
    clang llvm libelf-dev pkg-config \
    linux-headers-generic \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Nightly toolchain + rust-src for eBPF (-Z build-std=core).
# bpfel-unknown-none has no prebuilt rust-std, so we compile from source.
# rustup target add is NOT needed (and will fail); just rust-src is enough.
RUN rustup toolchain install nightly --component rust-src --no-self-update

# bpf-linker: LLVM-based linker required for bpfel-unknown-none target
RUN cargo install --locked bpf-linker

WORKDIR /build

# ── Cache dependencies ────────────────────────────────────────
COPY Cargo.toml Cargo.lock ./
COPY vectorguard-common/Cargo.toml ./vectorguard-common/
COPY vectorguard-ebpf/Cargo.toml   ./vectorguard-ebpf/
COPY vectorguard-ebpf/.cargo       ./vectorguard-ebpf/.cargo/
COPY vectorguard/Cargo.toml        ./vectorguard/
COPY vectorguard/build.rs          ./vectorguard/
COPY vectorguard/proto              ./vectorguard/proto/

# Stub sources so cargo can resolve deps without the full source tree
RUN mkdir -p vectorguard-common/src vectorguard-ebpf/src vectorguard/src && \
    echo "pub fn stub(){}" > vectorguard-common/src/lib.rs && \
    printf '#![no_std]\n#![no_main]\n#[panic_handler]\nfn p(_:&core::panic::PanicInfo)->!{loop{}}\n' \
      > vectorguard-ebpf/src/main.rs && \
    echo "fn main(){}" > vectorguard/src/main.rs

RUN cargo fetch
# Pre-build userspace dependencies (cached layer; ignores build.rs since eBPF isn't built yet)
RUN CARGO_CFG_TARGET_OS=linux cargo build -p vectorguard --release 2>/dev/null || true

# ── Build actual source ────────────────────────────────────────
COPY . .

# 1. Compile eBPF kernel program (nightly, no_std, BPF target).
#    The result lands at target/bpfel-unknown-none/release/vectorguard-ebpf.
#    build.rs copies it to OUT_DIR for include_bytes! embedding.
RUN cargo +nightly build -p vectorguard-ebpf \
    --target bpfel-unknown-none --release -Z build-std=core

# 2. Compile userspace daemon. build.rs copies the pre-built eBPF binary
#    from target/bpfel-unknown-none/release/ into OUT_DIR.
RUN cargo build -p vectorguard --release

# ── Runtime Image ────────────────────────────────────────────
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y libelf1 libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/vectorguard /usr/local/bin/vectorguard
COPY --from=builder /build/vectorguard/config.toml    /etc/vectorguard/config.toml
COPY --from=builder /build/rules                       /etc/vectorguard/rules/

ENTRYPOINT ["vectorguard"]
CMD ["--config", "/etc/vectorguard/config.toml"]
