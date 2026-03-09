# ── Build Stage ──────────────────────────────────────────────
FROM rust:1.82-slim-bookworm AS builder

# Tools required for eBPF compilation
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    pkg-config \
    linux-headers-generic \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Add eBPF target and rust-src component (required by aya-build)
RUN rustup target add bpfel-unknown-none
RUN rustup component add rust-src

WORKDIR /build
COPY . .

# 1. Compile eBPF kernel program (no_std, BPF target)
RUN cargo build -p vectorguard-ebpf --target bpfel-unknown-none --release \
    -Z build-std=core

# 2. Compile userspace daemon (normal Linux target)
#    build.rs picks up the eBPF binary from OUT_DIR automatically
RUN cargo build -p vectorguard --release

# ── Runtime Image ────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libelf1 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/vectorguard /usr/local/bin/vectorguard

# Default config and rules (overridden by ConfigMap in K8s)
COPY --from=builder /build/vectorguard/config.toml /etc/vectorguard/config.toml
COPY --from=builder /build/rules /etc/vectorguard/rules

ENTRYPOINT ["vectorguard"]
CMD ["--config", "/etc/vectorguard/config.toml"]
