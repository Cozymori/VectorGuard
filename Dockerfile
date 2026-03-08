FROM rust:1.82-slim-bookworm AS builder

# eBPF 빌드에 필요한 도구
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    pkg-config \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# bpf 타겟 추가
RUN rustup target add bpfel-unknown-none
RUN rustup component add rust-src

WORKDIR /build
COPY . .

# 1. eBPF 프로그램 빌드 (bpf target)
RUN cargo build -p vectorguard-ebpf --target bpfel-unknown-none --release \
    -Z build-std=core

# 2. userspace 빌드 (일반 Linux target)
RUN cargo build -p vectorguard --release

# ── 실행 이미지 ──────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libelf1 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/vectorguard /usr/local/bin/vectorguard
COPY --from=builder /build/vectorguard/config.toml /etc/vectorguard/config.toml

ENTRYPOINT ["vectorguard"]
