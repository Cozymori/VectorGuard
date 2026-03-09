use std::{env, path::PathBuf};

fn main() {
    // ── Tetragon protobuf (all platforms) ─────────────────────
    println!("cargo:rerun-if-changed=proto/tetragon.proto");

    tonic_build::configure()
        .build_server(false)
        .compile_protos(&["proto/tetragon.proto"], &["proto"])
        .expect("Failed to compile Tetragon proto");

    // ── eBPF binary embedding (Linux only) ────────────────────
    // The eBPF program is compiled separately (via `cargo +nightly build -p
    // vectorguard-ebpf --target bpfel-unknown-none --release`) before the
    // userspace daemon build runs.  We simply locate the compiled binary and
    // copy it to OUT_DIR so that `include_bytes!(concat!(env!("OUT_DIR"),
    // "/vectorguard-ebpf"))` in collector.rs resolves correctly.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        return;
    }

    println!("cargo:rerun-if-changed=../vectorguard-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../vectorguard-common/src/lib.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap();

    // The eBPF binary is placed here by the separate nightly cargo build step.
    let ebpf_binary = workspace_root
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("vectorguard-ebpf");

    let ebpf_out = out_dir.join("vectorguard-ebpf");

    if !ebpf_binary.exists() {
        panic!(
            "eBPF binary not found at {:?}. \
             Build it first with: cargo +nightly build -p vectorguard-ebpf \
             --target bpfel-unknown-none --release -Z build-std=core",
            ebpf_binary
        );
    }

    std::fs::copy(&ebpf_binary, &ebpf_out).unwrap_or_else(|e| {
        panic!("Failed to copy eBPF binary {:?} → {:?}: {}", ebpf_binary, ebpf_out, e)
    });
}
