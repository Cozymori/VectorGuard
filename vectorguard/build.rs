fn main() {
    // ── Compile Tetragon protobuf (all platforms) ──────────
    println!("cargo:rerun-if-changed=proto/tetragon.proto");

    tonic_build::configure()
        .build_server(false)
        .compile_protos(&["proto/tetragon.proto"], &["proto"])
        .expect("Failed to compile Tetragon proto");

    // ── Compile eBPF (Linux only) ──────────────────────────
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        return;
    }

    println!("cargo:rerun-if-changed=../vectorguard-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../vectorguard-common/src/lib.rs");

    let ebpf_package = aya_build::Package {
        name: "vectorguard-ebpf",
        root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../vectorguard-ebpf"),
        no_default_features: false,
        features: &[],
    };

    aya_build::build_ebpf([ebpf_package], aya_build::Toolchain::default())
        .expect("Failed to build eBPF program");
}
