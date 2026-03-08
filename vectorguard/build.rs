fn main() {
    // eBPF compilation only makes sense when building for Linux
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
