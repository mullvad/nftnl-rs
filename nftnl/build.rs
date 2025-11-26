fn main() {
    // socket expressions are available starting from libmnl 1.2.0.
    println!("cargo::rustc-check-cfg=cfg(socketexpr)");
    if nftnl_version() >= (1, 2, 0) {
        println!(r#"cargo::rustc-cfg=socketexpr"#);
    };
}

/// Version of `nftnl` for the exported bindings. Major, minor, patch.
const fn nftnl_version() -> (u32, u32, u32) {
    match () {
        _ if cfg!(feature = "nftnl-1-3-0") => (1, 3, 0),
        _ if cfg!(feature = "nftnl-1-2-9") => (1, 2, 9),
        _ if cfg!(feature = "nftnl-1-2-8") => (1, 2, 8),
        _ if cfg!(feature = "nftnl-1-2-7") => (1, 2, 7),
        _ if cfg!(feature = "nftnl-1-2-6") => (1, 2, 6),
        _ if cfg!(feature = "nftnl-1-2-5") => (1, 2, 5),
        _ if cfg!(feature = "nftnl-1-2-4") => (1, 2, 4),
        _ if cfg!(feature = "nftnl-1-2-3") => (1, 2, 3),
        _ if cfg!(feature = "nftnl-1-2-2") => (1, 2, 2),
        _ if cfg!(feature = "nftnl-1-2-1") => (1, 2, 1),
        _ if cfg!(feature = "nftnl-1-2-0") => (1, 2, 0),
        _ if cfg!(feature = "nftnl-1-1-9") => (1, 1, 9),
        _ if cfg!(feature = "nftnl-1-1-8") => (1, 1, 8),
        _ if cfg!(feature = "nftnl-1-1-7") => (1, 1, 7),
        _ if cfg!(feature = "nftnl-1-1-6") => (1, 1, 6),
        _ if cfg!(feature = "nftnl-1-1-5") => (1, 1, 5),
        _ if cfg!(feature = "nftnl-1-1-4") => (1, 1, 4),
        _ if cfg!(feature = "nftnl-1-1-3") => (1, 1, 3),
        _ if cfg!(feature = "nftnl-1-1-2") => (1, 1, 2),
        _ if cfg!(feature = "nftnl-1-1-1") => (1, 1, 1),
        _ if cfg!(feature = "nftnl-1-1-0") => (1, 1, 0),
        _ if cfg!(feature = "nftnl-1-0-9") => (1, 0, 9),
        _ if cfg!(feature = "nftnl-1-0-8") => (1, 0, 8),
        _ if cfg!(feature = "nftnl-1-0-7") => (1, 0, 7),
        _ => (1, 0, 6),
    }
}
