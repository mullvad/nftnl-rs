fn main() {
    // socket expressions are available starting from libmnl 1.2.0.
    println!("cargo::rustc-check-cfg=cfg(socketexpr)");
    if nftnl_sys::version::NFTNL_VERSION >= (1, 2, 0) {
        println!(r#"cargo::rustc-cfg=socketexpr"#);
    };
}
