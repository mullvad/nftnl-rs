use std::{env, path::PathBuf};

const MIN_VERSION: &str = {
    match () {
        _ if cfg!(feature = "nftnl-1-3-0") => "1.3.0",
        _ if cfg!(feature = "nftnl-1-2-9") => "1.2.9",
        _ if cfg!(feature = "nftnl-1-2-8") => "1.2.8",
        _ if cfg!(feature = "nftnl-1-2-7") => "1.2.7",
        _ if cfg!(feature = "nftnl-1-2-6") => "1.2.6",
        _ if cfg!(feature = "nftnl-1-2-5") => "1.2.5",
        _ if cfg!(feature = "nftnl-1-2-4") => "1.2.4",
        _ if cfg!(feature = "nftnl-1-2-3") => "1.2.3",
        _ if cfg!(feature = "nftnl-1-2-2") => "1.2.2",
        _ if cfg!(feature = "nftnl-1-2-1") => "1.2.1",
        _ if cfg!(feature = "nftnl-1-2-0") => "1.2.0",
        _ if cfg!(feature = "nftnl-1-1-9") => "1.1.9",
        _ if cfg!(feature = "nftnl-1-1-8") => "1.1.8",
        _ if cfg!(feature = "nftnl-1-1-7") => "1.1.7",
        _ if cfg!(feature = "nftnl-1-1-6") => "1.1.6",
        _ if cfg!(feature = "nftnl-1-1-5") => "1.1.5",
        _ if cfg!(feature = "nftnl-1-1-4") => "1.1.4",
        _ if cfg!(feature = "nftnl-1-1-3") => "1.1.3",
        _ if cfg!(feature = "nftnl-1-1-2") => "1.1.2",
        _ if cfg!(feature = "nftnl-1-1-1") => "1.1.1",
        _ if cfg!(feature = "nftnl-1-1-0") => "1.1.0",
        _ if cfg!(feature = "nftnl-1-0-9") => "1.0.9",
        _ if cfg!(feature = "nftnl-1-0-8") => "1.0.8",
        _ if cfg!(feature = "nftnl-1-0-7") => "1.0.7",
        _ => "1.0.6",
    }
};

fn get_env(var: &'static str) -> Option<PathBuf> {
    println!("cargo:rerun-if-env-changed={}", var);
    env::var_os(var).map(PathBuf::from)
}

fn main() {
    // Do NOT link when building documentation on docs.rs. The native libraries are not
    // present on their build machines and just makes the compilation fail. Documentation
    // generation will work without linking.
    if std::env::var("DOCS_RS").is_ok() {
        return;
    }

    if let Some(lib_dir) = get_env("LIBNFTNL_LIB_DIR") {
        if !lib_dir.is_dir() {
            panic!(
                "libnftnl library directory does not exist: {}",
                lib_dir.display()
            );
        }
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=nftnl");
    } else {
        // Trying with pkg-config instead
        println!("Minimum libnftnl version: {}", MIN_VERSION);
        pkg_config::Config::new()
            .atleast_version(MIN_VERSION)
            .probe("libnftnl")
            .unwrap();
    }
}
