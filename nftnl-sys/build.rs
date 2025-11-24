use std::{env, path::PathBuf};

/// Version of libnftnl that we export bindings for.
const VERSION: (u32, u32, u32) = {
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
};

fn get_env(var: &'static str) -> Option<PathBuf> {
    println!("cargo:rerun-if-env-changed={}", var);
    env::var_os(var).map(PathBuf::from)
}

fn version_str() -> String {
    let (major, minor, patch) = VERSION;
    format!("{major}.{minor}.{patch}")
}

fn output_version_env() {
    let (major, minor, patch) = VERSION;
    let version_str = version_str();
    println!("cargo::rustc-env=LIBNFTNL_VERSION={version_str}");
    println!("cargo::rustc-env=LIBNFTNL_MAJOR={major}");
    println!("cargo::rustc-env=LIBNFTNL_MINOR={minor}");
    println!("cargo::rustc-env=LIBNFTNL_PATCH={patch}");
}

fn main() {
    // Do NOT link when building documentation on docs.rs. The native libraries are not
    // present on their build machines and just makes the compilation fail. Documentation
    // generation will work without linking.
    if env::var("DOCS_RS").is_ok() {
        return;
    }

    output_version_env();

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
        let version_str = version_str();
        println!("Minimum libnftnl version: {version_str}");
        pkg_config::Config::new()
            .atleast_version(&version_str)
            .probe("libnftnl")
            .unwrap();
    }
}
