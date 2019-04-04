extern crate pkg_config;

use std::{env, path::PathBuf};

cfg_if::cfg_if! {
    if #[cfg(feature = "nftnl-1-1-2")] {
        const MIN_VERSION: &str = "1.1.2";
    } else if #[cfg(feature = "nftnl-1-1-1")] {
        const MIN_VERSION: &str = "1.1.1";
    } else if #[cfg(feature = "nftnl-1-1-0")] {
        const MIN_VERSION: &str = "1.1.0";
    } else if #[cfg(feature = "nftnl-1-0-9")] {
        const MIN_VERSION: &str = "1.0.9";
    } else if #[cfg(feature = "nftnl-1-0-8")] {
        const MIN_VERSION: &str = "1.0.8";
    } else if #[cfg(feature = "nftnl-1-0-7")] {
        const MIN_VERSION: &str = "1.0.7";
    } else {
        const MIN_VERSION: &str = "1.0.6";
    }
}

fn get_env(var: &'static str) -> Option<PathBuf> {
    println!("cargo:rerun-if-env-changed={}", var);
    env::var_os(var).map(PathBuf::from)
}

fn main() {
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

    if let Some(lib_dir) = get_env("LIBMNL_LIB_DIR") {
        if !lib_dir.is_dir() {
            panic!(
                "libmnl library directory does not exist: {}",
                lib_dir.display()
            );
        }
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=mnl");
    } else {
        // Trying with pkg-config instead
        pkg_config::Config::new()
            .atleast_version("1.0.0")
            .probe("libmnl")
            .unwrap();
    }
}
