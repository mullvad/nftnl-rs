extern crate pkg_config;

#[cfg(feature = "nftnl-1-1-0")]
const MIN_VERSION: &str = "1.1.0";

#[cfg(all(feature = "nftnl-1-0-9", not(feature = "nftnl-1-1-0")))]
const MIN_VERSION: &str = "1.0.9";

#[cfg(all(feature = "nftnl-1-0-8", not(feature = "nftnl-1-0-9")))]
const MIN_VERSION: &str = "1.0.8";

#[cfg(all(feature = "nftnl-1-0-7", not(feature = "nftnl-1-0-8")))]
const MIN_VERSION: &str = "1.0.7";

#[cfg(not(feature = "nftnl-1-0-7"))]
const MIN_VERSION: &str = "1.0.6";

fn main() {
    println!("Minimum libnftnl version: {}", MIN_VERSION);
    pkg_config::Config::new()
        .atleast_version(MIN_VERSION)
        .probe("libnftnl")
        .unwrap();
}
