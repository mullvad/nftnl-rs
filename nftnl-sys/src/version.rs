/// Version of `nftnl` for the exported bindings. Major, minor, patch.
pub const NFTNL_VERSION: (u32, u32, u32) = (NFTNL_MAJOR, NFTNL_MINOR, NFTNL_PATCH);

/// [NFTNL_VERSION] as a string.
pub const NFTNL_VERSION_STR: &str = env!("LIBNFTNL_VERSION");

/// Major-version of [NFTNL_VERSION].
pub const NFTNL_MAJOR: u32 = match u32::from_str_radix(env!("LIBNFTNL_MAJOR"), 10) {
    Ok(n) => n,
    Err(_) => panic!(),
};

/// Minor-version of [NFTNL_VERSION].
pub const NFTNL_MINOR: u32 = match u32::from_str_radix(env!("LIBNFTNL_MINOR"), 10) {
    Ok(n) => n,
    Err(_) => panic!(),
};

/// Patch-version of [NFTNL_VERSION].
pub const NFTNL_PATCH: u32 = match u32::from_str_radix(env!("LIBNFTNL_PATCH"), 10) {
    Ok(n) => n,
    Err(_) => panic!(),
};
