use std::sync::LazyLock;

/// Kernel version and major revision, i.e. the first two numbers of e.g. "6.6.9-foo-1"
pub static KERNEL_VERSION: LazyLock<Option<(u32, u32)>> = LazyLock::new(|| {
    // parse kernel version from uname based on this "specification":
    // https://www.linfo.org/kernel_version_numbering.html

    let uname = nix::sys::utsname::uname().ok()?;
    let release = uname.release().to_str()?;
    let (kernel_version, release) = release.split_once('.')?;
    let (major_revision, _) = release.split_once('.')?;

    let kernel_version = kernel_version.parse().ok()?;
    let major_revision = major_revision.parse().ok()?;

    Some((kernel_version, major_revision))
});
