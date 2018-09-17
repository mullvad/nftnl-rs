# nftnl

Safe abstraction for [`libnftnl`]. Provides low-level userspace access to the in-kernel
nf_tables subsystem. See [`nftnl-sys`] for the low level FFI bindings to the C library.

Can be used to create and remove tables, chains, sets and rules from the nftables firewall,
the successor to iptables.

This library currently has quite rough edges and does not make adding and removing nftables
entries super easy and elegant. That is partly because the library needs more work, but also
partly because nftables is super low level and extremely customizable, making it hard, and
probably wrong, to try and create a too simple/limited wrapper. See examples for inspiration.
One can also look at how the original project this crate was developed to support uses it:
[Mullvad VPN app](https://github.com/mullvad/mullvadvpn-app)

## Selecting version of `libnftnl`

See the documentation for the corresponding sys crate for details: [`nftnl-sys`]
This crate has the same features as the sys crate, and selecting version works the same.

[`libnftnl`]: https://netfilter.org/projects/libnftnl/
[`nftnl-sys`]: https://crates.io/crates/nftnl-sys

License: MIT/Apache-2.0
