# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

### Categories each change fall into

* **Added**: for new features.
* **Changed**: for changes in existing functionality.
* **Deprecated**: for soon-to-be removed features.
* **Removed**: for now removed features.
* **Fixed**: for any bug fixes.
* **Security**: in case of vulnerabilities.


## [Unreleased]
### Added
- Add support for matching on socket UID and socket GID in `Meta` expressions.


## [0.4.0] - 2020-05-27
### Added
- Add `Reject` verdict for responding with ICMP packets or TCP RST to the origin.


## [0.3.0] - 2020-04-20
### Added
- Add `ChainType` and allow setting a chain to either filter, route or nat type.
- Add support for reading and setting marks in the `Meta` and `Conntrack` expressions.
- Add support for reading the cgroup via the `Meta` expression.
- Add `Immediate` expression type that can load data into the registers.
- Add support for masquerading.
- Implement `Debug` for `Chain`.

### Changed
- Change `get_tables_nlmsg` to include all tables, not only inet tables,
  but also arp, ip, ip6, bridge etc.

### Fixed
- Fix compilation errors on ARM64 platforms.
- Set `NFTNL_CHAIN_FAMILY` for chains and other fixes making the library compatible
  with older kernels.

## [0.2.1] - 2019-09-23
### Added
- Add support for checking ICMPv6 header fields.


## [0.2.0] - 2019-04-05
### Added
- Add `add-get-tables-request` that can create requests to enumerate tables.
- Add bindings to `libnftnl-1.1.2`.

### Changed
- Upgrade crates to Rust 2018 edition.
- Remove the `error-chain` dependency. Now aborts on allocation error.


## [0.1.0] - 2018-09-10
### Added
- Bindings to `libnftnl` versions `1.0.6` through `1.1.1`
- Initial safe abstraction. Support for batches, tables, chains, rules and sets.
  All with a limited set of expression types.
