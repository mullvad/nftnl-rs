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
### Changed
- Upgrade crates to Rust 2021 edition.


## [0.6.2] - 2022-02-11
### Added
- Add `ct status` to load the conntrack status, and add conntrack status bitflags.

### Fixed
- Specify dependency versions more exactly to allow building with minimal versions
  of the entire dependency tree.


## [0.6.1] - 2021-02-04
### Changed
- Upgrade the err-derive dependency to 0.3.0.


## [0.6.0] - 2020-11-23
### Added
- Implement Send+Sync for Table, Chain, Rule, Batch and Iter (batch iterator).
- Add `Nat` expression allowing SNat and DNat rules.

### Changed
- Add `Register` enum and a register field to the `Immediate` expression. Allowing control
  over which netfilter register the immediate data is loaded into

### Fixed
- Fix memory leak in `table::get_tables_cb`.


## [0.5.0] - 2020-06-04
### Added
- Add support for matching on socket UID and socket GID in `Meta` expressions.

### Changed
- Mark `Meta` and many payload enums as `#[non_exhaustive]`. Allows adding more expressions
  without a breaking release in the future.
- Increase minimum supported rust version to 1.40 due to `#[non_exhaustive]`.


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
