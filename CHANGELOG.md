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
