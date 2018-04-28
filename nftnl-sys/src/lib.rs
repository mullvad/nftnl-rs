// Copyright 2018 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Low level FFI bindings to [`libnftnl`]. a userspace library providing a low-level netlink
//! programming interface (API) to the in-kernel nf_tables subsystem.
//!
//! See [`nftnl`] for a higher level safe abstraction.
//!
//! [`libnftnl`]: https://netfilter.org/projects/libnftnl/
//! [`nftnl`]: https://crates.io/crates/nftnl

#![no_std]
#![cfg(target_os = "linux")]
#![allow(non_camel_case_types)]

extern crate libc;

#[cfg(feature = "nftnl-1-0-9")]
mod nftnl_1_0_9;
#[cfg(feature = "nftnl-1-0-9")]
pub use nftnl_1_0_9::*;

#[cfg(all(feature = "nftnl-1-0-8", not(feature = "nftnl-1-0-9")))]
mod nftnl_1_0_8;
#[cfg(all(feature = "nftnl-1-0-8", not(feature = "nftnl-1-0-9")))]
pub use nftnl_1_0_8::*;

#[cfg(all(feature = "nftnl-1-0-7", not(feature = "nftnl-1-0-8")))]
mod nftnl_1_0_7;
#[cfg(all(feature = "nftnl-1-0-7", not(feature = "nftnl-1-0-8")))]
pub use nftnl_1_0_7::*;

#[cfg(not(feature = "nftnl-1-0-7"))]
mod nftnl_1_0_6;
#[cfg(not(feature = "nftnl-1-0-7"))]
pub use nftnl_1_0_6::*;
