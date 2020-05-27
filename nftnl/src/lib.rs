// Copyright 2018 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Safe abstraction for [`libnftnl`]. Provides low-level userspace access to the in-kernel
//! nf_tables subsystem. See [`nftnl-sys`] for the low level FFI bindings to the C library.
//!
//! Can be used to create and remove tables, chains, sets and rules from the nftables firewall,
//! the successor to iptables.
//!
//! This library currently has quite rough edges and does not make adding and removing netfilter
//! entries super easy and elegant. That is partly because the library needs more work, but also
//! partly because nftables is super low level and extremely customizable, making it hard, and
//! probably wrong, to try and create a too simple/limited wrapper. See examples for inspiration.
//! One can also look at how the original project this crate was developed to support uses it:
//! [Mullvad VPN app](https://github.com/mullvad/mullvadvpn-app)
//!
//! Understanding how to use [`libnftnl`] and implementing this crate has mostly been done by
//! reading the source code for the [`nftables`] program and attaching debuggers to the `nft`
//! binary. Since the implementation is mostly based on trial and error, there might of course be
//! a number of places where the underlying library is used in an invalid or not intended way.
//! Large portions of [`libnftnl`] are also not covered yet. Contributions are welcome!
//!
//! # Selecting version of `libnftnl`
//!
//! See the documentation for the corresponding sys crate for details: [`nftnl-sys`]
//! This crate has the same features as the sys crate, and selecting version works the same.
//!
//! [`libnftnl`]: https://netfilter.org/projects/libnftnl/
//! [`nftables`]: https://netfilter.org/projects/nftables/
//! [`nftnl-sys`]: https://crates.io/crates/nftnl-sys

#[macro_use]
extern crate log;


pub use nftnl_sys;
use nftnl_sys::libc::c_void;

macro_rules! try_alloc {
    ($e:expr) => {{
        let ptr = $e;
        if ptr.is_null() {
            // OOM, and the tried allocation was likely very small,
            // so we are in a very tight situation. We do what libstd does, aborts.
            std::process::abort();
        }
        ptr
    }};
}

mod batch;
pub use batch::{batch_is_supported, default_batch_page_size, Batch, FinalizedBatch, NetlinkError};

pub mod expr;

pub mod table;
pub use table::Table;

mod chain;
pub use chain::{Chain, ChainType, Hook, Policy, Priority};

mod rule;
pub use rule::Rule;

pub mod set;

/// The type of the message as it's sent to netfilter. A message consists of an object, such as a
/// [`Table`], [`Chain`] or [`Rule`] for example, and a [`MsgType`] to describe what to do with
/// that object. If a [`Table`] object is sent with `MsgType::Add` then that table will be added
/// to netfilter, if sent with `MsgType::Del` it will be removed.
///
/// [`Table`]: struct.Table.html
/// [`Chain`]: struct.Chain.html
/// [`Rule`]: struct.Rule.html
/// [`MsgType`]: enum.MsgType.html
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum MsgType {
    /// Add the object to netfilter.
    Add,
    /// Remove the object from netfilter.
    Del,
}

/// Denotes a protocol. Used to specify which protocol a table or set belongs to.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum ProtoFamily {
    Unspec = libc::NFPROTO_UNSPEC as u16,
    /// Inet - Means both IPv4 and IPv6
    Inet = libc::NFPROTO_INET as u16,
    Ipv4 = libc::NFPROTO_IPV4 as u16,
    Arp = libc::NFPROTO_ARP as u16,
    NetDev = libc::NFPROTO_NETDEV as u16,
    Bridge = libc::NFPROTO_BRIDGE as u16,
    Ipv6 = libc::NFPROTO_IPV6 as u16,
    DecNet = libc::NFPROTO_DECNET as u16,
}

/// Trait for all types in this crate that can serialize to a Netlink message.
///
/// # Unsafe
///
/// This trait is unsafe to implement because it must never serialize to anything larger than the
/// largest possible netlink message. Internally the `nft_nlmsg_maxsize()` function is used to make
/// sure the `buf` pointer passed to `write` always has room for the largest possible Netlink
/// message.
pub unsafe trait NlMsg {
    /// Serializes the Netlink message to the buffer at `buf`. `buf` must have space for at least
    /// `nft_nlmsg_maxsize()` bytes. This is not checked by the compiler, which is why this method
    /// is unsafe.
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType);
}

/// The largest nf_tables netlink message is the set element message, which
/// contains the NFTA_SET_ELEM_LIST_ELEMENTS attribute. This attribute is
/// a nest that describes the set elements. Given that the netlink attribute
/// length (nla_len) is 16 bits, the largest message is a bit larger than
/// 64 KBytes.
pub fn nft_nlmsg_maxsize() -> u32 {
    u32::from(::std::u16::MAX) + unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32
}
