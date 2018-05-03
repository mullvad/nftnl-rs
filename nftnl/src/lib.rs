pub extern crate nftnl_sys;

#[macro_use]
extern crate error_chain;
extern crate libc;

use nftnl_sys::c_void;

error_chain! {
    errors {
        AllocationError { description("Unable to allocate memory") }
    }
}

pub mod expr;

mod table;
pub use table::Table;

mod chain;
pub use chain::{Chain, Hook, Priority};

mod rule;
pub use rule::Rule;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum MsgType {
    Add,
    Del,
}

#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum ProtoFamily {
    Unspec = libc::NFPROTO_UNSPEC as u16,
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
    ::std::u16::MAX as u32 + unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32
}
