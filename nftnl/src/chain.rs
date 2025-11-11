use crate::{MsgType, Table};
use nftnl_sys::{self as sys, libc};
use std::{
    ffi::{CStr, c_void},
    fmt,
    os::raw::c_char,
};

pub type Priority = i32;

/// The netfilter event hooks a chain can register for.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum Hook {
    /// Hook into the pre-routing stage of netfilter. Corresponds to `NF_INET_PRE_ROUTING`.
    PreRouting = libc::NF_INET_PRE_ROUTING as u16,
    /// Hook into the input stage of netfilter. Corresponds to `NF_INET_LOCAL_IN`.
    In = libc::NF_INET_LOCAL_IN as u16,
    /// Hook into the forward stage of netfilter. Corresponds to `NF_INET_FORWARD`.
    Forward = libc::NF_INET_FORWARD as u16,
    /// Hook into the output stage of netfilter. Corresponds to `NF_INET_LOCAL_OUT`.
    Out = libc::NF_INET_LOCAL_OUT as u16,
    /// Hook into the post-routing stage of netfilter. Corresponds to `NF_INET_POST_ROUTING`.
    PostRouting = libc::NF_INET_POST_ROUTING as u16,
    /// Hook into the ingress stage of netfilter. Corresponds to `NF_INET_INGRESS`.
    Ingress = libc::NF_INET_INGRESS as u16,
}

/// A chain policy. Decides what to do with a packet that was processed by the chain but did not
/// match any rules.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum Policy {
    /// Accept the packet.
    Accept = libc::NF_ACCEPT as u32,
    /// Drop the packet.
    Drop = libc::NF_DROP as u32,
}

/// Base chain type.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ChainType {
    /// Used to filter packets.
    /// Supported protocols: ip, ip6, inet, arp, and bridge tables.
    Filter,
    /// Used to reroute packets if IP headers or packet marks are modified.
    /// Supported protocols: ip, and ip6 tables.
    Route,
    /// Used to perform NAT.
    /// Supported protocols: ip, and ip6 tables.
    Nat,
}

impl ChainType {
    fn as_c_str(&self) -> &'static CStr {
        match *self {
            ChainType::Filter => c"filter",
            ChainType::Route => c"route",
            ChainType::Nat => c"nat",
        }
    }
}

/// Abstraction of a `nftnl_chain`. Chains reside inside [`Table`]s and they hold [`Rule`]s.
///
/// There are two types of chains, "base chain" and "regular chain". See [`set_hook`] for more
/// details.
///
/// [`Table`]: struct.Table.html
/// [`Rule`]: struct.Rule.html
/// [`set_hook`]: #method.set_hook
pub struct Chain<'a> {
    chain: *mut sys::nftnl_chain,
    table: &'a Table,
}

// Safety: It should be safe to pass this around and *read* from it
// from multiple threads
unsafe impl Send for Chain<'_> {}
unsafe impl Sync for Chain<'_> {}

impl<'a> Chain<'a> {
    /// Creates a new chain instance inside the given [`Table`] and with the given name.
    ///
    /// [`Table`]: struct.Table.html
    pub fn new<T: AsRef<CStr>>(name: &T, table: &'a Table) -> Chain<'a> {
        unsafe {
            let chain = try_alloc!(sys::nftnl_chain_alloc());
            sys::nftnl_chain_set_u32(
                chain,
                sys::NFTNL_CHAIN_FAMILY as u16,
                table.get_family() as u32,
            );
            sys::nftnl_chain_set_str(
                chain,
                sys::NFTNL_CHAIN_TABLE as u16,
                table.get_name().as_ptr(),
            );
            sys::nftnl_chain_set_str(chain, sys::NFTNL_CHAIN_NAME as u16, name.as_ref().as_ptr());
            Chain { chain, table }
        }
    }

    /// Sets the hook and priority for this chain. Without calling this method the chain well
    /// become a "regular chain" without any hook and will thus not receive any traffic unless
    /// some rule forward packets to it via goto or jump verdicts.
    ///
    /// By calling `set_hook` with a hook the chain that is created will be registered with that
    /// hook and is thus a "base chain". A "base chain" is an entry point for packets from the
    /// networking stack.
    pub fn set_hook(&mut self, hook: Hook, priority: Priority) {
        unsafe {
            sys::nftnl_chain_set_u32(self.chain, sys::NFTNL_CHAIN_HOOKNUM as u16, hook as u32);
            sys::nftnl_chain_set_s32(self.chain, sys::NFTNL_CHAIN_PRIO as u16, priority);
        }
    }

    /// Set the type of a base chain. This only applies if the chain has been registered
    /// with a hook by calling `set_hook`.
    pub fn set_type(&mut self, chain_type: ChainType) {
        unsafe {
            sys::nftnl_chain_set_str(
                self.chain,
                sys::NFTNL_CHAIN_TYPE as u16,
                chain_type.as_c_str().as_ptr(),
            );
        }
    }

    /// Sets the default policy for this chain. That means what action netfilter will apply to
    /// packets processed by this chain, but that did not match any rules in it.
    pub fn set_policy(&mut self, policy: Policy) {
        unsafe {
            sys::nftnl_chain_set_u32(self.chain, sys::NFTNL_CHAIN_POLICY as u16, policy as u32);
        }
    }

    /// Sets the device for this chain. This only applies if the chain has been registered with an `ingress` hook by calling `set_hook`.
    pub fn set_device<T: AsRef<CStr>>(&mut self, device: &T) {
        unsafe {
            sys::nftnl_chain_set_str(
                self.chain,
                sys::NFTNL_CHAIN_DEV as u16,
                device.as_ref().as_ptr(),
            );
        }
    }

    /// Returns the name of this chain.
    pub fn get_name(&self) -> &CStr {
        unsafe {
            let ptr = sys::nftnl_chain_get_str(self.chain, sys::NFTNL_CHAIN_NAME as u16);
            CStr::from_ptr(ptr)
        }
    }

    /// Returns a reference to the [`Table`] this chain belongs to
    ///
    /// [`Table`]: struct.Table.html
    pub fn get_table(&self) -> &Table {
        self.table
    }
}

impl fmt::Debug for Chain<'_> {
    /// Return a string representation of the chain.
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer: [u8; 4096] = [0; 4096];
        unsafe {
            sys::nftnl_chain_snprintf(
                buffer.as_mut_ptr().cast::<c_char>(),
                buffer.len(),
                self.chain,
                sys::NFTNL_OUTPUT_DEFAULT,
                0,
            );
        }
        let s = unsafe { CStr::from_ptr(buffer.as_ptr() as *const c_char) };
        write!(fmt, "{:?}", s)
    }
}

unsafe impl crate::NlMsg for Chain<'_> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let raw_msg_type = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWCHAIN,
            MsgType::Del => libc::NFT_MSG_DELCHAIN,
        };
        let flags: u16 = match msg_type {
            MsgType::Add => (libc::NLM_F_ACK | libc::NLM_F_CREATE) as u16,
            MsgType::Del => libc::NLM_F_ACK as u16,
        };
        let header = unsafe {
            sys::nftnl_nlmsg_build_hdr(
                buf.cast::<c_char>(),
                raw_msg_type as u16,
                self.table.get_family() as u16,
                flags,
                seq,
            )
        };
        unsafe { sys::nftnl_chain_nlmsg_build_payload(header, self.chain) };
    }
}

impl Drop for Chain<'_> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_chain_free(self.chain) };
    }
}
