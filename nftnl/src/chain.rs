use libc;
use nftnl_sys::{self as sys, libc::c_void};

use std::ffi::CStr;

use crate::Table;
use crate::{MsgType, Result};


pub type Priority = u32;

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

impl<'a> Chain<'a> {
    /// Creates a new chain instance inside the given [`Table`] and with the given name.
    ///
    /// [`Table`]: struct.Table.html
    pub fn new<T: AsRef<CStr>>(name: &T, table: &'a Table) -> Result<Chain<'a>> {
        unsafe {
            let chain = try_alloc!(sys::nftnl_chain_alloc());
            sys::nftnl_chain_set_str(
                chain,
                sys::NFTNL_CHAIN_TABLE as u16,
                table.get_name().as_ptr(),
            );
            sys::nftnl_chain_set_str(chain, sys::NFTNL_CHAIN_NAME as u16, name.as_ref().as_ptr());
            Ok(Chain { chain, table })
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
            sys::nftnl_chain_set_u32(self.chain, sys::NFTNL_CHAIN_PRIO as u16, priority);
        }
    }

    /// Sets the default policy for this chain. That means what action netfilter will apply to
    /// packets processed by this chain, but that did not match any rules in it.
    pub fn set_policy(&mut self, policy: Policy) {
        unsafe {
            sys::nftnl_chain_set_u32(self.chain, sys::NFTNL_CHAIN_POLICY as u16, policy as u32);
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

unsafe impl<'a> crate::NlMsg for Chain<'a> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let raw_msg_type = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWCHAIN,
            MsgType::Del => libc::NFT_MSG_DELCHAIN,
        };
        let header = sys::nftnl_nlmsg_build_hdr(
            buf as *mut i8,
            raw_msg_type as u16,
            self.table.get_family() as u16,
            libc::NLM_F_ACK as u16,
            seq,
        );
        sys::nftnl_chain_nlmsg_build_payload(header, self.chain);
    }
}

impl<'a> Drop for Chain<'a> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_chain_free(self.chain) };
    }
}
