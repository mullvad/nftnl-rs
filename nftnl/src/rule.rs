use crate::{MsgType, chain::Chain, expr::Expression};
use nftnl_sys::{self as sys, libc};
use std::ffi::c_void;
use std::os::raw::c_char;
use std::ptr;

/// A nftables firewall rule.
pub struct Rule<'a> {
    rule: ptr::NonNull<sys::nftnl_rule>,
    chain: &'a Chain<'a>,
}

// Safety: It should be safe to pass this around and *read* from it
// from multiple threads
unsafe impl Send for Rule<'_> {}
unsafe impl Sync for Rule<'_> {}

impl<'a> Rule<'a> {
    /// Creates a new rule object in the given [`Chain`].
    ///
    /// [`Chain`]: struct.Chain.html
    pub fn new(chain: &'a Chain<'_>) -> Rule<'a> {
        unsafe {
            let rule = try_alloc!(sys::nftnl_rule_alloc());
            sys::nftnl_rule_set_u32(
                rule.as_ptr(),
                sys::NFTNL_RULE_FAMILY as u16,
                chain.get_table().get_family() as u32,
            );
            sys::nftnl_rule_set_str(
                rule.as_ptr(),
                sys::NFTNL_RULE_TABLE as u16,
                chain.get_table().get_name().as_ptr(),
            );
            sys::nftnl_rule_set_str(
                rule.as_ptr(),
                sys::NFTNL_RULE_CHAIN as u16,
                chain.get_name().as_ptr(),
            );

            Rule { rule, chain }
        }
    }

    /// Sets the position of this rule within the chain it lives in. By default a new rule is added
    /// to the end of the chain.
    pub fn set_position(&mut self, position: u64) {
        unsafe {
            sys::nftnl_rule_set_u64(
                self.rule.as_ptr(),
                sys::NFTNL_RULE_POSITION as u16,
                position,
            );
        }
    }

    pub fn set_handle(&mut self, handle: u64) {
        unsafe {
            sys::nftnl_rule_set_u64(self.rule.as_ptr(), sys::NFTNL_RULE_HANDLE as u16, handle);
        }
    }

    /// Adds an expression to this rule. Expressions are evaluated from first to last added.
    /// As soon as an expression does not match the packet it's being evaluated for, evaluation
    /// stops and the packet is evaluated against the next rule in the chain.
    pub fn add_expr(&mut self, expr: &impl Expression) {
        unsafe { sys::nftnl_rule_add_expr(self.rule.as_ptr(), expr.to_expr(self).as_ptr()) }
    }

    /// Returns a reference to the [`Chain`] this rule lives in.
    ///
    /// [`Chain`]: struct.Chain.html
    pub fn get_chain(&self) -> &Chain<'_> {
        self.chain
    }
}

unsafe impl crate::NlMsg for Rule<'_> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let type_ = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWRULE,
            MsgType::Del => libc::NFT_MSG_DELRULE,
        };
        let flags: u16 = match msg_type {
            MsgType::Add => {
                (libc::NLM_F_CREATE | libc::NLM_F_APPEND | libc::NLM_F_EXCL | libc::NLM_F_ACK)
                    as u16
            }
            MsgType::Del => libc::NLM_F_ACK as u16,
        };
        let header = unsafe {
            sys::nftnl_nlmsg_build_hdr(
                buf.cast::<c_char>(),
                type_ as u16,
                self.chain.get_table().get_family() as u16,
                flags,
                seq,
            )
        };
        unsafe { sys::nftnl_rule_nlmsg_build_payload(header, self.rule.as_ptr()) };
    }
}

impl Drop for Rule<'_> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_rule_free(self.rule.as_ptr()) };
    }
}
