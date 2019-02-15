use libc;
use nftnl_sys::{self as sys, libc::c_void};

use crate::chain::Chain;
use crate::expr::Expression;
use crate::{ErrorKind, MsgType, Result};

/// A nftables firewall rule.
pub struct Rule<'a> {
    rule: *mut sys::nftnl_rule,
    chain: &'a Chain<'a>,
}

impl<'a> Rule<'a> {
    /// Creates a new rule object in the given [`Chain`].
    ///
    /// [`Chain`]: struct.Chain.html
    pub fn new(chain: &'a Chain<'_>) -> Result<Rule<'a>> {
        unsafe {
            let rule = sys::nftnl_rule_alloc();
            ensure!(!rule.is_null(), ErrorKind::AllocationError);

            sys::nftnl_rule_set_str(
                rule,
                sys::NFTNL_RULE_TABLE as u16,
                chain.get_table().get_name().as_ptr(),
            );
            sys::nftnl_rule_set_str(
                rule,
                sys::NFTNL_RULE_CHAIN as u16,
                chain.get_name().as_ptr(),
            );
            sys::nftnl_rule_set_u32(
                rule,
                sys::NFTNL_RULE_FAMILY as u16,
                chain.get_table().get_family() as u32,
            );

            Ok(Rule { rule, chain })
        }
    }

    /// Sets the position of this rule within the chain it lives in. By default a new rule is added
    /// to the end of the chain.
    pub fn set_position(&mut self, position: u64) {
        unsafe {
            sys::nftnl_rule_set_u64(self.rule, sys::NFTNL_RULE_POSITION as u16, position);
        }
    }

    pub fn set_handle(&mut self, handle: u64) {
        unsafe {
            sys::nftnl_rule_set_u64(self.rule, sys::NFTNL_RULE_HANDLE as u16, handle);
        }
    }

    /// Adds an expression to this rule. Expressions are evaluated from first to last added.
    /// As soon as an expression does not match the packet it's being evaluated for, evaluation
    /// stops and the packet is evaluated against the next rule in the chain.
    pub fn add_expr(&mut self, expr: &impl Expression) -> Result<()> {
        unsafe { sys::nftnl_rule_add_expr(self.rule, expr.to_expr()?) }
        Ok(())
    }

    /// Returns a reference to the [`Chain`] this rule lives in.
    ///
    /// [`Chain`]: struct.Chain.html
    pub fn get_chain(&self) -> &Chain<'_> {
        self.chain
    }
}

unsafe impl<'a> crate::NlMsg for Rule<'a> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let type_ = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWRULE,
            MsgType::Del => libc::NFT_MSG_DELRULE,
        };
        let header = sys::nftnl_nlmsg_build_hdr(
            buf as *mut i8,
            type_ as u16,
            self.chain.get_table().get_family() as u16,
            (libc::NLM_F_APPEND | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16,
            seq,
        );
        sys::nftnl_rule_nlmsg_build_payload(header, self.rule);
    }
}

impl<'a> Drop for Rule<'a> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_rule_free(self.rule) };
    }
}
