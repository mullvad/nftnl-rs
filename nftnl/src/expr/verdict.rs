use super::Expression;
use nftnl_sys::{self as sys, libc::{self, c_char}};
use std::{ffi::{CStr, CString}};

/// A verdict expression. In the background, this is usually an "Immediate" expression in nftnl
/// terms, but here it is simplified to only represent a verdict.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Verdict {
    /// Silently drop the packet.
    Drop,
    /// Accept the packet and let it pass.
    Accept,
    /// Reject the packet and return a message.
    Reject,
    Queue,
    Continue,
    Break,
    Jump {
        chain: CString,
    },
    Goto {
        chain: CString,
    },
    Return,
}

impl Verdict {
    unsafe fn immediate_to_expr(&self, immediate_const: i32) -> *mut sys::nftnl_expr {
        let expr = try_alloc!(sys::nftnl_expr_alloc(
            b"immediate\0" as *const _ as *const c_char
        ));

        sys::nftnl_expr_set_u32(
            expr,
            sys::NFTNL_EXPR_IMM_DREG as u16,
            libc::NFT_REG_VERDICT as u32,
        );

        if let Some(chain) = self.chain() {
            sys::nftnl_expr_set_str(expr, sys::NFTNL_EXPR_IMM_CHAIN as u16, chain.as_ptr());
        }
        sys::nftnl_expr_set_u32(
            expr,
            sys::NFTNL_EXPR_IMM_VERDICT as u16,
            immediate_const as u32,
        );

        expr
    }

    unsafe fn to_reject_expr(&self) -> *mut sys::nftnl_expr {
        let expr = try_alloc!(sys::nftnl_expr_alloc(
            b"reject\0" as *const _ as *const c_char
        ));

        sys::nftnl_expr_set_u32(
            expr,
            sys::NFTNL_EXPR_REJECT_TYPE as u16,
            libc::NFT_REJECT_ICMPX_UNREACH as u32,
        );

        // TODO: Allow setting the ICMP code
        sys::nftnl_expr_set_u8(
            expr,
            sys::NFTNL_EXPR_REJECT_CODE as u16,
            libc::NFT_REJECT_ICMPX_HOST_UNREACH as u8,
        );

        expr
    }

    fn chain(&self) -> Option<&CStr> {
        match *self {
            Verdict::Jump { ref chain } => Some(chain.as_c_str()),
            Verdict::Goto { ref chain } => Some(chain.as_c_str()),
            _ => None,
        }
    }
}

impl Expression for Verdict {
    fn to_expr(&self) -> *mut sys::nftnl_expr {
        let immediate_const = match *self {
            Verdict::Drop => libc::NF_DROP,
            Verdict::Accept => libc::NF_ACCEPT,
            Verdict::Queue => libc::NF_QUEUE,
            Verdict::Continue => libc::NFT_CONTINUE,
            Verdict::Break => libc::NFT_BREAK,
            Verdict::Jump { .. } => libc::NFT_JUMP,
            Verdict::Goto { .. } => libc::NFT_GOTO,
            Verdict::Return => libc::NFT_RETURN,
            Verdict::Reject => return unsafe { self.to_reject_expr() },
        };
        unsafe { self.immediate_to_expr(immediate_const) }
    }
}

#[macro_export]
macro_rules! nft_expr_verdict {
    (drop) => {
        $crate::expr::Verdict::Drop
    };
    (accept) => {
        $crate::expr::Verdict::Accept
    };
    (reject) => {
        $crate::expr::Verdict::Reject
    };
    (queue) => {
        $crate::expr::Verdict::Queue
    };
    (continue) => {
        $crate::expr::Verdict::Continue
    };
    (break) => {
        $crate::expr::Verdict::Break
    };
    (jump $chain:expr) => {
        $crate::expr::Verdict::Jump { chain: $chain }
    };
    (goto $chain:expr) => {
        $crate::expr::Verdict::Goto { chain: $chain }
    };
    (return) => {
        $crate::expr::Verdict::Return
    };
}
