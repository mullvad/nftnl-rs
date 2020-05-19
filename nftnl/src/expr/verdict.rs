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
    Reject {
        /// Reject expression reject types:
        /// `NFT_REJECT_ICMP_UNREACH`: return an ICMP unreachable packet
        /// `NFT_REJECT_TCP_RST`: reject using TCP RST
        /// `NFT_REJECT_ICMPX_UNREACH`: ICMP unreachable for inet and bridge
        reject_type: u32,
        /// An ICMP reject code:
        /// `NFT_REJECT_ICMPX_NO_ROUTE`,
        /// `NFT_REJECT_ICMPX_PORT_UNREACH`,
        /// `NFT_REJECT_ICMPX_HOST_UNREACH`, or
        /// `NFT_REJECT_ICMPX_ADMIN_PROHIBITED`.
        icmp_code: u8,
    },
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

    unsafe fn to_reject_expr(&self, reject_type: u32, icmp_code: u8) -> *mut sys::nftnl_expr {
        let expr = try_alloc!(sys::nftnl_expr_alloc(
            b"reject\0" as *const _ as *const c_char
        ));

        sys::nftnl_expr_set_u32(
            expr,
            sys::NFTNL_EXPR_REJECT_TYPE as u16,
            reject_type,
        );

        sys::nftnl_expr_set_u8(
            expr,
            sys::NFTNL_EXPR_REJECT_CODE as u16,
            icmp_code,
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
            Verdict::Reject { reject_type, icmp_code } => return unsafe {
                self.to_reject_expr(reject_type, icmp_code)
            },
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
    (reject $type:ident $code:ident) => {
        $crate::expr::Verdict::Reject { reject_type: $type, code: $code }
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
