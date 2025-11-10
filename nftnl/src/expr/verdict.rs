use super::{Expression, Rule};
use crate::ProtoFamily;
use nftnl_sys::{
    self as sys,
    libc::{self, c_char},
};
use std::ffi::{CStr, CString};

/// A verdict expression. In the background, this is usually an "Immediate" expression in nftnl
/// terms, but here it is simplified to only represent a verdict.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Verdict {
    /// Silently drop the packet.
    Drop,
    /// Accept the packet and let it pass.
    Accept,
    /// Reject the packet and return a message.
    Reject(RejectionType),
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

/// The type of rejection message sent by the Reject verdict.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum RejectionType {
    /// Return an ICMP unreachable packet
    Icmp(IcmpCode),
    /// Reject by sending a TCP RST packet
    TcpRst,
}

impl RejectionType {
    fn to_raw(self, family: ProtoFamily) -> u32 {
        use libc::*;
        let value = match self {
            RejectionType::Icmp(..) => match family {
                ProtoFamily::Bridge | ProtoFamily::Inet => NFT_REJECT_ICMPX_UNREACH,
                _ => NFT_REJECT_ICMP_UNREACH,
            },
            RejectionType::TcpRst => NFT_REJECT_TCP_RST,
        };
        value as u32
    }
}

/// An ICMP reject code.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum IcmpCode {
    NoRoute = libc::NFT_REJECT_ICMPX_NO_ROUTE as u8,
    PortUnreach = libc::NFT_REJECT_ICMPX_PORT_UNREACH as u8,
    HostUnreach = libc::NFT_REJECT_ICMPX_HOST_UNREACH as u8,
    AdminProhibited = libc::NFT_REJECT_ICMPX_ADMIN_PROHIBITED as u8,
}

impl Verdict {
    unsafe fn to_immediate_expr(&self, immediate_const: i32) -> *mut sys::nftnl_expr {
        let expr = try_alloc!(unsafe {
            sys::nftnl_expr_alloc(b"immediate\0" as *const _ as *const c_char)
        });

        unsafe {
            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_IMM_DREG as u16,
                libc::NFT_REG_VERDICT as u32,
            )
        };

        if let Some(chain) = self.chain() {
            unsafe {
                sys::nftnl_expr_set_str(expr, sys::NFTNL_EXPR_IMM_CHAIN as u16, chain.as_ptr())
            };
        }
        unsafe {
            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_IMM_VERDICT as u16,
                immediate_const as u32,
            )
        };

        expr
    }

    unsafe fn to_reject_expr(
        &self,
        reject_type: RejectionType,
        family: ProtoFamily,
    ) -> *mut sys::nftnl_expr {
        let expr = try_alloc!(unsafe { sys::nftnl_expr_alloc(c"reject".as_ptr()) });

        unsafe {
            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_REJECT_TYPE as u16,
                reject_type.to_raw(family),
            )
        };

        let reject_code = match reject_type {
            RejectionType::Icmp(code) => code as u8,
            RejectionType::TcpRst => 0,
        };

        unsafe { sys::nftnl_expr_set_u8(expr, sys::NFTNL_EXPR_REJECT_CODE as u16, reject_code) };

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
    fn to_expr(&self, rule: &Rule) -> *mut sys::nftnl_expr {
        let immediate_const = match *self {
            Verdict::Drop => libc::NF_DROP,
            Verdict::Accept => libc::NF_ACCEPT,
            Verdict::Queue => libc::NF_QUEUE,
            Verdict::Continue => libc::NFT_CONTINUE,
            Verdict::Break => libc::NFT_BREAK,
            Verdict::Jump { .. } => libc::NFT_JUMP,
            Verdict::Goto { .. } => libc::NFT_GOTO,
            Verdict::Return => libc::NFT_RETURN,
            Verdict::Reject(reject_type) => {
                return unsafe {
                    self.to_reject_expr(reject_type, rule.get_chain().get_table().get_family())
                };
            }
        };
        unsafe { self.to_immediate_expr(immediate_const) }
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
    (reject icmp $code:expr) => {
        $crate::expr::Verdict::Reject(RejectionType::Icmp($code))
    };
    (reject tcp-rst) => {
        $crate::expr::Verdict::Reject(RejectionType::TcpRst)
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
