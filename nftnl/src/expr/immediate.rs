use super::Expression;
use libc;
use nftnl_sys::{self as sys, libc::{c_char, c_void}};
use std::{ffi::{CStr, CString}, mem::size_of_val};

/// An immediate expression. Used to set immediate data.
/// Verdicts are handled separately by [Verdict].
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Immediate<T> {
    pub data: T,
}

impl<T> Expression for Immediate<T> {
    fn to_expr(&self) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(
                b"immediate\0" as *const _ as *const c_char
            ));

            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_IMM_DREG as u16,
                libc::NFT_REG_1 as u32,
            );

            sys::nftnl_expr_set(
                expr,
                sys::NFTNL_EXPR_IMM_DATA as u16,
                &self.data as *const _ as *const c_void,
                size_of_val(&self.data) as u32,
            );

            expr
        }
    }
}

#[macro_export]
macro_rules! nft_expr_immediate {
    (data $value:expr) => {
        $crate::expr::Immediate { data: $value }
    };
}

/// A verdict expression. In the background actually an "Immediate" expression in nftnl terms,
/// but here it's simplified to only represent a verdict.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Verdict {
    /// Silently drop the packet.
    Drop,
    /// Accept the packet and let it pass.
    Accept,
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
    fn verdict_const(&self) -> i32 {
        match *self {
            Verdict::Drop => libc::NF_DROP,
            Verdict::Accept => libc::NF_ACCEPT,
            Verdict::Queue => libc::NF_QUEUE,
            Verdict::Continue => libc::NFT_CONTINUE,
            Verdict::Break => libc::NFT_BREAK,
            Verdict::Jump { .. } => libc::NFT_JUMP,
            Verdict::Goto { .. } => libc::NFT_GOTO,
            Verdict::Return => libc::NFT_RETURN,
        }
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
        unsafe {
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
                self.verdict_const() as u32,
            );

            expr
        }
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
