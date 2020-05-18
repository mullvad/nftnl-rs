use super::Expression;
use libc;
use nftnl_sys::{self as sys, libc::{c_char, c_void}};
use std::mem::size_of_val;

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
