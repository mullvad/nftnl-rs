use libc;
use nftnl_sys::{self as sys, c_void, c_char};

use super::Expression;
use expr::cmp::ToSlice;
use {ErrorKind, Result};

/// Expression for performing bitwise masking and XOR on the data in a register.
pub struct Bitwise<M: ToSlice, X: ToSlice> {
    mask: M,
    xor: X,
}

impl<M: ToSlice, X: ToSlice> Bitwise<M, X> {
    pub fn new(mask: M, xor: X) -> Self {
        Self { mask, xor }
    }
}

impl<M: ToSlice, X: ToSlice> Expression for Bitwise<M, X> {
    fn to_expr(&self) -> Result<*mut sys::nftnl_expr> {
        unsafe {
            let expr = sys::nftnl_expr_alloc(b"bitwise\0" as *const _ as *const c_char);
            ensure!(!expr.is_null(), ErrorKind::AllocationError);

            let mask = self.mask.to_slice();
            let xor = self.xor.to_slice();
            assert!(mask.len() == xor.len());
            let len = mask.len() as u32;

            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_BITWISE_SREG as u16,
                libc::NFT_REG_1 as u32,
            );
            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_BITWISE_DREG as u16,
                libc::NFT_REG_1 as u32,
            );
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_BITWISE_LEN as u16, len);

            sys::nftnl_expr_set(
                expr,
                sys::NFTNL_EXPR_BITWISE_MASK as u16,
                mask.as_ref() as *const _ as *const c_void,
                len,
            );
            sys::nftnl_expr_set(
                expr,
                sys::NFTNL_EXPR_BITWISE_XOR as u16,
                xor.as_ref() as *const _ as *const c_void,
                len,
            );

            Ok(expr)
        }
    }
}

#[macro_export]
macro_rules! nft_expr_bitwise {
    (mask $mask:expr,xor $xor:expr) => {
        $crate::expr::Bitwise::new($mask, $xor)
    };
}
