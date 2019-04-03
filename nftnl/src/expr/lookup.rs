use super::Expression;
use crate::set::Set;
use libc;
use nftnl_sys::{self as sys, libc::c_char};
use std::ffi::CString;

pub struct Lookup {
    set_name: CString,
    set_id: u32,
}

impl Lookup {
    pub fn new<K>(set: &Set<'_, K>) -> Self {
        Lookup {
            set_name: set.get_name().to_owned(),
            set_id: set.get_id(),
        }
    }
}

impl Expression for Lookup {
    fn to_expr(&self) -> crate::Result<*mut sys::nftnl_expr> {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(
                b"lookup\0" as *const _ as *const c_char
            ));

            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_LOOKUP_SREG as u16,
                libc::NFT_REG_1 as u32,
            );
            sys::nftnl_expr_set_str(
                expr,
                sys::NFTNL_EXPR_LOOKUP_SET as u16,
                self.set_name.as_ptr() as *const _ as *const c_char,
            );
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_LOOKUP_SET_ID as u16, self.set_id);

            // This code is left here since it's quite likely we need it again when we get further
            // if self.reverse {
            //     sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_LOOKUP_FLAGS as u16,
            //         libc::NFT_LOOKUP_F_INV as u32);
            // }

            Ok(expr)
        }
    }
}

#[macro_export]
macro_rules! nft_expr_lookup {
    ($set:expr) => {
        $crate::expr::Lookup::new($set)
    };
}
