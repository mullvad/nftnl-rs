use super::Expression;
use libc;
use nftnl_sys::{self as sys, libc::c_char};

bitflags::bitflags! {
    pub struct States: u32 {
        const INVALID = 1;
        const ESTABLISHED = 2;
        const RELATED = 4;
        const NEW = 8;
        const UNTRACKED = 64;
    }
}

pub enum Conntrack {
    State,
}

impl Conntrack {
    fn raw_key(&self) -> u32 {
        match *self {
            Conntrack::State => libc::NFT_CT_STATE as u32,
        }
    }
}

impl Expression for Conntrack {
    fn to_expr(&self) -> crate::Result<*mut sys::nftnl_expr> {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(b"ct\0" as *const _ as *const c_char));

            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_CT_DREG as u16, libc::NFT_REG_1 as u32);
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_CT_KEY as u16, self.raw_key());

            Ok(expr)
        }
    }
}

#[macro_export]
macro_rules! nft_expr_ct {
    (state) => {
        $crate::expr::Conntrack::State
    };
}
