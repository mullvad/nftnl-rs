use super::{Expression, Rule};
use nftnl_sys::{self as sys, libc};
use std::os::raw::c_char;

bitflags::bitflags! {
    pub struct States: u32 {
        const INVALID = 1;
        const ESTABLISHED = 2;
        const RELATED = 4;
        const NEW = 8;
        const UNTRACKED = 64;
    }
}

bitflags::bitflags! {
    pub struct ConntrackStatus: u32 {
        const EXPECTED = 1;
        const SEEN_REPLY = 2;
        const ASSURED = 4;
        const CONFIRMED = 8;
        const SRC_NAT = 16;
        const DST_NAT = 32;
        const SEQ_ADJUST = 64;
        const SRC_NAT_DONE = 128;
        const DST_NAT_DONE = 256;
        const DYING = 512;
        const FIXED_TIMEOUT = 1024;
        const TEMPLATE = 2048;
        const UNTRACKED = 4096;
        const HELPER = 8192;
        const OFFLOAD = 16384;
        const HW_OFFLOAD = 32768;
    }
}

pub enum Conntrack {
    State,
    Status,
    Mark { set: bool },
    Zone { set: bool },
}

impl Conntrack {
    fn raw_key(&self) -> u32 {
        match *self {
            Conntrack::State => libc::NFT_CT_STATE as u32,
            Conntrack::Status => libc::NFT_CT_STATUS as u32,
            Conntrack::Mark { .. } => libc::NFT_CT_MARK as u32,
            // TODO: Update this once libc has definitions for NFT_CT_ZONE
            // (https://github.com/rust-lang/libc/issues/3566)
            Conntrack::Zone { .. } => 17 as u32,
        }
    }
}

impl Expression for Conntrack {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(b"ct\0" as *const _ as *const c_char));

            match &self {
                Conntrack::Mark { set: true } | Conntrack::Zone { set: true } => {
                    sys::nftnl_expr_set_u32(
                        expr,
                        sys::NFTNL_EXPR_CT_SREG as u16,
                        libc::NFT_REG_1 as u32,
                    );
                }
                _ => {
                    sys::nftnl_expr_set_u32(
                        expr,
                        sys::NFTNL_EXPR_CT_DREG as u16,
                        libc::NFT_REG_1 as u32,
                    );
                }
            }

            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_CT_KEY as u16, self.raw_key());

            expr
        }
    }
}

#[macro_export]
macro_rules! nft_expr_ct {
    (state) => {
        $crate::expr::Conntrack::State
    };
    (status) => {
        $crate::expr::Conntrack::Status
    };
    (mark set) => {
        $crate::expr::Conntrack::Mark { set: true }
    };
    (mark) => {
        $crate::expr::Conntrack::Mark { set: false }
    };
    (zone set) => {
        $crate::expr::Conntrack::Zone { set: true }
    };
    (zone) => {
        $crate::expr::Conntrack::Zone { set: false }
    };
}
