use libc;
use nftnl_sys as sys;

use super::Expression;
use {ErrorKind, Result};

/// A meta expression refers to meta data associated with a packet.
pub enum Meta {
    /// Ethertype protocol value.
    Protocol,
    /// Input interface index.
    Iif,
    /// Output interface index.
    Oif,
    /// Input interface name.
    IifName,
    /// Output interface name.
    OifName,
    /// Transport layer protocol.
    NfProto,
    /// Layer4 protocol.
    L4Proto,
}

impl Meta {
    pub fn to_raw_key(&self) -> u32 {
        use self::Meta::*;
        match *self {
            Protocol => libc::NFT_META_PROTOCOL as u32,
            Iif => libc::NFT_META_IIF as u32,
            Oif => libc::NFT_META_OIF as u32,
            IifName => libc::NFT_META_IIFNAME as u32,
            OifName => libc::NFT_META_OIFNAME as u32,
            NfProto => libc::NFT_META_NFPROTO as u32,
            L4Proto => libc::NFT_META_L4PROTO as u32,
        }
    }
}

impl Expression for Meta {
    fn to_expr(&self) -> Result<*mut sys::nftnl_expr> {
        unsafe {
            let expr = sys::nftnl_expr_alloc(b"meta\0" as *const _ as *const i8);
            if expr.is_null() {
                bail!(ErrorKind::AllocationError);
            }
            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_META_DREG as u16,
                libc::NFT_REG_1 as u32,
            );
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_META_KEY as u16, self.to_raw_key());
            Ok(expr)
        }
    }
}

#[macro_export]
macro_rules! nft_expr_meta {
    (proto) => {
        $crate::expr::Meta::Protocol
    };
    (iif) => {
        $crate::expr::Meta::Iif
    };
    (oif) => {
        $crate::expr::Meta::Oif
    };
    (iifname) => {
        $crate::expr::Meta::IifName
    };
    (oifname) => {
        $crate::expr::Meta::OifName
    };
    (nfproto) => {
        $crate::expr::Meta::NfProto
    };
    (l4proto) => {
        $crate::expr::Meta::L4Proto
    };
}
