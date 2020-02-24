use super::Expression;
use libc;
use nftnl_sys::{self as sys, libc::c_char};

/// A meta expression refers to meta data associated with a packet.
pub enum Meta {
    /// Packet ethertype protocol (skb->protocol), invalid in OUTPUT.
    Protocol,
    /// Packet input interface index (dev->ifindex).
    Iif,
    /// Packet output interface index (dev->ifindex).
    Oif,
    /// Packet input interface name (dev->name)
    IifName,
    /// Packet output interface name (dev->name).
    OifName,
    /// Packet input interface type (dev->type).
    IifType,
    /// Packet output interface type (dev->type).
    OifType,
    /// Netfilter protocol (Transport layer protocol).
    NfProto,
    /// Layer 4 protocol number.
    L4Proto,
    /// Socket control group (skb->sk->sk_classid).
    Cgroup,
    /// A 32bit pseudo-random number
    PRandom,
}

impl Meta {
    /// Returns the corresponding `NFT_*` constant for this meta expression.
    pub fn to_raw_key(&self) -> u32 {
        use self::Meta::*;
        match *self {
            Protocol => libc::NFT_META_PROTOCOL as u32,
            Iif => libc::NFT_META_IIF as u32,
            Oif => libc::NFT_META_OIF as u32,
            IifName => libc::NFT_META_IIFNAME as u32,
            OifName => libc::NFT_META_OIFNAME as u32,
            IifType => libc::NFT_META_IIFTYPE as u32,
            OifType => libc::NFT_META_OIFTYPE as u32,
            NfProto => libc::NFT_META_NFPROTO as u32,
            L4Proto => libc::NFT_META_L4PROTO as u32,
            Cgroup => libc::NFT_META_CGROUP as u32,
            PRandom => libc::NFT_META_PRANDOM as u32,
        }
    }
}

impl Expression for Meta {
    fn to_expr(&self) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(
                b"meta\0" as *const _ as *const c_char
            ));

            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_META_DREG as u16,
                libc::NFT_REG_1 as u32,
            );
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_META_KEY as u16, self.to_raw_key());
            expr
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
    (iiftype) => {
        $crate::expr::Meta::IifType
    };
    (oiftype) => {
        $crate::expr::Meta::OifType
    };
    (nfproto) => {
        $crate::expr::Meta::NfProto
    };
    (l4proto) => {
        $crate::expr::Meta::L4Proto
    };
    (cgroup) => {
        $crate::expr::Meta::Cgroup
    };
    (random) => {
        $crate::expr::Meta::PRandom
    };
}
