//! A module with all the nftables expressions that can be added to [`Rule`]s to build up how
//! they match against packets.
//!
//! [`Rule`]: struct.Rule.html

use std::ptr;

use super::rule::Rule;
use nftnl_sys::{self as sys, libc};

/// Trait for every safe wrapper of an nftables expression.
pub trait Expression {
    /// Allocates and returns the low level `nftnl_expr` representation of this expression.
    /// The caller to this method is responsible for freeing the expression.
    fn to_expr(&self, rule: &Rule) -> ptr::NonNull<sys::nftnl_expr>;
}

/// A netfilter data register. The expressions store and read data to and from these
/// when evaluating rule statements.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum Register {
    Reg1 = libc::NFT_REG_1,
    Reg2 = libc::NFT_REG_2,
    Reg3 = libc::NFT_REG_3,
    Reg4 = libc::NFT_REG_4,
}

impl Register {
    pub fn to_raw(self) -> u32 {
        self as u32
    }
}

mod bitwise;
pub use self::bitwise::*;

mod cmp;
pub use self::cmp::*;

mod counter;
pub use self::counter::*;

pub mod ct;
pub use self::ct::*;

mod immediate;
pub use self::immediate::*;

mod lookup;
pub use self::lookup::*;

mod masquerade;
pub use self::masquerade::*;

mod meta;
pub use self::meta::*;

mod nat;
pub use self::nat::*;

mod payload;
pub use self::payload::*;

mod verdict;
pub use self::verdict::*;

#[cfg(feature = "nftnl-1-1-1")]
mod socket;
#[cfg(feature = "nftnl-1-1-1")]
pub use self::socket::*;

// CURRENT OBJECTIVE
// add support for the following nft selector
//   socket cgroupv2 level <integer> <string>
//   socket cgroupv2 level 1 "mullvad-exclusions"
//
// ```
// table inet cgroups-nullvad {
//	chain blaha {
//		type route hook output priority filter; policy accept;
//		socket cgroupv2 level 1 "mullvad-exclusions"        ct mark set 0x00000f41 meta mark set 0x6d6f6c65 counter packets 20 bytes 1952
//	}
// }
//
//
//
// ```
//
// // is this it???
//   nft_exp!(socket cgroupv2 level 1),
//   nft_exp!(cmp == "mullvad-exclusions"),

#[macro_export(local_inner_macros)]
macro_rules! nft_expr {
    (bitwise mask $mask:expr,xor $xor:expr) => {
        nft_expr_bitwise!(mask $mask, xor $xor)
    };
    (socket $thingy:tt level $level:expr) => {
        nft_expr_nftnl_1_2_0!(socket $thingy level $level)
    };
    (cmp $op:tt $data:expr) => {
        nft_expr_cmp!($op $data)
    };
    (counter) => {
        $crate::expr::Counter
    };
    (ct $key:ident set) => {
        nft_expr_ct!($key set)
    };
    (ct $key:ident) => {
        nft_expr_ct!($key)
    };
    (verdict $verdict:ident) => {
        nft_expr_verdict!($verdict)
    };
    (verdict $verdict:ident $chain:expr) => {
        nft_expr_verdict!($verdict $chain)
    };
    (lookup $set:expr) => {
        nft_expr_lookup!($set)
    };
    (masquerade) => {
        $crate::expr::Masquerade
    };
    (meta $expr:ident set) => {
        nft_expr_meta!($expr set)
    };
    (meta $expr:ident) => {
        nft_expr_meta!($expr)
    };
    (payload $proto:ident $field:ident) => {
        nft_expr_payload!($proto $field)
    };
    (payload_raw $base:ident $offset:expr, $length:expr) => {
        nft_expr_payload!($base $offset, $length)
    };
    (immediate $expr:ident $value:expr) => {
        nft_expr_immediate!($expr $value)
    };
}

#[cfg(not(feature = "nftnl-1-2-0"))]
#[macro_export]
macro_rules! nft_expr_nftnl_1_2_0 {
    ($($_:tt)+) => {
        ::std::compile_error!("This feature requires feature 'nftnl-1-2-0'");
    };
}

#[cfg(feature = "nftnl-1-2-0")]
#[macro_export]
macro_rules! nft_expr_nftnl_1_2_0 {
    (socket cgroupv2 level $level:expr) => {
        nft_expr_nftnl_1_2_0!(socket (::nftnl::expr::SocketKey::CgroupV2) level $level)
    };
    (socket ($key:expr) level $level:expr) => {
        // TODO: why do we need to specify register??
        ::nftnl::expr::Socket::new($key, ::nftnl::expr::Register::Reg1, $level)
    };
}
