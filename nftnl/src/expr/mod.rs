//! A module with all the nftables expressions that can be added to [`Rule`]s to build up how
//! they match against packets.
//!
//! [`Rule`]: struct.Rule.html

use super::rule::Rule;
use nftnl_sys::{self as sys, libc};

/// Trait for every safe wrapper of an nftables expression.
pub trait Expression {
    /// Allocates and returns the low level `nftnl_expr` representation of this expression.
    /// The caller to this method is responsible for freeing the expression.
    fn to_expr(&self, rule: &Rule) -> *mut sys::nftnl_expr;
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

mod log;
pub use self::log::*;

mod verdict;
pub use self::verdict::*;

#[macro_export(local_inner_macros)]
macro_rules! nft_expr {
    (bitwise mask $mask:expr,xor $xor:expr) => {
        nft_expr_bitwise!(mask $mask, xor $xor)
    };
    (cmp $op:tt $data:expr) => {
        nft_expr_cmp!($op $data)
    };
    (log) => {
        nft_expr_log!()
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
    (immediate $expr:ident $value:expr) => {
        nft_expr_immediate!($expr $value)
    };
}
