use nftnl_sys as sys;

use Result;

pub trait Expression {
    fn to_expr(&self) -> Result<*mut sys::nftnl_expr>;
}

mod bitwise;
pub use self::bitwise::*;

mod cmp;
pub use self::cmp::*;

mod counter;
pub use self::counter::*;

pub mod ct;
pub use self::ct::Conntrack;

mod immediate;
pub use self::immediate::*;

mod lookup;
pub use self::lookup::*;

mod meta;
pub use self::meta::*;

mod payload;
pub use self::payload::*;

#[macro_export]
macro_rules! nft_expr {
    (bitwise mask $mask:expr,xor $xor:expr) => {
        nft_expr_bitwise!(mask $mask, xor $xor)
    };
    (cmp $op:tt $data:expr) => {
        nft_expr_cmp!($op $data)
    };
    (counter) => {
        $crate::expr::Counter
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
    (meta $expr:ident) => {
        nft_expr_meta!($expr)
    };
    (payload $proto:ident $field:ident) => {
        nft_expr_payload!($proto $field)
    };
}
