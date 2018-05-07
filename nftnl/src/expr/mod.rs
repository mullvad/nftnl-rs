use nftnl_sys as sys;

use Result;

pub trait Expression {
    fn to_expr(&self) -> Result<*mut sys::nftnl_expr>;
}

mod cmp;
pub use self::cmp::*;

mod counter;
pub use self::counter::*;

mod meta;
pub use self::meta::*;

mod payload;
pub use self::payload::*;

#[macro_export]
macro_rules! nft_expr {
    (cmp $op:tt $data:expr) => {
        nft_expr_cmp!($op $data)
    };
    (counter) => {
        $crate::expr::Counter
    };
    (meta $expr:ident) => {
        nft_expr_meta!($expr)
    };
    (payload $proto:ident $field:ident) => {
        nft_expr_payload!($proto $field)
    };
}
