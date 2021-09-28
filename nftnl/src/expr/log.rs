use super::{Expression, Rule};
use nftnl_sys::{
    self as sys,
    libc::c_char,
};

/// A log expression.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Log {}


impl Log {}

impl Expression for Log {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(
                b"log\0" as *const _ as *const c_char
            ));

            expr
        }
    }
}

#[macro_export]
macro_rules! nft_expr_log {
    () => {
        $crate::expr::Log {}
    };
}
