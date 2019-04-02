use super::Expression;
use nftnl_sys::{self as sys, libc::c_char};

/// A counter expression adds a counter to the rule that is incremented to count number of packets
/// and number of bytes for all packets that has matched the rule.
pub struct Counter;

impl Expression for Counter {
    fn to_expr(&self) -> crate::Result<*mut sys::nftnl_expr> {
        Ok(try_alloc!(unsafe {
            sys::nftnl_expr_alloc(b"counter\0" as *const _ as *const c_char)
        }))
    }
}
