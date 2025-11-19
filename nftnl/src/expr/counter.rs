use std::ptr;

use super::{Expression, Rule};
use nftnl_sys as sys;

/// A counter expression adds a counter to the rule that is incremented to count number of packets
/// and number of bytes for all packets that has matched the rule.
pub struct Counter;

impl Expression for Counter {
    fn to_expr(&self, _rule: &Rule) -> ptr::NonNull<sys::nftnl_expr> {
        try_alloc!(unsafe { sys::nftnl_expr_alloc(c"counter".as_ptr()) })
    }
}
