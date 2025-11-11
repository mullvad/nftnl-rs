use super::{Expression, Rule};
use nftnl_sys as sys;

/// Sets the source IP to that of the output interface.
pub struct Masquerade;

impl Expression for Masquerade {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        try_alloc!(unsafe { sys::nftnl_expr_alloc(c"masq".as_ptr()) })
    }
}
