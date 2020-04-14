use super::Expression;
use nftnl_sys::{self as sys, libc::c_char};

/// Sets the source IP to that of the output interface.
pub struct Masquerade;

impl Expression for Masquerade {
    fn to_expr(&self) -> *mut sys::nftnl_expr {
        try_alloc!(unsafe { sys::nftnl_expr_alloc(b"masq\0" as *const _ as *const c_char) })
    }
}
