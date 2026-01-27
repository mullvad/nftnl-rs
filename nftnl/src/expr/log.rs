use super::{Expression, Rule};
use nftnl_sys::{self as sys};
use std::ptr::NonNull;

/// A log expression.
#[derive(Debug, Default)]
pub struct Log {
    group: Option<u16>,
}

impl Log {
    /// Create a new log expression belonging to `group`.
    pub fn new_with_group(group: u16) -> Self {
        Log { group: Some(group) }
    }
}

impl Expression for Log {
    fn to_expr(&self, _rule: &Rule) -> std::ptr::NonNull<nftnl_sys::nftnl_expr> {
        let expr = unsafe { sys::nftnl_expr_alloc(c"log".as_ptr()) };
        let expr = NonNull::new(expr).expect("Failed to allocate log expression.");
        if let Some(group) = self.group {
            unsafe {
                sys::nftnl_expr_set_u16(
                    expr.as_ptr(),
                    sys::NFTNL_EXPR_LOG_GROUP.try_into().unwrap(),
                    group,
                );
            }
        };
        expr
    }
}

#[macro_export]
macro_rules! nft_expr_log {
    (group $group:expr) => {
        $crate::expr::Log::new_with_group($group)
    };
    () => {
        $crate::expr::Log::new()
    };
}
