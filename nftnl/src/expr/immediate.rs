use super::{Expression, Register, Rule};
use nftnl_sys as sys;
use std::ffi::c_void;
use std::mem::size_of_val;
use std::os::raw::c_char;

/// An immediate expression. Used to set immediate data.
/// Verdicts are handled separately by [Verdict](super::Verdict).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Immediate<T> {
    pub data: T,
    pub register: Register,
}

impl<T> Immediate<T> {
    pub fn new(data: T, register: Register) -> Self {
        Self { data, register }
    }
}

impl<T> Expression for Immediate<T> {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(
                b"immediate\0" as *const _ as *const c_char
            ));

            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_IMM_DREG as u16,
                self.register.to_raw(),
            );

            sys::nftnl_expr_set(
                expr,
                sys::NFTNL_EXPR_IMM_DATA as u16,
                &self.data as *const _ as *const c_void,
                size_of_val(&self.data) as u32,
            );

            expr
        }
    }
}

#[macro_export]
macro_rules! nft_expr_immediate {
    (data $value:expr) => {
        $crate::expr::Immediate {
            data: $value,
            register: $crate::expr::Register::Reg1,
        }
    };
}
