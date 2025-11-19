use crate::expr::Register;

use super::{Expression, Rule};
use nftnl_sys::{self as sys};
use std::ptr;

pub struct Socket {
    key: SocketKey,
    /// https://git.netfilter.org/libnftnl/tree/include/linux/netfilter/nf_tables.h
    register: Register,
    level: u32,
}

#[repr(u32)] // See nftnl_expr_socket_parse
#[derive(Clone, Copy, Debug)]
pub enum SocketKey {
    /// NFT_SOCKET_TRANSPARENT
    Transparent = 0,
    /// NFT_SOCKET_MARK
    Mark = 1,
    /// NFT_SOCKET_WILDCARD
    Wildcard = 2,
    /// NFT_SOCKET_CGROUPV2
    CgroupV2 = 3,
}

impl SocketKey {
    pub fn to_raw(self) -> u32 {
        self as u32
    }
}

impl Socket {
    pub fn new(key: SocketKey, register: Register, level: u32) -> Self {
        Socket {
            level,
            register,
            key,
        }
    }
}

impl Expression for Socket {
    fn to_expr(&self, _rule: &Rule) -> ptr::NonNull<sys::nftnl_expr> {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(c"socket".as_ptr()));

            // Should dreg come first?
            sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                sys::NFTNL_EXPR_IMM_DREG as u16,
                self.register.to_raw(),
            );

            sys::nftnl_expr_set_u8(
                expr.as_ptr(),
                sys::NFTNL_EXPR_SOCKET_KEY as u16,
                self.key as u8,
            );
            sys::nftnl_expr_set_u32(
                expr.as_ptr(),
                sys::NFTNL_EXPR_SOCKET_LEVEL as u16,
                self.level,
            );

            expr
        }
    }
}
