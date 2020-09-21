use super::{Expression, Register, Rule};
use crate::ProtoFamily;
use nftnl_sys::{self as sys, libc};
use std::os::raw::c_char;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum NatType {
    /// Source NAT. Changes the source address of a packet
    SNat = libc::NFT_NAT_SNAT,
    /// Destination NAT. Changeth the destination address of a packet
    DNat = libc::NFT_NAT_DNAT,
}

/// A source or destination NAT statement. Modifies the source or destination address
/// (and possibly port) of packets.
pub struct Nat {
    pub nat_type: NatType,
    pub family: ProtoFamily,
    pub ip_register: Register,
    pub port_register: Option<Register>,
}

impl Expression for Nat {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        let expr =
            try_alloc!(unsafe { sys::nftnl_expr_alloc(b"nat\0" as *const _ as *const c_char) });

        unsafe {
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_NAT_TYPE as u16, self.nat_type as u32);
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_NAT_FAMILY as u16, self.family as u32);
            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_NAT_REG_ADDR_MIN as u16,
                self.ip_register.to_raw(),
            );
            if let Some(port_register) = self.port_register {
                sys::nftnl_expr_set_u32(
                    expr,
                    sys::NFTNL_EXPR_NAT_REG_PROTO_MIN as u16,
                    port_register.to_raw(),
                );
            }
        }

        expr
    }
}
