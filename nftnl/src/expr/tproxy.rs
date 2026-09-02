use std::ptr;

use super::{Expression, Register, Rule};
use crate::ProtoFamily;
use nftnl_sys as sys;

// Stable ABI since libnftnl 1.0.6. Some generated binding files omit these constants.
const NFTNL_EXPR_TPROXY_FAMILY: u16 = 1;
const NFTNL_EXPR_TPROXY_REG_ADDR: u16 = 2;
const NFTNL_EXPR_TPROXY_REG_PORT: u16 = 3;

/// TPROXY redirects packets to a local listener without modifying packet headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TProxy {
    pub family: Option<ProtoFamily>,
    pub addr_register: Option<Register>,
    pub port_register: Option<Register>,
}

impl TProxy {
    pub fn new_port(port_register: Register) -> Self {
        TProxy {
            family: None,
            addr_register: None,
            port_register: Some(port_register),
        }
    }

    pub fn new_addr(family: Option<ProtoFamily>, addr_register: Register) -> Self {
        TProxy {
            family,
            addr_register: Some(addr_register),
            port_register: None,
        }
    }

    pub fn new_addr_port(
        family: Option<ProtoFamily>,
        addr_register: Register,
        port_register: Register,
    ) -> Self {
        TProxy {
            family,
            addr_register: Some(addr_register),
            port_register: Some(port_register),
        }
    }
}

impl Expression for TProxy {
    fn to_expr(&self, rule: &Rule) -> ptr::NonNull<sys::nftnl_expr> {
        let expr = try_alloc!(unsafe { sys::nftnl_expr_alloc(c"tproxy".as_ptr()) });

        let family = match self.family {
            Some(ProtoFamily::Inet) | Some(ProtoFamily::Unspec) | None => {
                match rule.get_chain().get_table().get_family() {
                    ProtoFamily::Ipv4 => ProtoFamily::Ipv4,
                    ProtoFamily::Ipv6 => ProtoFamily::Ipv6,
                    _ => ProtoFamily::Unspec,
                }
            }
            Some(family) => family,
        };

        unsafe {
            sys::nftnl_expr_set_u32(expr.as_ptr(), NFTNL_EXPR_TPROXY_FAMILY, family as u32);
            if let Some(addr_register) = self.addr_register {
                sys::nftnl_expr_set_u32(
                    expr.as_ptr(),
                    NFTNL_EXPR_TPROXY_REG_ADDR,
                    addr_register.to_raw(),
                );
            }
            if let Some(port_register) = self.port_register {
                sys::nftnl_expr_set_u32(
                    expr.as_ptr(),
                    NFTNL_EXPR_TPROXY_REG_PORT,
                    port_register.to_raw(),
                );
            }
        }

        expr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Chain, Table};

    #[test]
    fn tproxy_port_in_inet_resolves_to_unspec() {
        let table = Table::new(c"filter", ProtoFamily::Inet);
        let chain = Chain::new(c"prerouting", &table);
        let rule = Rule::new(&chain);

        let tproxy = TProxy::new_port(Register::Reg1);
        let expr = tproxy.to_expr(&rule);

        unsafe {
            assert!(sys::nftnl_expr_is_set(
                expr.as_ptr(),
                NFTNL_EXPR_TPROXY_FAMILY
            ));
            assert_eq!(
                sys::nftnl_expr_get_u32(expr.as_ptr(), NFTNL_EXPR_TPROXY_FAMILY),
                ProtoFamily::Unspec as u32
            );
            assert!(sys::nftnl_expr_is_set(
                expr.as_ptr(),
                NFTNL_EXPR_TPROXY_REG_PORT
            ));
            assert_eq!(
                sys::nftnl_expr_get_u32(expr.as_ptr(), NFTNL_EXPR_TPROXY_REG_PORT),
                Register::Reg1.to_raw()
            );
            assert!(!sys::nftnl_expr_is_set(
                expr.as_ptr(),
                NFTNL_EXPR_TPROXY_REG_ADDR
            ));
            sys::nftnl_expr_free(expr.as_ptr());
        }
    }

    #[test]
    fn tproxy_port_in_ipv4_resolves_to_ipv4() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let chain = Chain::new(c"prerouting", &table);
        let rule = Rule::new(&chain);

        let tproxy = TProxy::new_port(Register::Reg1);
        let expr = tproxy.to_expr(&rule);

        unsafe {
            assert_eq!(
                sys::nftnl_expr_get_u32(expr.as_ptr(), NFTNL_EXPR_TPROXY_FAMILY),
                ProtoFamily::Ipv4 as u32
            );
            sys::nftnl_expr_free(expr.as_ptr());
        }
    }

    #[test]
    fn tproxy_port_in_ipv6_resolves_to_ipv6() {
        let table = Table::new(c"filter", ProtoFamily::Ipv6);
        let chain = Chain::new(c"prerouting", &table);
        let rule = Rule::new(&chain);

        let tproxy = TProxy::new_port(Register::Reg1);
        let expr = tproxy.to_expr(&rule);

        unsafe {
            assert_eq!(
                sys::nftnl_expr_get_u32(expr.as_ptr(), NFTNL_EXPR_TPROXY_FAMILY),
                ProtoFamily::Ipv6 as u32
            );
            sys::nftnl_expr_free(expr.as_ptr());
        }
    }

    #[test]
    fn tproxy_explicit_family_and_addr() {
        let table = Table::new(c"filter", ProtoFamily::Inet);
        let chain = Chain::new(c"prerouting", &table);
        let rule = Rule::new(&chain);

        let tproxy = TProxy::new_addr_port(Some(ProtoFamily::Ipv6), Register::Reg1, Register::Reg2);
        let expr = tproxy.to_expr(&rule);

        unsafe {
            assert_eq!(
                sys::nftnl_expr_get_u32(expr.as_ptr(), NFTNL_EXPR_TPROXY_FAMILY),
                ProtoFamily::Ipv6 as u32
            );
            assert_eq!(
                sys::nftnl_expr_get_u32(expr.as_ptr(), NFTNL_EXPR_TPROXY_REG_ADDR),
                Register::Reg1.to_raw()
            );
            assert_eq!(
                sys::nftnl_expr_get_u32(expr.as_ptr(), NFTNL_EXPR_TPROXY_REG_PORT),
                Register::Reg2.to_raw()
            );
            sys::nftnl_expr_free(expr.as_ptr());
        }
    }
}
