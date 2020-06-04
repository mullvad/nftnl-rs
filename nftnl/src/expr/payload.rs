use super::{Expression, Rule};
use nftnl_sys::{self as sys, libc};
use std::os::raw::c_char;

trait HeaderField {
    fn offset(&self) -> u32;
    fn len(&self) -> u32;
}

/// Payload expressions refer to data from the packet's payload.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Payload {
    LinkLayer(LLHeaderField),
    Network(NetworkHeaderField),
    Transport(TransportHeaderField),
}

impl Payload {
    fn base(self) -> u32 {
        match self {
            Payload::LinkLayer(_) => libc::NFT_PAYLOAD_LL_HEADER as u32,
            Payload::Network(_) => libc::NFT_PAYLOAD_NETWORK_HEADER as u32,
            Payload::Transport(_) => libc::NFT_PAYLOAD_TRANSPORT_HEADER as u32,
        }
    }
}

impl HeaderField for Payload {
    fn offset(&self) -> u32 {
        use self::Payload::*;
        match *self {
            LinkLayer(ref f) => f.offset(),
            Network(ref f) => f.offset(),
            Transport(ref f) => f.offset(),
        }
    }

    fn len(&self) -> u32 {
        use self::Payload::*;
        match *self {
            LinkLayer(ref f) => f.len(),
            Network(ref f) => f.len(),
            Transport(ref f) => f.len(),
        }
    }
}

impl Expression for Payload {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(
                b"payload\0" as *const _ as *const c_char
            ));

            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_PAYLOAD_BASE as u16, self.base());
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_PAYLOAD_OFFSET as u16, self.offset());
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_PAYLOAD_LEN as u16, self.len());
            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_PAYLOAD_DREG as u16,
                libc::NFT_REG_1 as u32,
            );

            expr
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum LLHeaderField {
    Daddr,
    Saddr,
    EtherType,
}

impl HeaderField for LLHeaderField {
    fn offset(&self) -> u32 {
        use self::LLHeaderField::*;
        match *self {
            Daddr => 0,
            Saddr => 6,
            EtherType => 12,
        }
    }

    fn len(&self) -> u32 {
        use self::LLHeaderField::*;
        match *self {
            Daddr => 6,
            Saddr => 6,
            EtherType => 2,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum NetworkHeaderField {
    Ipv4(Ipv4HeaderField),
    Ipv6(Ipv6HeaderField),
}

impl HeaderField for NetworkHeaderField {
    fn offset(&self) -> u32 {
        use self::NetworkHeaderField::*;
        match *self {
            Ipv4(ref f) => f.offset(),
            Ipv6(ref f) => f.offset(),
        }
    }

    fn len(&self) -> u32 {
        use self::NetworkHeaderField::*;
        match *self {
            Ipv4(ref f) => f.len(),
            Ipv6(ref f) => f.len(),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Ipv4HeaderField {
    Ttl,
    Protocol,
    Saddr,
    Daddr,
}

impl HeaderField for Ipv4HeaderField {
    fn offset(&self) -> u32 {
        use self::Ipv4HeaderField::*;
        match *self {
            Ttl => 8,
            Protocol => 9,
            Saddr => 12,
            Daddr => 16,
        }
    }

    fn len(&self) -> u32 {
        use self::Ipv4HeaderField::*;
        match *self {
            Ttl => 1,
            Protocol => 1,
            Saddr => 4,
            Daddr => 4,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Ipv6HeaderField {
    NextHeader,
    HopLimit,
    Saddr,
    Daddr,
}

impl HeaderField for Ipv6HeaderField {
    fn offset(&self) -> u32 {
        use self::Ipv6HeaderField::*;
        match *self {
            NextHeader => 6,
            HopLimit => 7,
            Saddr => 8,
            Daddr => 24,
        }
    }

    fn len(&self) -> u32 {
        use self::Ipv6HeaderField::*;
        match *self {
            NextHeader => 1,
            HopLimit => 1,
            Saddr => 16,
            Daddr => 16,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransportHeaderField {
    Tcp(TcpHeaderField),
    Udp(UdpHeaderField),
    Icmpv6(Icmpv6HeaderField),
}

impl HeaderField for TransportHeaderField {
    fn offset(&self) -> u32 {
        use self::TransportHeaderField::*;
        match *self {
            Tcp(ref f) => f.offset(),
            Udp(ref f) => f.offset(),
            Icmpv6(ref f) => f.offset(),
        }
    }

    fn len(&self) -> u32 {
        use self::TransportHeaderField::*;
        match *self {
            Tcp(ref f) => f.len(),
            Udp(ref f) => f.len(),
            Icmpv6(ref f) => f.len(),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum TcpHeaderField {
    Sport,
    Dport,
}

impl HeaderField for TcpHeaderField {
    fn offset(&self) -> u32 {
        use self::TcpHeaderField::*;
        match *self {
            Sport => 0,
            Dport => 2,
        }
    }

    fn len(&self) -> u32 {
        use self::TcpHeaderField::*;
        match *self {
            Sport => 2,
            Dport => 2,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum UdpHeaderField {
    Sport,
    Dport,
    Len,
}

impl HeaderField for UdpHeaderField {
    fn offset(&self) -> u32 {
        use self::UdpHeaderField::*;
        match *self {
            Sport => 0,
            Dport => 2,
            Len => 4,
        }
    }

    fn len(&self) -> u32 {
        use self::UdpHeaderField::*;
        match *self {
            Sport => 2,
            Dport => 2,
            Len => 2,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Icmpv6HeaderField {
    Type,
    Code,
    Checksum,
}

impl HeaderField for Icmpv6HeaderField {
    fn offset(&self) -> u32 {
        use self::Icmpv6HeaderField::*;
        match *self {
            Type => 0,
            Code => 1,
            Checksum => 2,
        }
    }

    fn len(&self) -> u32 {
        use self::Icmpv6HeaderField::*;
        match *self {
            Type => 1,
            Code => 1,
            Checksum => 2,
        }
    }
}

#[macro_export(local_inner_macros)]
macro_rules! nft_expr_payload {
    (@ipv4_field ttl) => {
        $crate::expr::Ipv4HeaderField::Ttl
    };
    (@ipv4_field protocol) => {
        $crate::expr::Ipv4HeaderField::Protocol
    };
    (@ipv4_field saddr) => {
        $crate::expr::Ipv4HeaderField::Saddr
    };
    (@ipv4_field daddr) => {
        $crate::expr::Ipv4HeaderField::Daddr
    };

    (@ipv6_field nextheader) => {
        $crate::expr::Ipv6HeaderField::NextHeader
    };
    (@ipv6_field hoplimit) => {
        $crate::expr::Ipv6HeaderField::HopLimit
    };
    (@ipv6_field saddr) => {
        $crate::expr::Ipv6HeaderField::Saddr
    };
    (@ipv6_field daddr) => {
        $crate::expr::Ipv6HeaderField::Daddr
    };

    (@tcp_field sport) => {
        $crate::expr::TcpHeaderField::Sport
    };
    (@tcp_field dport) => {
        $crate::expr::TcpHeaderField::Dport
    };

    (@udp_field sport) => {
        $crate::expr::UdpHeaderField::Sport
    };
    (@udp_field dport) => {
        $crate::expr::UdpHeaderField::Dport
    };
    (@udp_field len) => {
        $crate::expr::UdpHeaderField::Len
    };

    (ethernet daddr) => {
        $crate::expr::Payload::LinkLayer($crate::expr::LLHeaderField::Daddr)
    };
    (ethernet saddr) => {
        $crate::expr::Payload::LinkLayer($crate::expr::LLHeaderField::Saddr)
    };
    (ethernet ethertype) => {
        $crate::expr::Payload::LinkLayer($crate::expr::LLHeaderField::EtherType)
    };

    (ipv4 $field:ident) => {
        $crate::expr::Payload::Network($crate::expr::NetworkHeaderField::Ipv4(
            nft_expr_payload!(@ipv4_field $field),
        ))
    };
    (ipv6 $field:ident) => {
        $crate::expr::Payload::Network($crate::expr::NetworkHeaderField::Ipv6(
            nft_expr_payload!(@ipv6_field $field),
        ))
    };

    (tcp $field:ident) => {
        $crate::expr::Payload::Transport($crate::expr::TransportHeaderField::Tcp(
            nft_expr_payload!(@tcp_field $field),
        ))
    };
    (udp $field:ident) => {
        $crate::expr::Payload::Transport($crate::expr::TransportHeaderField::Udp(
            nft_expr_payload!(@udp_field $field),
        ))
    };
}
