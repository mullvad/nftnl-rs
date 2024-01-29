use super::{Expression, Rule};
use nftnl_sys::{self as sys, libc};
use std::os::raw::c_char;
use std::str::FromStr;

#[non_exhaustive]
pub enum FibResult {
    Oif,
    OifName,
    AddrType,
}

impl FromStr for FibResult {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "oif" => Ok(FibResult::Oif),
            "oifname" => Ok(FibResult::OifName),
            "type" => Ok(FibResult::AddrType),
            _ => Err("Invalid FibResult variant"),
        }
    }
}

impl FibResult {
    pub fn raw_result_type(&self) -> u32 {
        use FibResult::*;

        // From: linux/netfilter/nf_tables.h
        match *self {
            Oif => 1,
            OifName => 2,
            AddrType => 3,
        }
    }
}

#[non_exhaustive]
pub enum Fib {
    SAddr { result: &'static str },
    DAddr { result: &'static str },
    Mark { result: &'static str },
    Iif { result: &'static str },
    Oif { result: &'static str },
    Present { result: &'static str },
}

impl Fib {
    pub fn flags(&self) -> u32 {
        use Fib::*;

        // From: linux/netfilter/nf_tables.h
        match *self {
            SAddr { .. } => 1 << 0,
            DAddr { .. } => 1 << 1,
            Mark { .. } => 1 << 2,
            Iif { .. } => 1 << 3,
            Oif { .. } => 1 << 4,
            Present { .. } => 1 << 5,
        }
    }

    pub fn result(&self) -> u32 {
        use Fib::*;

        let result: FibResult = match self {
            SAddr { result }
            | DAddr { result }
            | Mark { result }
            | Iif { result }
            | Oif { result }
            | Present { result } => result
                .parse()
                .expect("Unexpected fib result. Must be type, oif or oifname."),
        };

        result.raw_result_type()
    }
}

impl Expression for Fib {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(b"fib\0" as *const _ as *const c_char));

            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_FIB_DREG as u16,
                libc::NFT_REG_1 as u32,
            );

            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_FIB_RESULT as u16, self.result());
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_FIB_FLAGS as u16, self.flags());

            expr
        }
    }
}

#[macro_export]
macro_rules! nft_expr_fib {
    (saddr $result:expr) => {
        $crate::expr::Fib::SAddr { result: $result }
    };
    (daddr $result:expr) => {
        $crate::expr::Fib::DAddr { result: $result }
    };
    (mark $result:expr) => {
        $crate::expr::Fib::Mark { result: $result }
    };
    (iif $result:expr) => {
        $crate::expr::Fib::Iif { result: $result }
    };
    (oif $result:expr) => {
        $crate::expr::Fib::Oif { result: $result }
    };
    (present $result:expr) => {
        $crate::expr::Fib::Present { result: $result }
    };
}
