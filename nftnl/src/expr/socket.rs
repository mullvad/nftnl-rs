//! Socket expressions.
//!
//! Socket expressions are available since nftnl 1.2.0.

#[cfg(feature = "nftnl-1-2-0")]
pub mod imp {
    use crate::Rule;
    use crate::expr::{Expression, Register};

    use nftnl_sys::{self as sys};
    use std::ptr;

    pub struct Socket {
        key: SocketKey,
        register: Register,
        level: u32,
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
            let expr = try_alloc!(unsafe { sys::nftnl_expr_alloc(c"socket".as_ptr()) });
            // In the source code for socket expr, the member values are validated to be of type 'MNL_TYPE_U32'
            // https://git.netfilter.org/libnftnl/tree/src/expr/socket.c
            unsafe {
                sys::nftnl_expr_set_u32(
                    expr.as_ptr(),
                    sys::NFTNL_EXPR_SOCKET_KEY as u16,
                    self.key.to_raw(),
                )
            };
            unsafe {
                sys::nftnl_expr_set_u32(
                    expr.as_ptr(),
                    sys::NFTNL_EXPR_SOCKET_DREG as u16,
                    self.register.to_raw(),
                )
            };
            unsafe {
                sys::nftnl_expr_set_u32(
                    expr.as_ptr(),
                    sys::NFTNL_EXPR_SOCKET_LEVEL as u16,
                    self.level,
                )
            };
            expr
        }
    }

    #[repr(u32)]
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

    #[macro_export(local_inner_macros)]
    macro_rules! nft_expr_socket {
    (socket cgroupv2 level $level:expr) => {
        nft_expr_socket!(socket (::nftnl::expr::SocketKey::CgroupV2) level $level)
    };
    (socket ($key:expr) level $level:expr) => {
        // TODO: why do we need to specify register??
        ::nftnl::expr::Socket::new($key, ::nftnl::expr::Register::Reg1, $level)
    };
}
}

#[cfg(not(feature = "nftnl-1-2-0"))]
mod imp {
    #[macro_export(local_inner_macros)]
    macro_rules! nft_expr_socket {
        ($($_:tt)+) => {
            ::std::compile_error!("This feature requires feature 'nftnl-1-2-0'");
        };
    }
}
