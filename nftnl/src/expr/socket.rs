//! Socket expressions.
//!
//! Match on existing UDP/TCP sockets and their attributes.

#[cfg_attr(not(socketexpr), allow(unused_imports))]
pub use imp::*;

#[cfg(socketexpr)]
mod imp {
    use crate::Rule;
    use crate::expr::{Expression, Register};

    use nftnl_sys::{self as sys};
    use std::ptr::{self, NonNull};

    pub struct Socket {
        /// Socket key to match.
        key: SocketKey,
        /// Destination register.
        ///
        /// The result of matching on this expression will be stored in this [Register].
        register: Register,
        /// CGroups V2 ancestor level.
        level: u32,
    }

    impl Socket {
        pub fn new(key: SocketKey, level: u32) -> Self {
            // Use NFT_REG_1 to store the result of this match expression.
            // This is fine since the data may be contained in a single register (4 bytes).
            // https://anatomic.rip/netfilter_nf_tables/#dataregs
            let register = Register::Reg1;
            Socket {
                level,
                register,
                key,
            }
        }
    }

    impl Expression for Socket {
        fn to_expr(&self, _rule: &Rule) -> ptr::NonNull<sys::nftnl_expr> {
            let expr = unsafe { sys::nftnl_expr_alloc(c"socket".as_ptr()) };
            let expr = NonNull::new(expr).expect("Failed to allocate socket expression. Are you linking againts the wrong version of nftnl?");

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
        ::nftnl::expr::Socket::new($key, $level)
    };
}
}

#[cfg(not(socketexpr))]
mod imp {
    #[macro_export(local_inner_macros)]
    macro_rules! nft_expr_socket {
        ($($_:tt)+) => {
            ::std::compile_error!("This feature requires feature 'nftnl-1-2-0'");
        };
    }
}
