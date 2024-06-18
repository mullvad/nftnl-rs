use crate::{MsgType, ProtoFamily, Table};
use nftnl_sys::{self as sys, libc};
use std::{
    ffi::{c_void, CStr},
    fmt,
    os::raw::c_char,
};

/// Priority of a chain. This can be an integral value, a named priority, 
/// or a named priority with an offset.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Priority {
    Integer(i32),
    Name(PriorityName),
    NamedOffset(PriorityName, i32),
}

/// Named priorities for chains.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum PriorityName {
    Raw,
    Mangle,
    DstNat,
    Filter,
    Security,
    SrcNat,
    Out,
}

impl Priority {
    /// Get the priority value for a given family and hook.
    /// 
    /// If the combination is invalid, `None` is returned.
    pub const fn value(self, family: ProtoFamily, hook: Hook) -> Option<i32> {
        match self {
            Priority::Integer(value) => Some(value),
            Priority::Name(name) => Self::named(name, family, hook),
            Priority::NamedOffset(name, offset) => {
                // not using `Option::map` to make it const
                if let Some(value) = Self::named(name, family, hook) {
                    value.checked_add(offset)
                } else {
                    None
                }
            }
        }
    }

    const fn named(name: PriorityName, family: ProtoFamily, hook: Hook) -> Option<i32> {
        use Hook::*;
        use PriorityName::*;
        use ProtoFamily::*;
        // see nft manpage for compatibility matrices
        match (name, family, hook) {
            // Table 6
            (Raw, Inet | Ipv4 | Ipv6, _) => Some(libc::NF_IP_PRI_RAW),
            (Mangle, Inet | Ipv4 | Ipv6, _) => Some(libc::NF_IP_PRI_MANGLE),
            (DstNat, Inet | Ipv4 | Ipv6, PreRouting) => Some(libc::NF_IP_PRI_NAT_DST),
            (Filter, Inet | Ipv4 | Ipv6 | Arp | NetDev, _) => Some(libc::NF_IP_PRI_FILTER),
            (Security, Inet | Ipv4 | Ipv6, _) => Some(libc::NF_IP_PRI_SECURITY),
            (SrcNat, Inet | Ipv4 | Ipv6, PostRouting) => Some(libc::NF_IP_PRI_NAT_SRC),
            // Table 7
            // Bridge constants not defined in libc yet, see
            // https://github.com/rust-lang/libc/pull/3734
            (DstNat, Bridge, PreRouting) => Some(-300),
            (Filter, Bridge, _) => Some(-200),
            (PriorityName::Out, Bridge, Hook::Out) => Some(100),
            (SrcNat, Bridge, PostRouting) => Some(300),
            _ => None,
        }
    }
}

/// The netfilter event hooks a chain can register for.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum Hook {
    /// Hook into the pre-routing stage of netfilter. Corresponds to `NF_INET_PRE_ROUTING`.
    PreRouting = libc::NF_INET_PRE_ROUTING as u16,
    /// Hook into the input stage of netfilter. Corresponds to `NF_INET_LOCAL_IN`.
    In = libc::NF_INET_LOCAL_IN as u16,
    /// Hook into the forward stage of netfilter. Corresponds to `NF_INET_FORWARD`.
    Forward = libc::NF_INET_FORWARD as u16,
    /// Hook into the output stage of netfilter. Corresponds to `NF_INET_LOCAL_OUT`.
    Out = libc::NF_INET_LOCAL_OUT as u16,
    /// Hook into the post-routing stage of netfilter. Corresponds to `NF_INET_POST_ROUTING`.
    PostRouting = libc::NF_INET_POST_ROUTING as u16,
}

/// A chain policy. Decides what to do with a packet that was processed by the chain but did not
/// match any rules.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum Policy {
    /// Accept the packet.
    Accept = libc::NF_ACCEPT as u32,
    /// Drop the packet.
    Drop = libc::NF_DROP as u32,
}

/// Base chain type.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ChainType {
    /// Used to filter packets.
    /// Supported protocols: ip, ip6, inet, arp, and bridge tables.
    Filter,
    /// Used to reroute packets if IP headers or packet marks are modified.
    /// Supported protocols: ip, and ip6 tables.
    Route,
    /// Used to perform NAT.
    /// Supported protocols: ip, and ip6 tables.
    Nat,
}

impl ChainType {
    fn as_c_str(&self) -> &'static CStr {
        let bytes: &[u8] = match *self {
            ChainType::Filter => b"filter\0",
            ChainType::Route => b"route\0",
            ChainType::Nat => b"nat\0",
        };
        unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
    }
}

/// Abstraction of a `nftnl_chain`. Chains reside inside [`Tables`](crate::Table) and they hold [`Rules`](crate::Rule).
///
/// There are two types of chains, **base chains** and **regular chains**.
///
/// A regular chain is not an entry point for packets, and
/// "may be used as jump target and is used for better rule organization".
///
/// A base chain on the other hand is hooked into the networking stack and is an entry point for packets.
/// However, there are certain constraints for it to be valid. Therefore, a base chain may only be
/// set through the [`BaseChainSetter`] and its [`try_set`](BaseChainSetter::try_set) function.
///
/// See the nftables manpage for more information.
pub struct Chain<'a> {
    chain: *mut sys::nftnl_chain,
    table: &'a Table,
}

impl<'a> Chain<'a> {
    /// Create a regular chain.
    ///
    /// ```
    /// use nftnl::{Chain, Table, ProtoFamily};
    /// use std::ffi::CString;
    ///
    /// let table_name = CString::new("test-table").unwrap();
    /// let chain_name = CString::new("test-chain").unwrap();
    /// let table = Table::new(&table_name, ProtoFamily::Inet);
    ///
    /// let chain = Chain::new(&chain_name, &table);
    /// ```
    pub fn new<T: AsRef<CStr>>(name: T, table: &'a Table) -> Self {
        unsafe {
            let chain = try_alloc!(sys::nftnl_chain_alloc());
            sys::nftnl_chain_set_u32(
                chain,
                sys::NFTNL_CHAIN_FAMILY as u16,
                table.get_family() as u32,
            );
            sys::nftnl_chain_set_str(
                chain,
                sys::NFTNL_CHAIN_TABLE as u16,
                table.get_name().as_ptr(),
            );
            sys::nftnl_chain_set_str(chain, sys::NFTNL_CHAIN_NAME as u16, name.as_ref().as_ptr());
            Chain { chain, table }
        }
    }
}

/// A setter for configuring a valid base chain.
#[derive(Debug, Clone, Copy, Default)]
pub struct BaseChainSetter<'a> {
    chain_type: Option<ChainType>,
    hook: Option<Hook>,
    priority: Option<Priority>,
    device: Option<&'a CStr>,
    policy: Option<Policy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Errors that can occur when setting a base chain through [`BaseChainSetter::try_set`].
pub enum BaseChainError {
    MissingChainType,
    MissingHook,
    MissingPriority,
    InvalidCombination,
    InvalidPriority,
}

impl fmt::Display for BaseChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use BaseChainError::*;
        match self {
            MissingChainType => write!(f, "missing chain type"),
            MissingHook => write!(f, "missing hook"),
            MissingPriority => write!(f, "missing priority"),
            InvalidCombination => write!(f, "invalid combination of chain type, family, and hook"),
            InvalidPriority => write!(f, "invalid priority value"),
        }
    }
}

impl std::error::Error for BaseChainError {}

impl<'a> BaseChainSetter<'a> {
    /// Create a new base chain setter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the chain type. This is mandatory for a base chain.
    pub fn chain_type(mut self, chain_type: ChainType) -> Self {
        self.chain_type = Some(chain_type);
        self
    }

    /// Configure the hook. This is mandatory for a base chain.
    pub fn hook(mut self, hook: Hook) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Configure the priority. This is mandatory for a base chain.
    pub fn priority(mut self, priority: Priority) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Configure the device. This is optional.
    pub fn device<T: AsRef<CStr>>(mut self, device: Option<&'a T>) -> Self {
        self.device = device.map(AsRef::as_ref);
        self
    }

    /// Configure the policy. This is optional.
    pub fn policy(mut self, policy: Option<Policy>) -> Self {
        self.policy = policy;
        self
    }

    /// Try to set `chain` as the configured base chain.
    ///
    /// If the base chain configuration is valid, the chain will be set and the function will return `Ok(())`.
    /// Otherwise, no operation will be performed and the error will be returned as `Err(BaseChainError)`.
    ///
    /// ```
    /// use nftnl::*;
    /// use std::ffi::CString;
    ///
    /// let table_name = CString::new("test-table").unwrap();
    /// let chain_name = CString::new("test-chain").unwrap();
    /// let table = Table::new(&table_name, ProtoFamily::Inet);
    /// let mut chain = Chain::new(&chain_name, &table);
    ///
    /// let setter = BaseChainSetter::new()
    ///    .chain_type(ChainType::Nat)
    ///    .hook(Hook::PreRouting)
    ///    .priority(Priority::Integral(0));
    ///
    /// let result = setter.try_set(&mut chain);
    ///
    /// assert_eq!(result, Ok(()));
    ///
    /// // setter can be reused and modified
    /// let setter = setter.hook(Hook::Forward);
    /// let result = setter.try_set(&mut chain);
    ///
    /// assert_eq!(result, Err(BaseChainError::InvalidCombination));
    /// ```
    pub fn try_set(&self, chain: &mut Chain<'_>) -> Result<(), BaseChainError> {
        use BaseChainError::*;
        let Self {
            chain_type,
            hook,
            priority,
            device,
            policy,
        } = self;
        let Chain { chain, table } = *chain;

        // "For base chains, type, hook and priority parameters are mandatory."
        if chain_type.is_none() {
            return Err(MissingChainType);
        }
        if hook.is_none() {
            return Err(MissingHook);
        }
        if priority.is_none() {
            return Err(MissingPriority);
        }

        let (chain_type, hook, priority) = (chain_type.unwrap(), hook.unwrap(), priority.unwrap());
        let family = table.get_family();

        {
            use ChainType::*;
            use Hook::*;
            use ProtoFamily::*;

            // nft manpage Table 5
            // FIXME: add missing netdev ingress/egress hooks
            match (chain_type, family, hook) {
                (Filter, Arp, In | Out) => (),
                (Filter, Arp, _) => return Err(InvalidCombination),
                (Filter, _, _) => (),
                (Nat, Inet | Ipv4 | Ipv6, PreRouting | In | Out | PostRouting) => (),
                // Inet not documented
                (Route, Inet | Ipv4 | Ipv6, Out) => (),
                _ => return Err(InvalidCombination),
            };
        }

        let Some(priority) = priority.value(family, hook) else {
            return Err(InvalidPriority);
        };

        // "there's a lower excluding limit of -200 for priority values,
        //  because conntrack hooks at this priority and NAT requires it"
        if chain_type == ChainType::Nat && priority <= -200 {
            return Err(InvalidPriority);
        }

        unsafe {
            sys::nftnl_chain_set_str(
                chain,
                sys::NFTNL_CHAIN_TYPE as u16,
                chain_type.as_c_str().as_ptr(),
            );

            sys::nftnl_chain_set_u32(chain, sys::NFTNL_CHAIN_HOOKNUM as u16, hook as u32);

            sys::nftnl_chain_set_s32(chain, sys::NFTNL_CHAIN_PRIO as u16, priority);

            if let Some(device) = device {
                sys::nftnl_chain_set_str(chain, sys::NFTNL_CHAIN_DEV as u16, device.as_ptr());
            }

            if let Some(policy) = policy {
                sys::nftnl_chain_set_u32(chain, sys::NFTNL_CHAIN_POLICY as u16, *policy as u32);
            }
        }

        Ok(())
    }
}

impl<'a> Chain<'a> {
    /// Returns the name of this chain.
    pub fn get_name(&self) -> &CStr {
        unsafe {
            let ptr = sys::nftnl_chain_get_str(self.chain, sys::NFTNL_CHAIN_NAME as u16);
            CStr::from_ptr(ptr)
        }
    }

    /// Returns a reference to the [`Table`] this chain belongs to
    pub fn get_table(&self) -> &Table {
        self.table
    }
}

// Safety: It should be safe to pass this around and *read* from it
// from multiple threads
unsafe impl<'a> Send for Chain<'a> {}
unsafe impl<'a> Sync for Chain<'a> {}

impl<'a> fmt::Debug for Chain<'a> {
    /// Return a string representation of the chain.
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer: [u8; 4096] = [0; 4096];
        unsafe {
            sys::nftnl_chain_snprintf(
                buffer.as_mut_ptr() as *mut c_char,
                buffer.len(),
                self.chain,
                sys::NFTNL_OUTPUT_DEFAULT,
                0,
            );
        }
        let s = unsafe { CStr::from_ptr(buffer.as_ptr() as *const c_char) };
        write!(fmt, "{:?}", s)
    }
}

unsafe impl<'a> crate::NlMsg for Chain<'a> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let raw_msg_type = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWCHAIN,
            MsgType::Del => libc::NFT_MSG_DELCHAIN,
        };
        let flags: u16 = match msg_type {
            MsgType::Add => (libc::NLM_F_ACK | libc::NLM_F_CREATE) as u16,
            MsgType::Del => libc::NLM_F_ACK as u16,
        };
        let header = sys::nftnl_nlmsg_build_hdr(
            buf as *mut c_char,
            raw_msg_type as u16,
            self.table.get_family() as u16,
            flags,
            seq,
        );
        sys::nftnl_chain_nlmsg_build_payload(header, self.chain);
    }
}

impl<'a> Drop for Chain<'a> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_chain_free(self.chain) };
    }
}
