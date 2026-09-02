use crate::{MsgType, ProtoFamily, table::Table};
use nftnl_sys::{self as sys, libc};
use std::{
    cell::Cell,
    ffi::{CStr, c_void},
    net::{Ipv4Addr, Ipv6Addr},
    os::raw::c_char,
    ptr,
    rc::Rc,
};

#[macro_export]
macro_rules! nft_set {
    ($name:expr, $id:expr, $table:expr, $family:expr) => {
        $crate::set::Set::new($name, $id, $table, $family)
    };
    ($name:expr, $id:expr, $table:expr, $family:expr; [ ]) => {
        nft_set!($name, $id, $table, $family)
    };
    ($name:expr, $id:expr, $table:expr, $family:expr; [ $($value:expr,)* ]) => {{
        let mut set = nft_set!($name, $id, $table, $family);
        $(
            set.add($value);
        )*
        set
    }};
}

pub struct Set<'a, K> {
    set: ptr::NonNull<sys::nftnl_set>,
    table: &'a Table,
    family: ProtoFamily,
    _marker: ::std::marker::PhantomData<K>,
}

impl<'a, K> Set<'a, K> {
    /// Creates an anonymous, constant set.
    ///
    /// Anonymous sets are intended to be referenced by a rule in the same transaction.
    pub fn new(name: &CStr, id: u32, table: &'a Table, family: ProtoFamily) -> Self
    where
        K: SetKey,
    {
        Self::new_with_flags(
            name,
            id,
            table,
            family,
            Some((libc::NFT_SET_ANONYMOUS | libc::NFT_SET_CONSTANT) as u32),
        )
    }

    /// Creates a named set that remains in the table independently of any rule.
    pub fn new_named(name: &CStr, id: u32, table: &'a Table, family: ProtoFamily) -> Self
    where
        K: SetKey,
    {
        Self::new_with_flags(name, id, table, family, None)
    }

    fn new_with_flags(
        name: &CStr,
        id: u32,
        table: &'a Table,
        family: ProtoFamily,
        flags: Option<u32>,
    ) -> Self
    where
        K: SetKey,
    {
        let set = try_alloc!(unsafe { sys::nftnl_set_alloc() });

        unsafe {
            let set = set.as_ptr();
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_FAMILY as u16, family as u32);
            sys::nftnl_set_set_str(set, sys::NFTNL_SET_TABLE as u16, table.get_name().as_ptr());
            sys::nftnl_set_set_str(set, sys::NFTNL_SET_NAME as u16, name.as_ptr());
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_ID as u16, id);

            if let Some(flags) = flags {
                sys::nftnl_set_set_u32(set, sys::NFTNL_SET_FLAGS as u16, flags);
            }
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_KEY_TYPE as u16, K::TYPE);
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_KEY_LEN as u16, K::LEN);
        }

        Set {
            set,
            table,
            family,
            _marker: ::std::marker::PhantomData,
        }
    }

    /// Adds a key to the set's in-memory element list.
    ///
    /// Use [`Set::elems_iter`] to add the resulting element messages to a batch.
    pub fn add(&mut self, key: &K)
    where
        K: SetKey,
    {
        unsafe {
            let elem = try_alloc!(sys::nftnl_set_elem_alloc());

            let data = key.data();
            let data_len = data.len() as u32;
            trace!("Adding key {data:?} with len {data_len}");
            sys::nftnl_set_elem_set(
                elem.as_ptr(),
                sys::NFTNL_SET_ELEM_KEY as u16,
                data.as_ref() as *const _ as *const c_void,
                data_len,
            );
            sys::nftnl_set_elem_add(self.set.as_ptr(), elem.as_ptr());
        }
    }

    /// Returns the netlink messages for the elements previously added to this set.
    pub fn elems_iter(&'a self) -> SetElemsIter<'a, K> {
        SetElemsIter::new(self)
    }

    pub fn as_ptr(&self) -> ptr::NonNull<sys::nftnl_set> {
        self.set
    }

    pub fn get_family(&self) -> ProtoFamily {
        self.family
    }

    pub fn get_name(&self) -> &CStr {
        unsafe {
            let ptr = sys::nftnl_set_get_str(self.set.as_ptr(), sys::NFTNL_SET_NAME as u16);
            CStr::from_ptr(ptr)
        }
    }

    pub fn get_id(&self) -> u32 {
        unsafe { sys::nftnl_set_get_u32(self.set.as_ptr(), sys::NFTNL_SET_ID as u16) }
    }

    /// Returns a message that flushes all elements from this set.
    pub fn flush(&self) -> FlushSet<'_, K> {
        FlushSet { set: self }
    }
}

unsafe impl<K> crate::NlMsg for Set<'_, K> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let type_ = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWSET,
            MsgType::Del => libc::NFT_MSG_DELSET,
        };
        let header = unsafe {
            sys::nftnl_nlmsg_build_hdr(
                buf.cast::<c_char>(),
                type_ as u16,
                self.table.get_family() as u16,
                (libc::NLM_F_APPEND | libc::NLM_F_CREATE | libc::NLM_F_ACK) as u16,
                seq,
            )
        };
        unsafe { sys::nftnl_set_nlmsg_build_payload(header, self.set.as_ptr()) };
    }
}

impl<K> Drop for Set<'_, K> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_set_free(self.set.as_ptr()) };
    }
}

pub struct SetElemsIter<'a, K> {
    set: &'a Set<'a, K>,
    iter: ptr::NonNull<sys::nftnl_set_elems_iter>,
    ret: Rc<Cell<i32>>,
}

impl<'a, K> SetElemsIter<'a, K> {
    fn new(set: &'a Set<'a, K>) -> Self {
        let iter = try_alloc!(unsafe { sys::nftnl_set_elems_iter_create(set.set.as_ptr()) });
        SetElemsIter {
            set,
            iter,
            ret: Rc::new(Cell::new(1)),
        }
    }
}

impl<'a, K: 'a> Iterator for SetElemsIter<'a, K> {
    type Item = SetElemsMsg<'a, K>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ret.get() <= 0
            || unsafe { sys::nftnl_set_elems_iter_cur(self.iter.as_ptr()).is_null() }
        {
            trace!("SetElemsIter iterator ending");
            None
        } else {
            trace!("SetElemsIter returning new SetElemsMsg");
            Some(SetElemsMsg {
                set: self.set,
                iter: self.iter.as_ptr(),
                ret: self.ret.clone(),
            })
        }
    }
}

impl<K> Drop for SetElemsIter<'_, K> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_set_elems_iter_destroy(self.iter.as_ptr()) };
    }
}

pub struct SetElemsMsg<'a, K> {
    set: &'a Set<'a, K>,
    iter: *mut sys::nftnl_set_elems_iter,
    ret: Rc<Cell<i32>>,
}

unsafe impl<K> crate::NlMsg for SetElemsMsg<'_, K> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        trace!("Writing SetElemsMsg to NlMsg");
        let (type_, flags) = match msg_type {
            MsgType::Add => (
                libc::NFT_MSG_NEWSETELEM,
                libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
            ),
            MsgType::Del => (libc::NFT_MSG_DELSETELEM, libc::NLM_F_ACK),
        };
        let header = unsafe {
            sys::nftnl_nlmsg_build_hdr(
                buf.cast::<c_char>(),
                type_ as u16,
                self.set.get_family() as u16,
                flags as u16,
                seq,
            )
        };
        self.ret
            .set(unsafe { sys::nftnl_set_elems_nlmsg_build_payload_iter(header, self.iter) });
    }
}

/// A netlink message that flushes all elements from a set.
pub struct FlushSet<'a, K> {
    set: &'a Set<'a, K>,
}

unsafe impl<K> crate::NlMsg for FlushSet<'_, K> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, _msg_type: MsgType) {
        trace!("Writing FlushSet to NlMsg");
        let header = unsafe {
            sys::nftnl_nlmsg_build_hdr(
                buf.cast::<c_char>(),
                libc::NFT_MSG_DELSETELEM as u16,
                self.set.get_family() as u16,
                libc::NLM_F_ACK as u16,
                seq,
            )
        };
        unsafe {
            sys::nftnl_set_elems_nlmsg_build_payload(header, self.set.set.as_ptr());
        }
    }
}

pub trait SetKey {
    const TYPE: u32;
    const LEN: u32;

    fn data(&self) -> Box<[u8]>;
}

impl SetKey for Ipv4Addr {
    const TYPE: u32 = 7;
    const LEN: u32 = 4;

    fn data(&self) -> Box<[u8]> {
        self.octets().to_vec().into_boxed_slice()
    }
}

impl SetKey for Ipv6Addr {
    const TYPE: u32 = 8;
    const LEN: u32 = 16;

    fn data(&self) -> Box<[u8]> {
        self.octets().to_vec().into_boxed_slice()
    }
}

impl SetKey for u16 {
    const TYPE: u32 = 13;
    const LEN: u32 = 2;

    fn data(&self) -> Box<[u8]> {
        self.to_be_bytes().to_vec().into_boxed_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_anonymous_constant_set() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let set = Set::<Ipv4Addr>::new(c"test", 1, &table, ProtoFamily::Ipv4);

        assert_eq!(
            flags(&set),
            Some((libc::NFT_SET_ANONYMOUS | libc::NFT_SET_CONSTANT) as u32)
        );
    }

    #[test]
    fn new_named_omits_anonymous_flags() {
        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let set = Set::<Ipv4Addr>::new_named(c"test", 1, &table, ProtoFamily::Ipv4);

        assert_eq!(flags(&set), None);
    }

    #[test]
    fn flush_writes_delsetelem_message() {
        use crate::NlMsg;

        let table = Table::new(c"filter", ProtoFamily::Ipv4);
        let set = Set::<Ipv4Addr>::new_named(c"test_set", 1, &table, ProtoFamily::Ipv4);
        let flush = set.flush();

        let mut buf = vec![0u8; crate::nft_nlmsg_maxsize() as usize];
        unsafe {
            flush.write(buf.as_mut_ptr().cast(), 1, MsgType::Del);
        }

        let header = buf.as_ptr().cast::<libc::nlmsghdr>();
        let nlmsg_type = unsafe { (*header).nlmsg_type };
        let expected_type =
            ((libc::NFNL_SUBSYS_NFTABLES as u16) << 8) | (libc::NFT_MSG_DELSETELEM as u16);
        assert_eq!(nlmsg_type, expected_type);
    }

    fn flags<K>(set: &Set<'_, K>) -> Option<u32> {
        unsafe {
            sys::nftnl_set_is_set(set.as_ptr().as_ptr(), sys::NFTNL_SET_FLAGS as u16)
                .then(|| sys::nftnl_set_get_u32(set.as_ptr().as_ptr(), sys::NFTNL_SET_FLAGS as u16))
        }
    }
}
