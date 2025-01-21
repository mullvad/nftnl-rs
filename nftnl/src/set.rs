use crate::{table::Table, MsgType, ProtoFamily};
use nftnl_sys::{self as sys, libc};
use std::{
    cell::Cell,
    ffi::{c_void, CStr},
    net::{Ipv4Addr, Ipv6Addr},
    os::raw::c_char,
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
    set: *mut sys::nftnl_set,
    table: &'a Table,
    family: ProtoFamily,
    _marker: ::std::marker::PhantomData<K>,
}

impl<'a, K> Set<'a, K> {
    pub fn new(name: &CStr, id: u32, table: &'a Table, family: ProtoFamily) -> Self
    where
        K: SetKey,
    {
        unsafe {
            let set = try_alloc!(sys::nftnl_set_alloc());

            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_FAMILY as u16, family as u32);
            sys::nftnl_set_set_str(set, sys::NFTNL_SET_TABLE as u16, table.get_name().as_ptr());
            sys::nftnl_set_set_str(set, sys::NFTNL_SET_NAME as u16, name.as_ptr());
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_ID as u16, id);

            sys::nftnl_set_set_u32(
                set,
                sys::NFTNL_SET_FLAGS as u16,
                (libc::NFT_SET_ANONYMOUS | libc::NFT_SET_CONSTANT) as u32,
            );
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_KEY_TYPE as u16, K::TYPE);
            sys::nftnl_set_set_u32(set, sys::NFTNL_SET_KEY_LEN as u16, K::LEN);

            Set {
                set,
                table,
                family,
                _marker: ::std::marker::PhantomData,
            }
        }
    }

    pub fn add(&mut self, key: &K)
    where
        K: SetKey,
    {
        unsafe {
            let elem = try_alloc!(sys::nftnl_set_elem_alloc());

            let data = key.data();
            let data_len = data.len() as u32;
            trace!("Adding key {:?} with len {}", data, data_len);
            sys::nftnl_set_elem_set(
                elem,
                sys::NFTNL_SET_ELEM_KEY as u16,
                data.as_ref() as *const _ as *const c_void,
                data_len,
            );
            sys::nftnl_set_elem_add(self.set, elem);
        }
    }

    pub fn elems_iter(&'a self) -> SetElemsIter<'a, K> {
        SetElemsIter::new(self)
    }

    pub fn as_ptr(&self) -> *mut sys::nftnl_set {
        self.set
    }

    pub fn get_family(&self) -> ProtoFamily {
        self.family
    }

    pub fn get_name(&self) -> &CStr {
        unsafe {
            let ptr = sys::nftnl_set_get_str(self.set, sys::NFTNL_SET_NAME as u16);
            CStr::from_ptr(ptr)
        }
    }

    pub fn get_id(&self) -> u32 {
        unsafe { sys::nftnl_set_get_u32(self.set, sys::NFTNL_SET_ID as u16) }
    }
}

unsafe impl<K> crate::NlMsg for Set<'_, K> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let type_ = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWSET,
            MsgType::Del => libc::NFT_MSG_DELSET,
        };
        let header = sys::nftnl_nlmsg_build_hdr(
            buf as *mut c_char,
            type_ as u16,
            self.table.get_family() as u16,
            (libc::NLM_F_APPEND | libc::NLM_F_CREATE | libc::NLM_F_ACK) as u16,
            seq,
        );
        sys::nftnl_set_nlmsg_build_payload(header, self.set);
    }
}

impl<K> Drop for Set<'_, K> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_set_free(self.set) };
    }
}

pub struct SetElemsIter<'a, K> {
    set: &'a Set<'a, K>,
    iter: *mut sys::nftnl_set_elems_iter,
    ret: Rc<Cell<i32>>,
}

impl<'a, K> SetElemsIter<'a, K> {
    fn new(set: &'a Set<'a, K>) -> Self {
        let iter = try_alloc!(unsafe { sys::nftnl_set_elems_iter_create(set.as_ptr()) });
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
        if self.ret.get() <= 0 || unsafe { sys::nftnl_set_elems_iter_cur(self.iter).is_null() } {
            trace!("SetElemsIter iterator ending");
            None
        } else {
            trace!("SetElemsIter returning new SetElemsMsg");
            Some(SetElemsMsg {
                set: self.set,
                iter: self.iter,
                ret: self.ret.clone(),
            })
        }
    }
}

impl<K> Drop for SetElemsIter<'_, K> {
    fn drop(&mut self) {
        unsafe { sys::nftnl_set_elems_iter_destroy(self.iter) };
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
        let header = sys::nftnl_nlmsg_build_hdr(
            buf as *mut c_char,
            type_ as u16,
            self.set.get_family() as u16,
            flags as u16,
            seq,
        );
        self.ret.set(sys::nftnl_set_elems_nlmsg_build_payload_iter(
            header, self.iter,
        ));
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
