use crate::{MsgType, ProtoFamily};
use nftnl_sys::{
    self as sys,
    libc::{self, c_void},
};
use std::{
    collections::HashSet,
    ffi::{CStr, CString},
};


/// Abstraction of `nftnl_table`. The top level container in netfilter. A table has a protocol
/// family and contain [`Chain`]s that in turn hold the rules.
///
/// [`Chain`]: struct.Chain.html
pub struct Table {
    table: *mut sys::nftnl_table,
    family: ProtoFamily,
}

impl Table {
    /// Creates a new table instance with the given name and protocol family.
    pub fn new<T: AsRef<CStr>>(name: &T, family: ProtoFamily) -> Table {
        unsafe {
            let table = try_alloc!(sys::nftnl_table_alloc());

            sys::nftnl_table_set_u32(table, sys::NFTNL_TABLE_FAMILY as u16, family as u32);
            sys::nftnl_table_set_str(table, sys::NFTNL_TABLE_NAME as u16, name.as_ref().as_ptr());
            sys::nftnl_table_set_u32(table, sys::NFTNL_TABLE_FLAGS as u16, 0u32);
            Table { table, family }
        }
    }

    /// Returns the name of this table.
    pub fn get_name(&self) -> &CStr {
        unsafe {
            let ptr = sys::nftnl_table_get_str(self.table, sys::NFTNL_TABLE_NAME as u16);
            CStr::from_ptr(ptr)
        }
    }

    /// Returns the protocol family for this table.
    pub fn get_family(&self) -> ProtoFamily {
        self.family
    }
}

unsafe impl crate::NlMsg for Table {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let raw_msg_type = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWTABLE,
            MsgType::Del => libc::NFT_MSG_DELTABLE,
        };
        let header = sys::nftnl_nlmsg_build_hdr(
            buf as *mut i8,
            raw_msg_type as u16,
            self.family as u16,
            libc::NLM_F_ACK as u16,
            seq,
        );
        sys::nftnl_table_nlmsg_build_payload(header, self.table);
    }
}

impl Drop for Table {
    fn drop(&mut self) {
        unsafe { sys::nftnl_table_free(self.table) };
    }
}

/// Returns a buffer containing a netlink message which requests a list of all the netfilter
/// tables that are currently set.
pub fn get_tables_nlmsg(seq: u32) -> Vec<u8> {
    let mut buffer = vec![0; crate::nft_nlmsg_maxsize() as usize];
    let _ = unsafe {
        sys::nftnl_nlmsg_build_hdr(
            buffer.as_mut_ptr() as *mut i8,
            libc::NFT_MSG_GETTABLE as u16,
            ProtoFamily::Unspec as u16,
            (libc::NLM_F_ROOT | libc::NLM_F_MATCH) as u16,
            seq,
        )
    };
    buffer
}

/// A callback to parse the response for messages created with `get_tables_nlmsg`. This callback
/// extracts a set of applied table names.
pub fn get_tables_cb(header: &libc::nlmsghdr, tables: &mut HashSet<CString>) -> libc::c_int {
    unsafe {
        let nf_table = sys::nftnl_table_alloc();
        let err = sys::nftnl_table_nlmsg_parse(header, nf_table);
        if err < 0 {
            error!("Failed to parse nelink table message - {}", err);
            return err;
        }
        let table_name = CStr::from_ptr(sys::nftnl_table_get_str(
            nf_table,
            sys::NFTNL_TABLE_NAME as u16,
        ))
        .to_owned();
        tables.insert(table_name);
    };
    return 1;
}
