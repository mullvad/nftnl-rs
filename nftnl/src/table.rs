use libc;
use nftnl_sys::{self as sys, c_void};

use std::ffi::CStr;

use {ErrorKind, MsgType, ProtoFamily, Result};


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
    pub fn new<T: AsRef<CStr>>(name: &T, family: ProtoFamily) -> Result<Table> {
        unsafe {
            let table = sys::nftnl_table_alloc();
            if table.is_null() {
                bail!(ErrorKind::AllocationError);
            }

            sys::nftnl_table_set_str(table, sys::NFTNL_TABLE_NAME as u16, name.as_ref().as_ptr());
            sys::nftnl_table_set_u32(table, sys::NFTNL_TABLE_FAMILY as u16, family as u32);
            Ok(Table { table, family })
        }
    }

    pub fn get_name(&self) -> &CStr {
        unsafe {
            let ptr = sys::nftnl_table_get_str(self.table, sys::NFTNL_TABLE_NAME as u16);
            CStr::from_ptr(ptr)
        }
    }

    pub fn get_family(&self) -> ProtoFamily {
        self.family
    }
}

unsafe impl ::NlMsg for Table {
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
