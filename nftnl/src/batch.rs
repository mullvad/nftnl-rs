use libc;
use nftnl_sys::{self as sys, c_void};

use std::ptr;
use {ErrorKind, MsgType, NlMsg, Result};

/// Check if the kernel supports batched netlink messages to netfilter.
pub fn batch_is_supported() -> Result<bool> {
    match unsafe { sys::nftnl_batch_is_supported() } {
        1 => Ok(true),
        0 => Ok(false),
        _ => bail!(ErrorKind::NetlinkError),
    }
}

pub struct Batch {
    batch: *mut sys::nftnl_batch,
    seq: u32,
}

impl Batch {
    /// Creates a new nftnl batch with the [default page size]
    ///
    /// [default page size]: fn.default_batch_page_size.html
    pub fn new() -> Result<Self> {
        Self::with_page_size(default_batch_page_size())
    }

    pub fn with_page_size(batch_page_size: u32) -> Result<Self> {
        let batch = unsafe { sys::nftnl_batch_alloc(batch_page_size, ::nft_nlmsg_maxsize()) };
        ensure!(!batch.is_null(), ErrorKind::AllocationError);
        let mut this = Batch { batch, seq: 1 };
        this.write_begin_msg()?;
        Ok(this)
    }

    pub fn add<T: NlMsg>(&mut self, msg: &T, msg_type: MsgType) -> Result<()> {
        trace!("Writing NlMsg with seq {} to batch", self.seq);
        unsafe { msg.write(self.current(), self.seq, msg_type) };
        self.next()
    }

    pub fn add_iter<T, I>(&mut self, msg_iter: I, msg_type: MsgType) -> Result<()>
    where
        T: NlMsg,
        I: Iterator<Item = T>,
    {
        for msg in msg_iter {
            self.add(&msg, msg_type)?;
        }
        Ok(())
    }

    pub fn finalize(mut self) -> Result<FinalizedBatch> {
        self.write_end_msg()?;
        Ok(FinalizedBatch { batch: self })
    }

    fn current(&self) -> *mut c_void {
        unsafe { sys::nftnl_batch_buffer(self.batch) }
    }

    fn next(&mut self) -> Result<()> {
        if unsafe { sys::nftnl_batch_update(self.batch) } < 0 {
            bail!(ErrorKind::AllocationError);
        }
        self.seq += 1;
        Ok(())
    }

    fn write_begin_msg(&mut self) -> Result<()> {
        unsafe { sys::nftnl_batch_begin(self.current() as *mut i8, self.seq) };
        self.next()
    }

    fn write_end_msg(&mut self) -> Result<()> {
        unsafe { sys::nftnl_batch_end(self.current() as *mut i8, self.seq) };
        self.next()
    }

    pub fn as_raw_batch(&self) -> *mut sys::nftnl_batch {
        self.batch
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        unsafe { sys::nftnl_batch_free(self.batch) };
    }
}

pub struct FinalizedBatch {
    batch: Batch,
}

impl FinalizedBatch {
    pub fn iter<'a>(&'a self) -> Iter<'a> {
        let num_pages = unsafe { sys::nftnl_batch_iovec_len(self.batch.as_raw_batch()) as usize };
        let mut iovecs = vec![
            libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            num_pages
        ];
        let iovecs_ptr = iovecs.as_mut_ptr() as *mut sys::iovec;
        unsafe {
            sys::nftnl_batch_iovec(self.batch.as_raw_batch(), iovecs_ptr, num_pages as u32);
        }
        Iter {
            iovecs: iovecs.into_iter(),
            _marker: ::std::marker::PhantomData,
        }
    }
}

impl<'a> IntoIterator for &'a FinalizedBatch {
    type Item = &'a [u8];
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

pub struct Iter<'a> {
    iovecs: ::std::vec::IntoIter<libc::iovec>,
    _marker: ::std::marker::PhantomData<&'a ()>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        self.iovecs.next().map(|iovec| unsafe {
            ::std::slice::from_raw_parts(iovec.iov_base as *const u8, iovec.iov_len)
        })
    }
}

/// selected batch page is 256 Kbytes long to load ruleset of
/// half a million rules without hitting -EMSGSIZE due to large
/// iovec.
pub fn default_batch_page_size() -> u32 {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u32 * 32 }
}
