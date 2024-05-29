use crate::{MsgType, NlMsg};
use nftnl_sys::{self as sys, libc};
use std::ffi::c_void;
use std::os::raw::c_char;
use std::ptr;

/// Error while communicating with netlink
#[derive(err_derive::Error, Debug)]
#[error(display = "Error while communicating with netlink")]
pub struct NetlinkError(());

/// Check if the kernel supports batched netlink messages to netfilter.
pub fn batch_is_supported() -> std::result::Result<bool, NetlinkError> {
    match unsafe { sys::nftnl_batch_is_supported() } {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(NetlinkError(())),
    }
}

/// A batch of netfilter messages to be performed in one atomic operation. Corresponds to
/// `nftnl_batch` in libnftnl.
pub struct Batch {
    batch: *mut sys::nftnl_batch,
    seq: u32,
}

// Safety: It should be safe to pass this around and *read* from it
// from multiple threads
unsafe impl Send for Batch {}
unsafe impl Sync for Batch {}

impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}

impl Batch {
    /// Creates a new nftnl batch with the [default page size].
    ///
    /// [default page size]: fn.default_batch_page_size.html
    pub fn new() -> Self {
        Self::with_page_size(default_batch_page_size())
    }

    /// Creates a new nftnl batch with the given batch size.
    pub fn with_page_size(batch_page_size: u32) -> Self {
        let batch = try_alloc!(unsafe {
            sys::nftnl_batch_alloc(batch_page_size, crate::nft_nlmsg_maxsize())
        });
        let mut this = Batch { batch, seq: 1 };
        this.write_begin_msg();
        this
    }

    /// Adds the given message to this batch.
    pub fn add<T: NlMsg>(&mut self, msg: &T, msg_type: MsgType) {
        trace!("Writing NlMsg with seq {} to batch", self.seq);
        unsafe { msg.write(self.current(), self.seq, msg_type) };
        self.next()
    }

    /// Adds all the messages in the given iterator to this batch. If any message fails to be added
    /// the error for that failure is returned and all messages up until that message stays added
    /// to the batch.
    pub fn add_iter<T, I>(&mut self, msg_iter: I, msg_type: MsgType)
    where
        T: NlMsg,
        I: Iterator<Item = T>,
    {
        for msg in msg_iter {
            self.add(&msg, msg_type);
        }
    }

    /// Adds the final end message to the batch and returns a [`FinalizedBatch`] that can be used
    /// to send the messages to netfilter.
    ///
    /// [`FinalizedBatch`]: struct.FinalizedBatch.html
    pub fn finalize(mut self) -> FinalizedBatch {
        self.write_end_msg();
        FinalizedBatch { batch: self }
    }

    fn current(&self) -> *mut c_void {
        unsafe { sys::nftnl_batch_buffer(self.batch) }
    }

    fn next(&mut self) {
        if unsafe { sys::nftnl_batch_update(self.batch) } < 0 {
            // See try_alloc definition.
            std::process::abort();
        }
        self.seq += 1;
    }

    fn write_begin_msg(&mut self) {
        unsafe { sys::nftnl_batch_begin(self.current() as *mut c_char, self.seq) };
        self.next();
    }

    fn write_end_msg(&mut self) {
        unsafe { sys::nftnl_batch_end(self.current() as *mut c_char, self.seq) };
        self.next();
    }

    /// Returns the underlying `nftnl_batch` instance.
    pub fn as_raw_batch(&self) -> *mut sys::nftnl_batch {
        self.batch
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        unsafe { sys::nftnl_batch_free(self.batch) };
    }
}

/// A wrapper over [`Batch`], guaranteed to start with a proper batch begin and end with a proper
/// batch end message. Created from [`Batch::finalize`].
///
/// Can be turned into an iterator of the byte buffers to send to netlink to execute this batch.
///
/// [`Batch`]: struct.Batch.html
/// [`Batch::finalize`]: struct.Batch.html#method.finalize
pub struct FinalizedBatch {
    batch: Batch,
}

impl FinalizedBatch {
    /// Returns the iterator over byte buffers to send to netlink.
    pub fn iter(&self) -> Iter<'_> {
        let num_pages = unsafe { sys::nftnl_batch_iovec_len(self.batch.as_raw_batch()) as usize };
        let mut iovecs = vec![
            libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            num_pages
        ];
        let iovecs_ptr = iovecs.as_mut_ptr();
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

// Safety: It should be safe to pass this around and *read* from it
// from multiple threads.
unsafe impl<'a> Send for Iter<'a> {}
unsafe impl<'a> Sync for Iter<'a> {}

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
