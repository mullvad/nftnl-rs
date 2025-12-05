use crate::util::KERNEL_VERSION;
use crate::{MsgType, NlMsg};
use core::fmt;
use nftnl_sys::{self as sys, libc};
use nix::libc::{NLM_F_ACK, nlmsghdr};
use std::ffi::c_void;
use std::ops::Range;
use std::os::raw::c_char;
use std::ptr;
use std::sync::LazyLock;

/// Error while communicating with netlink
#[derive(Debug)]
pub struct NetlinkError(());

impl fmt::Display for NetlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        "Error while communicating with netlink".fmt(f)
    }
}

/// Whether we should set `F_ACK` for batch start/end messages.
pub static ACK_BATCH_END_MESSAGES: LazyLock<bool> = LazyLock::new(|| {
    let Some(kernel_version) = *KERNEL_VERSION else {
        if cfg!(debug_assertions) {
            panic!("Failed to parse kernel version");
        } else {
            return true;
        }
    };

    // The kernel didn't respect the F_ACK flag for netlink nft batch messages until 6.10
    kernel_version >= (6, 10)
});

impl std::error::Error for NetlinkError {}

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
    batch: ptr::NonNull<sys::nftnl_batch>,

    /// The range of sequence numbers assigned to the messages in this batch.
    seqs: Range<u32>,
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
    ///
    /// # Panics
    /// Panics if `batch_page_size + nft_nlmsg_maxsize` would overflow.
    pub fn with_page_size(batch_page_size: u32) -> Self {
        batch_page_size
            .checked_add(crate::nft_nlmsg_maxsize())
            .expect("batch_page_size is too large and would overflow");

        let batch = try_alloc!(unsafe {
            sys::nftnl_batch_alloc(batch_page_size, crate::nft_nlmsg_maxsize())
        });
        let mut this = Batch { batch, seqs: 1..1 };
        this.write_begin_msg();
        this
    }

    /// Adds the given message to this batch.
    pub fn add<T: NlMsg>(&mut self, msg: &T, msg_type: MsgType) {
        trace!("Writing NlMsg with seq {} to batch", self.seqs.end);
        unsafe { msg.write(self.current(), self.seqs.end, msg_type) };
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
        unsafe { sys::nftnl_batch_buffer(self.batch.as_ptr()) }
    }

    fn next(&mut self) {
        if unsafe { sys::nftnl_batch_update(self.batch.as_ptr()) } < 0 {
            // See try_alloc definition.
            std::process::abort();
        }
        self.seqs.end += 1;
    }

    fn write_begin_msg(&mut self) {
        unsafe { self.write_begin_or_end_msg(sys::nftnl_batch_begin) }
    }

    fn write_end_msg(&mut self) {
        unsafe { self.write_begin_or_end_msg(sys::nftnl_batch_end) }
    }

    unsafe fn write_begin_or_end_msg(
        &mut self,
        f: unsafe extern "C" fn(*mut c_char, u32) -> *mut nlmsghdr,
    ) {
        let buf_ptr = self.current().cast::<c_char>();

        // We only set F_ACK (and a sequence number) if the kernel supports it.
        let kernel_supports_ack = *ACK_BATCH_END_MESSAGES;
        let seq = kernel_supports_ack.then_some(self.seqs.end).unwrap_or(0);

        // Construct the header
        let header = unsafe { f(buf_ptr, seq) };

        // Raise F_ACK
        if kernel_supports_ack {
            unsafe { set_f_ack(header) };
            self.seqs.end += 1;
        }

        if unsafe { sys::nftnl_batch_update(self.batch.as_ptr()) } < 0 {
            // See try_alloc definition.
            std::process::abort();
        }
    }

    /// Returns the underlying `nftnl_batch` instance.
    pub fn as_raw_batch(&self) -> ptr::NonNull<sys::nftnl_batch> {
        self.batch
    }
}

/// Set the [`NLM_F_ACK`] flag on the netlink message.
unsafe fn set_f_ack(header: *mut libc::nlmsghdr) {
    let mut header = ptr::NonNull::new(header).expect("nlmsg_build_hdr never returns null");
    unsafe { header.as_mut() }.nlmsg_flags |= NLM_F_ACK as u16;
}

impl Drop for Batch {
    fn drop(&mut self) {
        unsafe { sys::nftnl_batch_free(self.batch.as_ptr()) };
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
        let num_pages = unsafe { sys::nftnl_batch_iovec_len(self.batch.batch.as_ptr()) as usize };
        let mut iovecs = vec![
            libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            num_pages
        ];
        let iovecs_ptr = iovecs.as_mut_ptr();
        unsafe {
            sys::nftnl_batch_iovec(self.batch.batch.as_ptr(), iovecs_ptr, num_pages as u32);
        }
        Iter {
            iovecs: iovecs.into_iter(),
            _marker: ::std::marker::PhantomData,
        }
    }

    /// Returns the range of sequence numbers for the messages in this batch that expect an ACK.
    pub fn sequence_numbers(&self) -> Range<u32> {
        self.batch.seqs.clone()
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
unsafe impl Send for Iter<'_> {}
unsafe impl Sync for Iter<'_> {}

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
