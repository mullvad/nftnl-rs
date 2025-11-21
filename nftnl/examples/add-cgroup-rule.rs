//! Adds a table, two chains and some rules to netfilter.
//!
//! This example uses `verdict accept` everywhere. So even after running this the firewall won't
//! block anything. This is so anyone trying to run this does not end up in a strange state
//! where they don't understand why their network is broken. Try changing to `verdict drop` if
//! you want to see the block working.
//!
//! Run the following to print out current active tables, chains and rules in netfilter. Must be
//! executed as root:
//! ```bash
//! # nft list ruleset
//! ```
//! After running this example, the output should be the following:
//! ```ignore
//! table inet example-table {
//!         chain chain-for-outgoing-packets {
//!                 type filter hook output priority 0; policy accept;
//!                 ip daddr 10.1.0.0/24 counter packets 0 bytes 0 accept
//!         }
//!
//!         chain chain-for-incoming-packets {
//!                 type filter hook input priority 0; policy accept;
//!                 iif "lo" accept
//!         }
//! }
//! ```
//!
//! Try pinging any IP in the network range denoted by the outgoing rule and see the counter
//! increment:
//! ```bash
//! $ ping 10.1.0.7
//! ```
//!
//! Everything created by this example can be removed by running
//! ```bash
//! # nft delete table inet example-table
//! ```
#![cfg(socketexpr)]

use nftnl::{Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table, nft_expr, nftnl_sys::libc};
use std::{ffi::CStr, fs, io, os::unix::fs::MetadataExt as _};

const TABLE_NAME: &CStr = c"example-table";
const OUT_CHAIN_NAME: &CStr = c"block-outgoing-from-my-cgroup";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a batch. This is used to store all the netlink messages we will later send.
    // Creating a new batch also automatically writes the initial batch begin message needed
    // to tell netlink this is a single transaction that might arrive over multiple netlink packets.
    let mut batch = Batch::new();

    // Create a netfilter table operating on both IPv4 and IPv6 (ProtoFamily::Inet)
    let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
    // Add the table to the batch with the `MsgType::Add` type, thus instructing netfilter to add
    // this table under its `ProtoFamily::Inet` ruleset.
    batch.add(&table, nftnl::MsgType::Add);

    // Create output chains under the table we created above.
    let mut out_chain = Chain::new(OUT_CHAIN_NAME, &table);

    // Hook the chain to the output event hook, with highest priority (priority zero).
    // See the `Chain::set_hook` documentation for details.
    out_chain.set_hook(nftnl::Hook::Out, 0);

    // Set the default policies on the chains. If no rule matches a packet processed by the
    // chain, it will accept the packet.
    out_chain.set_policy(nftnl::Policy::Accept);

    // Add the two chains to the batch with the `MsgType` to tell netfilter to create the chains
    // under the table.
    batch.add(&out_chain, nftnl::MsgType::Add);

    // === ADD CGROUPV2 RULE  ===

    // Create a new rule object under the input chain.
    let mut cgroup_rule = Rule::new(&out_chain);

    let cgroup_path = "/sys/fs/cgroup/my_cgroup";
    let cgroup_meta = fs::metadata(cgroup_path).expect("cgroup does not exist");
    let cgroup_ino = cgroup_meta.ino();

    cgroup_rule.add_expr(&nft_expr!(socket cgroupv2 level 1));
    cgroup_rule.add_expr(&nft_expr!(cmp == cgroup_ino)); // inode of cgroup dir
    cgroup_rule.add_expr(&nft_expr!(verdict drop));

    // Add the rule to the batch.
    batch.add(&cgroup_rule, nftnl::MsgType::Add);

    // === FINALIZE THE TRANSACTION AND SEND THE DATA TO NETFILTER ===

    // Finalize the batch. This means the batch end message is written into the batch, telling
    // netfilter the we reached the end of the transaction message. It's also converted to a type
    // that implements `IntoIterator<Item = &'a [u8]>`, thus allowing us to get the raw netlink data
    // out so it can be sent over a netlink socket to netfilter.
    let finalized_batch = batch.finalize();

    // Send the entire batch and process any returned messages.
    send_and_process(&finalized_batch)?;
    Ok(())
}

// Look up the interface index for a given interface name.
fn iface_index(name: &CStr) -> io::Result<libc::c_uint> {
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

fn send_and_process(batch: &FinalizedBatch) -> io::Result<()> {
    // Create a netlink socket to netfilter.
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    let portid = socket.portid();

    // Send all the bytes in the batch.
    socket.send_all(batch)?;

    // TODO: this buffer must be aligned to nlmsghdr
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected_seqs = batch.sequence_numbers();

    // Process acknowledgment messages from netfilter.
    while !expected_seqs.is_empty() {
        for message in socket.recv(&mut buffer[..])? {
            let message = message?;
            let expected_seq = expected_seqs.next().expect("Unexpected ACK");
            // Validate sequence number and check for error messages
            mnl::cb_run(message, expected_seq, portid)
                .inspect_err(|e| println!("message {expected_seq} errored"))?;
        }
    }
    Ok(())
}
