//! Adds a table, an ingress chain and some rules to netfilter.
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
//!         chain chain-for-ingress {
//!                 type filter hook ingress priority -450; policy accept;
//!                 ip saddr 127.0.0.1 counter packets 0 bytes 0 accept
//!         }
//! }
//! ```
//!
//! Try pinging any IP in the network range denoted by the outgoing rule and see the counter
//! increment:
//! ```bash
//! $ ping 127.0.0.2
//! ```
//!
//! Everything created by this example can be removed by running
//! ```bash
//! # nft delete table inet example-table
//! ```

use nftnl::{
    Batch, Chain, ChainType, FinalizedBatch, Policy, ProtoFamily, Rule, Table, nft_expr,
    nftnl_sys::libc,
};
use std::{ffi::CStr, io, net::Ipv4Addr};

const TABLE_NAME: &CStr = c"example-table";
const CHAIN_NAME: &CStr = c"chain-for-ingress";

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

    // Create input and output chains under the table we created above.
    let mut chain = Chain::new(CHAIN_NAME, &table);

    // Hook the chain to the input and output event hooks, with highest priority (priority zero).
    // See the `Chain::set_hook` documentation for details.
    chain.set_hook(nftnl::Hook::Ingress, -450); // -450 priority places this chain before any conntrack or defragmentation

    // Setting the chain type to filter is not necessary, as it is the default type.
    chain.set_type(ChainType::Filter);

    // Ingress hooks need a device to bind to.
    chain.set_device(c"lo");

    // Set the default policies on the chains. If no rule matches a packet processed by the
    // `out_chain` or the `in_chain` it will accept the packet.
    chain.set_policy(Policy::Accept);

    // Add the two chains to the batch with the `MsgType` to tell netfilter to create the chains
    // under the table.
    batch.add(&chain, nftnl::MsgType::Add);

    // === ADD A RULE ALLOWING (AND COUNTING) ALL PACKETS FROM THE 127.0.0.1 IP ADDRESS ===

    let mut rule = Rule::new(&chain);
    let local_ip = Ipv4Addr::new(127, 0, 0, 1);

    // Load the `nfproto` metadata into the netfilter register. This metadata denotes which layer3
    // protocol the packet being processed is using.
    rule.add_expr(&nft_expr!(meta nfproto));
    // Check if the currently processed packet is an IPv4 packet. This must be done before payload
    // data assuming the packet uses IPv4 can be loaded in the next expression.
    rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));

    // Load the IPv4 destination address into the netfilter register.
    rule.add_expr(&nft_expr!(payload ipv4 saddr));
    // Compare the register with the IP we are interested in.
    rule.add_expr(&nft_expr!(cmp == local_ip));

    // Add a packet counter to the rule. Shows how many packets have been evaluated against this
    // expression. Since expressions are evaluated from first to last, putting this counter before
    // the above IP net check would make the counter increment on all packets also *not* matching
    // those expressions. Because the counter would then be evaluated before it fails a check.
    // Similarly, if the counter was added after the verdict it would always remain at zero. Since
    // when the packet hits the verdict expression any further processing of expressions stop.
    rule.add_expr(&nft_expr!(counter));

    // Accept all the packets matching the rule so far.
    rule.add_expr(&nft_expr!(verdict accept));

    // Add the rule to the batch. Without this nothing would be sent over netlink and netfilter,
    // and all the work on `block_out_to_private_net_rule` so far would go to waste.
    batch.add(&rule, nftnl::MsgType::Add);

    // === FINALIZE THE TRANSACTION AND SEND THE DATA TO NETFILTER ===

    // Finalize the batch. This means the batch end message is written into the batch, telling
    // netfilter that we reached the end of the transaction message. It's also converted to a type
    // that implements `IntoIterator<Item = &'a [u8]>`, thus allowing us to get the raw netlink data
    // out so it can be sent over a netlink socket to netfilter.
    let finalized_batch = batch.finalize();

    // Send the entire batch and process any returned messages.
    send_and_process(&finalized_batch)?;
    Ok(())
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
            mnl::cb_run(message, expected_seq, portid)?;
        }
    }
    Ok(())
}
