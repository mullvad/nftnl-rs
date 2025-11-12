//! Adds a table, chain and a rule that blocks all traffic to a given MAC address
//!
//! Run the following to print out current active tables, chains and rules in netfilter. Must be
//! executed as root:
//! ```bash
//! # nft list ruleset
//! ```
//! After running this example, the output should be the following:
//! ```ignore
//! table inet example-filter-ethernet {
//!         chain chain-for-outgoing-packets {
//!                 type filter hook output priority 3; policy accept;
//!                 ether daddr 00:00:00:00:00:00 drop
//!                 counter packets 0 bytes 0 meta random > 2147483647 counter packets 0 bytes 0
//!         }
//! }
//! ```
//!
//!
//! Everything created by this example can be removed by running
//! ```bash
//! # nft delete table inet example-filter-ethernet
//! ```

use nftnl::{Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table, nft_expr, nftnl_sys::libc};
use std::{ffi::CStr, io};

const TABLE_NAME: &CStr = c"example-filter-ethernet";
const OUT_CHAIN_NAME: &CStr = c"chain-for-outgoing-packets";

const BLOCK_THIS_MAC: &[u8] = &[0, 0, 0, 0, 0, 0];

fn main() -> io::Result<()> {
    // For verbose explanations of what all these lines up until the rule creation does, see the
    // `add-rules` example.
    let mut batch = Batch::new();
    let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
    batch.add(&table, nftnl::MsgType::Add);

    let mut out_chain = Chain::new(OUT_CHAIN_NAME, &table);
    out_chain.set_hook(nftnl::Hook::Out, 3);
    out_chain.set_policy(nftnl::Policy::Accept);
    batch.add(&out_chain, nftnl::MsgType::Add);

    // === ADD RULE DROPPING ALL TRAFFIC TO THE MAC ADDRESS IN `BLOCK_THIS_MAC` ===

    let mut block_ethernet_rule = Rule::new(&out_chain);

    // Check that the interface type is an ethernet interface. Must be done before we can check
    // payload values in the ethernet header.
    block_ethernet_rule.add_expr(&nft_expr!(meta iiftype));
    block_ethernet_rule.add_expr(&nft_expr!(cmp == libc::ARPHRD_ETHER));

    // Compare the ethernet destination address against the MAC address we want to drop
    block_ethernet_rule.add_expr(&nft_expr!(payload ethernet daddr));
    block_ethernet_rule.add_expr(&nft_expr!(cmp == BLOCK_THIS_MAC));

    // Drop the matching packets.
    block_ethernet_rule.add_expr(&nft_expr!(verdict drop));

    batch.add(&block_ethernet_rule, nftnl::MsgType::Add);

    // === FOR FUN, ADD A PACKET THAT MATCHES 50% OF ALL PACKETS ===

    // This packet has a counter before and after the check that has 50% chance of matching.
    // So after a number of packets has passed through this rule, the first counter should have a
    // value approximately double that of the second counter. This rule has no verdict, so it never
    // does anything with the matching packets.
    let mut random_rule = Rule::new(&out_chain);
    // This counter expression will be evaluated (and increment the counter) for all packets coming
    // through.
    random_rule.add_expr(&nft_expr!(counter));

    // Load a pseudo-random 32 bit unsigned integer into the netfilter register.
    random_rule.add_expr(&nft_expr!(meta random));
    // Check if the random integer is larger than `u32::MAX/2`, thus having 50% chance of success.
    random_rule.add_expr(&nft_expr!(cmp > (u32::MAX / 2).to_be()));

    // Add a second counter. This will only be incremented for the packets passing the random check.
    random_rule.add_expr(&nft_expr!(counter));

    batch.add(&random_rule, nftnl::MsgType::Add);

    // === FINALIZE THE TRANSACTION AND SEND THE DATA TO NETFILTER ===

    let finalized_batch = batch.finalize();
    send_and_process(&finalized_batch)?;
    Ok(())
}

fn send_and_process(batch: &FinalizedBatch) -> io::Result<()> {
    // Create a netlink socket to netfilter.
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    // Send all the bytes in the batch.
    socket.send_all(batch)?;

    // Try to parse the messages coming back from netfilter. This part is still very unclear.
    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let very_unclear_what_this_is_for = 2;
    while let Some(message) = socket_recv(&socket, &mut buffer[..])? {
        match mnl::cb_run(message, very_unclear_what_this_is_for, portid)? {
            mnl::CbResult::Stop => {
                break;
            }
            mnl::CbResult::Ok => (),
        }
    }
    Ok(())
}

fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> io::Result<Option<&'a [u8]>> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}
