//! Adds a table containing a named IPv4 set.
//!
//! Run this example as root, then use `nft list table ip filter` to inspect the result.
//! The table can be removed with `nft delete table ip filter`.

use nftnl::{Batch, FinalizedBatch, MsgType, ProtoFamily, Table, set::Set};
use std::{io, net::Ipv4Addr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut batch = Batch::new();
    let table = Table::new(c"filter", ProtoFamily::Ipv4);
    batch.add(&table, MsgType::Add);

    let mut set: Set<Ipv4Addr> = Set::new_named(c"test_v4", 1, &table, ProtoFamily::Ipv4);
    set.add(&Ipv4Addr::new(1, 2, 3, 4));
    batch.add(&set, MsgType::Add);
    batch.add_iter(set.elems_iter(), MsgType::Add);

    send_and_process(&batch.finalize())?;
    Ok(())
}

fn send_and_process(batch: &FinalizedBatch) -> io::Result<()> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    let portid = socket.portid();
    socket.send_all(batch)?;

    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected_seqs = batch.sequence_numbers();
    while !expected_seqs.is_empty() {
        for message in socket.recv(&mut buffer[..])? {
            let message = message?;
            let expected_seq = expected_seqs.next().expect("Unexpected ACK");
            mnl::cb_run(message, expected_seq, portid)?;
        }
    }
    Ok(())
}
