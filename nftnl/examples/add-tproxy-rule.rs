//! Sets up a transparent proxy (TPROXY) rule in an inet table.
//!
//! Run this example as root, then use `nft list ruleset` to inspect the result.
//! After running this example, the output should be:
//! ```ignore
//! table inet example-table {
//!     chain prerouting {
//!         type filter hook prerouting priority -150; policy accept;
//!         tcp dport 80 tproxy to :1234
//!     }
//! }
//! ```
//! The table can be removed with `nft delete table inet example-table`.

use nftnl::{
    Batch, Chain, ChainType, FinalizedBatch, Hook, MsgType, Policy, ProtoFamily, Rule, Table,
    expr::{CmpOp, Immediate, Meta, Register},
    nft_expr,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut batch = Batch::new();

    let table = Table::new(c"example-table", ProtoFamily::Inet);
    batch.add(&table, MsgType::Add);

    let mut chain = Chain::new(c"prerouting", &table);
    chain.set_hook(Hook::PreRouting, -150); // mangle priority
    chain.set_type(ChainType::Filter);
    chain.set_policy(Policy::Accept);
    batch.add(&chain, MsgType::Add);

    let mut rule = Rule::new(&chain);
    rule.add_expr(&Meta::L4Proto);
    rule.add_expr(&nftnl::expr::Cmp::new(CmpOp::Eq, 6u8)); // TCP
    rule.add_expr(&nft_expr!(payload tcp dport));
    rule.add_expr(&nftnl::expr::Cmp::new(CmpOp::Eq, 80u16.to_be()));
    rule.add_expr(&Immediate::new(1234u16.to_be(), Register::Reg1));
    rule.add_expr(&nft_expr!(tproxy port Register::Reg1));
    batch.add(&rule, MsgType::Add);

    send_and_process(&batch.finalize())?;
    Ok(())
}

fn send_and_process(batch: &FinalizedBatch) -> std::io::Result<()> {
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
