//! Prove the routing resolver against this machine's own table: a target off
//! the segment must resolve to the gateway's MAC, an on-link target to its own.
//! Getting this wrong is the failure that returns no answers on a mixed-subnet
//! scan, so it is checked against addresses whose answers are known.
//!
//! Run elevated with: cargo run --features syn-sweep --example resolve_route -- 8.8.8.8 198.51.100.254

#[path = "../src/syn_sweep.rs"]
mod syn_sweep;
#[path = "../src/netlink.rs"]
mod netlink;

use std::net::Ipv4Addr;

use netlink::resolve_route;
use syn_sweep::LinkLayer;

fn mac(bytes: [u8; 6]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-")
}

fn main() {
    let targets: Vec<Ipv4Addr> = std::env::args()
        .skip(1)
        .filter_map(|arg| arg.parse().ok())
        .collect();
    let targets = if targets.is_empty() {
        vec![Ipv4Addr::new(8, 8, 8, 8)]
    } else {
        targets
    };

    for target in targets {
        match resolve_route(target) {
            Ok(route) => {
                let LinkLayer::Ethernet { source_mac, next_hop_mac } = route.link else {
                    println!("{target}: non-ethernet link");
                    continue;
                };
                println!(
                    "{target}\n  source {} via interface {}\n  source MAC   {}\n  next-hop MAC {}",
                    route.source_ip,
                    route.interface_index,
                    mac(source_mac),
                    mac(next_hop_mac),
                );
            }
            Err(error) => println!("{target}: {error}"),
        }
    }
}
