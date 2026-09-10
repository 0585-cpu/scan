//! Working out how to address a target at the link layer, which pcap leaves to
//! us because it writes whole frames.
//!
//! A frame's destination MAC is not the target's - it is the next hop's. For a
//! target on our own segment that is the target itself; for one behind a router
//! it is the router, and the two are told apart by the routing table, not by
//! comparing prefixes ourselves (a static route or a second interface would
//! make prefix arithmetic wrong). Windows answers all of it: GetBestRoute2
//! gives the next hop, the interface and the source address for a destination;
//! GetIfEntry2 gives that interface's MAC; and GetIpNetEntry2 gives the next
//! hop's, asking the stack to ARP for it when the cache is cold.
//!
//! Getting this wrong returns no answers rather than wrong ones - a SYN sent to
//! the wrong MAC is dropped by the first switch - so the sweep resolves it once
//! per target and caches the result.
#![cfg(all(windows, feature = "syn-sweep"))]
// Wired into the send loop in the next step; unused in the binary until then.
#![allow(dead_code)]

use std::net::Ipv4Addr;

use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetBestRoute2, GetIfEntry2, GetIpNetEntry2, ResolveIpNetEntry2, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
    MIB_IPNET_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, IN_ADDR, SOCKADDR_INET};

use crate::syn_sweep::LinkLayer;

/// How to reach one target: the address to send from, and the framing to wrap
/// the packet in (which carries the source and next-hop MACs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub source_ip: Ipv4Addr,
    pub link: LinkLayer,
    pub interface_index: u32,
}

/// Why a target could not be addressed. Each names the target or interface so a
/// failure points at the row that could not be resolved rather than the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    NoRoute(Ipv4Addr),
    NoInterfaceMac(u32),
    NoNextHopMac(Ipv4Addr),
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteError::NoRoute(ip) => write!(f, "no route to {ip}"),
            RouteError::NoInterfaceMac(index) => write!(f, "no MAC for interface {index}"),
            RouteError::NoNextHopMac(ip) => write!(f, "no MAC for next hop {ip}"),
        }
    }
}

impl std::error::Error for RouteError {}

/// An IPv4 SOCKADDR_INET. The union is zeroed and the v4 arm filled, which is
/// all the Windows calls read for an AF_INET address.
fn sockaddr(ip: Ipv4Addr) -> SOCKADDR_INET {
    let mut address: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    // Writing a union field is safe; only reading one is not.
    address.Ipv4.sin_family = AF_INET;
    address.Ipv4.sin_addr = in_addr(ip);
    address
}

/// IN_ADDR holds the four octets; writing them native and reading them native
/// keeps the byte order the octets are already in, whichever way the host runs.
fn in_addr(ip: Ipv4Addr) -> IN_ADDR {
    let mut value: IN_ADDR = unsafe { std::mem::zeroed() };
    value.S_un.S_addr = u32::from_ne_bytes(ip.octets());
    value
}

fn read_in_addr(value: IN_ADDR) -> Ipv4Addr {
    Ipv4Addr::from(unsafe { value.S_un.S_addr }.to_ne_bytes())
}

/// The MAC of a captured interface, or None when it has none six bytes long
/// (a tunnel or a virtual adapter that a wired scan would not use anyway).
fn interface_mac(interface_index: u32) -> Option<[u8; 6]> {
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = interface_index;
    if unsafe { GetIfEntry2(&mut row) } != 0 || row.PhysicalAddressLength < 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&row.PhysicalAddress[..6]);
    Some(mac)
}

/// The MAC of a neighbour, asking the stack to ARP for it if the cache is cold.
///
/// GetIpNetEntry2 reads the neighbour cache; a miss returns an error, and
/// ResolveIpNetEntry2 then sends the ARP and waits briefly for the reply before
/// the cache is read again. A neighbour that never answers has no MAC to send
/// to, which is a target we cannot reach at the link layer.
fn neighbour_mac(interface_index: u32, ip: Ipv4Addr) -> Option<[u8; 6]> {
    let mut row: MIB_IPNET_ROW2 = unsafe { std::mem::zeroed() };
    row.Address = sockaddr(ip);
    row.InterfaceIndex = interface_index;
    let mut result = unsafe { GetIpNetEntry2(&mut row) };
    if result != 0 {
        // A fresh row for the resolve; ResolveIpNetEntry2 fills it in place.
        let mut fresh: MIB_IPNET_ROW2 = unsafe { std::mem::zeroed() };
        fresh.Address = sockaddr(ip);
        fresh.InterfaceIndex = interface_index;
        unsafe { ResolveIpNetEntry2(&mut fresh, std::ptr::null()) };
        row = fresh;
        result = unsafe { GetIpNetEntry2(&mut row) };
    }
    if result != 0 || row.PhysicalAddressLength < 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&row.PhysicalAddress[..6]);
    Some(mac)
}

/// Everything the sweep needs to put a frame on the wire for one target.
pub fn resolve_route(dest: Ipv4Addr) -> Result<Route, RouteError> {
    let destination = sockaddr(dest);
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut best_source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    let result = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &destination,
            0,
            &mut route,
            &mut best_source,
        )
    };
    if result != 0 {
        return Err(RouteError::NoRoute(dest));
    }

    let interface_index = route.InterfaceIndex;
    let source_ip = read_in_addr(unsafe { best_source.Ipv4.sin_addr });

    // GetBestRoute2 reports an unspecified next hop when the target is on-link,
    // and the neighbour to resolve is then the target itself.
    let next_hop = read_in_addr(unsafe { route.NextHop.Ipv4.sin_addr });
    let next_hop = if next_hop.is_unspecified() { dest } else { next_hop };

    let source_mac = interface_mac(interface_index).ok_or(RouteError::NoInterfaceMac(interface_index))?;
    let next_hop_mac = neighbour_mac(interface_index, next_hop).ok_or(RouteError::NoNextHopMac(next_hop))?;

    Ok(Route {
        source_ip,
        interface_index,
        link: LinkLayer::Ethernet { source_mac, next_hop_mac },
    })
}
