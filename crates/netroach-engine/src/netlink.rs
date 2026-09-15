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
//! The route and neighbour half of this compiles on Windows whether or not
//! the sweep does: a connect or UDP scan cannot write a frame, but it still
//! benefits from knowing that an on-link address answers no ARP at all, which
//! means nothing is there to probe. Only the parts that hand a frame to pcap
//! need the sweep's feature.
#![cfg(windows)]
use std::net::Ipv4Addr;

#[cfg(feature = "syn-sweep")]
use windows_sys::core::GUID;
#[cfg(feature = "syn-sweep")]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid, GetIfEntry2, MIB_IF_ROW2,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetBestRoute2, GetIpNetEntry2, GetUnicastIpAddressTable, ResolveIpNetEntry2,
    MIB_IPFORWARD_ROW2, MIB_IPNET_ROW2, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
#[cfg(feature = "syn-sweep")]
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, IN_ADDR, SOCKADDR_INET};

#[cfg(feature = "syn-sweep")]
use crate::syn_sweep::LinkLayer;

/// How to reach one target: the address to send from, and the framing to wrap
/// the packet in (which carries the source and next-hop MACs).
#[cfg(feature = "syn-sweep")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub source_ip: Ipv4Addr,
    pub link: LinkLayer,
    pub interface_index: u32,
}

#[cfg(feature = "syn-sweep")]
/// Why a target could not be addressed. Each names the target or interface so a
/// failure points at the row that could not be resolved rather than the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    NoRoute(Ipv4Addr),
    NoInterfaceMac(u32),
    NoNextHopMac(Ipv4Addr),
    NoInterfaceLuid(u32),
    NoInterfaceGuid(u32),
    NoPcapDevice(String),
    AmbiguousPcapDevice(String),
}

#[cfg(feature = "syn-sweep")]
impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteError::NoRoute(ip) => write!(f, "no route to {ip}"),
            RouteError::NoInterfaceMac(index) => write!(f, "no MAC for interface {index}"),
            RouteError::NoNextHopMac(ip) => write!(f, "no MAC for next hop {ip}"),
            RouteError::NoInterfaceLuid(index) => write!(f, "no LUID for interface {index}"),
            RouteError::NoInterfaceGuid(index) => write!(f, "no GUID for interface {index}"),
            RouteError::NoPcapDevice(guid) => write!(f, "no Npcap device for interface {guid}"),
            RouteError::AmbiguousPcapDevice(guid) => {
                write!(f, "multiple Npcap devices matched interface {guid}")
            }
        }
    }
}

#[cfg(feature = "syn-sweep")]
impl std::error::Error for RouteError {}

#[cfg(feature = "syn-sweep")]
fn format_guid(guid: &GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    )
}

#[cfg(feature = "syn-sweep")]
fn pcap_device_for_guid(guid: &GUID, devices: &[pcap::Device]) -> Result<pcap::Device, RouteError> {
    let guid = format_guid(guid);
    let expected = format!(r"\Device\NPF_{guid}");
    let mut matches = devices
        .iter()
        .filter(|device| device.name.eq_ignore_ascii_case(&expected));
    let matched = matches
        .next()
        .cloned()
        .ok_or_else(|| RouteError::NoPcapDevice(guid.clone()))?;
    if matches.next().is_some() {
        return Err(RouteError::AmbiguousPcapDevice(guid));
    }
    Ok(matched)
}

#[cfg(feature = "syn-sweep")]
pub fn pcap_device_for_interface(
    interface_index: u32,
    devices: &[pcap::Device],
) -> Result<pcap::Device, RouteError> {
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    if unsafe { ConvertInterfaceIndexToLuid(interface_index, &mut luid) } != 0 {
        return Err(RouteError::NoInterfaceLuid(interface_index));
    }
    let mut guid: GUID = unsafe { std::mem::zeroed() };
    if unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) } != 0 {
        return Err(RouteError::NoInterfaceGuid(interface_index));
    }
    pcap_device_for_guid(&guid, devices)
}

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
#[cfg(feature = "syn-sweep")]
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
    // The broadcast address resolves to all ones, which is not a host's MAC;
    // the caller tells that case apart rather than treating it as a neighbour.
    //
    // A neighbour that never answered leaves an incomplete entry whose address
    // is all zeroes. Sending to it is worse than useless: a switch has never
    // learned that address, so it floods the frame to every port on the segment
    // rather than dropping it. A host that will not answer ARP is down, and the
    // sweep has nothing to say to it.
    if mac == [0u8; 6] {
        return None;
    }
    Some(mac)
}

/// Every IPv4 address this machine answers to.
///
/// A sweep cannot probe its own address: the packet never reaches the wire, and
/// the reply would come from the loopback path rather than the target. Scanning
/// one's own subnet always includes it, so the caller needs to know which
/// targets to hand to connect scanning instead of discovering it as a failure
/// part way through.
///
/// An empty list on failure is safe: the sweep still refuses a self-target, so
/// the worst case is the error this exists to avoid, not a wrong result.
pub fn local_ipv4_addresses() -> Vec<Ipv4Addr> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    if unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) } != 0 || table.is_null() {
        return Vec::new();
    }
    let mut addresses = Vec::new();
    unsafe {
        let count = (*table).NumEntries as usize;
        // Table is declared as one element; the rows follow it in memory.
        let rows = std::ptr::addr_of!((*table).Table) as *const MIB_UNICASTIPADDRESS_ROW;
        for index in 0..count {
            addresses.push(read_in_addr((*rows.add(index)).Address.Ipv4.sin_addr));
        }
        FreeMibTable(table.cast());
    }
    addresses
}

/// Where the stack would send a packet for this target. Discovery reads only
/// `on_link` and the interface; the rest is what the sweep needs to frame a
/// packet, and is absent from a build without it.
pub struct BestRoute {
    pub interface_index: u32,
    #[cfg_attr(not(feature = "syn-sweep"), allow(dead_code))]
    pub source_ip: Ipv4Addr,
    /// The neighbour to resolve: the target itself when it is on our own
    /// segment, the router otherwise.
    #[cfg_attr(not(feature = "syn-sweep"), allow(dead_code))]
    pub next_hop: Ipv4Addr,
    pub on_link: bool,
}

fn best_route(dest: Ipv4Addr) -> Option<BestRoute> {
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
        return None;
    }
    // GetBestRoute2 reports an unspecified next hop when the target is on-link,
    // and the neighbour to resolve is then the target itself.
    let next_hop = read_in_addr(unsafe { route.NextHop.Ipv4.sin_addr });
    let on_link = next_hop.is_unspecified();
    Some(BestRoute {
        interface_index: route.InterfaceIndex,
        source_ip: read_in_addr(unsafe { best_source.Ipv4.sin_addr }),
        next_hop: if on_link { dest } else { next_hop },
        on_link,
    })
}

/// What an address on our own segment turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnLinkAddress {
    /// A neighbour answered with a MAC of its own.
    Host,
    /// Nothing answered, so there is nothing there to probe.
    Silent,
    /// The segment's broadcast address, which resolves to every host at once
    /// rather than to one. A probe sent here is delivered to all of them.
    Broadcast,
}

/// What an address on our own segment answers ARP as.
///
/// `None` where the question does not apply: a target behind a router, or one
/// the stack has no route to at all. ARP is answered by the router for those,
/// which says nothing about whether the target is there - so a scan must not
/// read a silent neighbour cache as an absent host and skip it.
///
/// On our own segment it is decisive in the other direction. A frame cannot be
/// delivered to an on-link IPv4 address without its MAC, so an address that
/// answers no ARP has nothing on it to probe.
pub fn on_link_address_answers(dest: Ipv4Addr) -> Option<OnLinkAddress> {
    let route = best_route(dest)?;
    if !route.on_link {
        return None;
    }
    Some(match neighbour_mac(route.interface_index, dest) {
        Some(mac) if mac == [0xff; 6] => OnLinkAddress::Broadcast,
        Some(_) => OnLinkAddress::Host,
        None => OnLinkAddress::Silent,
    })
}

/// Everything the sweep needs to put a frame on the wire for one target.
#[cfg(feature = "syn-sweep")]
pub fn resolve_route(dest: Ipv4Addr) -> Result<Route, RouteError> {
    let route = best_route(dest).ok_or(RouteError::NoRoute(dest))?;
    let interface_index = route.interface_index;
    let source_ip = route.source_ip;
    let next_hop = route.next_hop;

    let source_mac =
        interface_mac(interface_index).ok_or(RouteError::NoInterfaceMac(interface_index))?;
    let next_hop_mac =
        neighbour_mac(interface_index, next_hop).ok_or(RouteError::NoNextHopMac(next_hop))?;

    Ok(Route {
        source_ip,
        interface_index,
        link: LinkLayer::Ethernet {
            source_mac,
            next_hop_mac,
        },
    })
}

#[cfg(all(test, feature = "syn-sweep"))]
mod tests {
    use windows_sys::core::GUID;

    use super::*;

    fn fixture_guid() -> GUID {
        GUID {
            data1: 0x0011_2233,
            data2: 0x4455,
            data3: 0x6677,
            data4: [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        }
    }

    #[test]
    fn formats_a_windows_interface_guid_for_npcap() {
        assert_eq!(
            format_guid(&fixture_guid()),
            "{00112233-4455-6677-8899-AABBCCDDEEFF}"
        );
    }

    #[test]
    fn matches_the_npcap_device_guid_case_insensitively() {
        let devices = vec![pcap::Device::from(
            r"\Device\NPF_{00112233-4455-6677-8899-aabbccddeeff}",
        )];

        let matched = pcap_device_for_guid(&fixture_guid(), &devices).unwrap();

        assert_eq!(matched.name, devices[0].name);
    }

    #[test]
    fn rejects_a_missing_npcap_device() {
        let error = pcap_device_for_guid(&fixture_guid(), &[]).unwrap_err();

        assert!(matches!(error, RouteError::NoPcapDevice(_)));
    }

    #[test]
    fn rejects_ambiguous_npcap_device_matches() {
        let name = r"\Device\NPF_{00112233-4455-6677-8899-AABBCCDDEEFF}";
        let devices = vec![pcap::Device::from(name), pcap::Device::from(name)];

        let error = pcap_device_for_guid(&fixture_guid(), &devices).unwrap_err();

        assert!(matches!(error, RouteError::AmbiguousPcapDevice(_)));
    }
}
