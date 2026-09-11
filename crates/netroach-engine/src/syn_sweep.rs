//! Building and reading the packets a SYN sweep is made of.
//!
//! A connect scan asks the operating system for a socket per port, and a port
//! that never answers holds that socket for the whole timeout - so throughput
//! is concurrency divided by timeout, and on a range that mostly does not
//! answer, that is the entire cost of the scan. A SYN sweep spends one packet
//! on such a port and keeps no state for it, which is what the machinery in
//! here buys.
//!
//! Keeping no state is the hard part: there is nowhere to remember fifteen
//! million outstanding probes. The sequence number carries a keyed hash of the
//! probe instead, and a reply counts as ours only if its acknowledgement
//! returns that number - which is also what stops a packet we did not send
//! becoming a finding. Everything here is a pure function of bytes, so all of
//! it is tested without a driver, an interface, or a network.
#![allow(dead_code)] // parts are used by the loopback example and the send loop to come
use std::net::Ipv4Addr;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const IP_PROTO_TCP: u8 = 6;
const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const TCP_MIN_HEADER_LEN: usize = 20;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;

/// The framing an adapter puts around the IP packet.
///
/// A wired interface is ethernet - fourteen bytes of MACs and a type - and the
/// destination MAC has to be the next hop, which is why it is resolved per
/// target. The loopback adapter is DLT_NULL instead: four bytes naming the
/// protocol family, no addresses, because a packet to oneself has no next hop.
/// Sending the wrong framing puts bytes on the wire the stack cannot read, so
/// the sweep asks the adapter which it is and builds to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkLayer {
    /// Ethernet (DLT_EN10MB): dst MAC, src MAC, ethertype.
    Ethernet {
        source_mac: [u8; 6],
        next_hop_mac: [u8; 6],
    },
    /// BSD loopback (DLT_NULL): a four-byte protocol family in host order.
    Null,
}

impl LinkLayer {
    /// The bytes that precede the IP packet on this link.
    fn header(&self) -> Vec<u8> {
        match self {
            LinkLayer::Ethernet {
                source_mac,
                next_hop_mac,
            } => {
                let mut header = Vec::with_capacity(ETHERNET_HEADER_LEN);
                header.extend_from_slice(next_hop_mac);
                header.extend_from_slice(source_mac);
                header.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
                header
            }
            // AF_INET is 2, written in the host's byte order - little-endian on
            // every machine this runs on.
            LinkLayer::Null => 2u32.to_le_bytes().to_vec(),
        }
    }

    /// Where the IP packet starts, and whether this frame is IPv4 at all.
    fn ip_offset(&self, frame: &[u8]) -> Option<usize> {
        match self {
            LinkLayer::Ethernet { .. } => {
                let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
                (ethertype == ETHERTYPE_IPV4).then_some(ETHERNET_HEADER_LEN)
            }
            LinkLayer::Null => {
                let family = u32::from_le_bytes([
                    *frame.get(0)?,
                    *frame.get(1)?,
                    *frame.get(2)?,
                    *frame.get(3)?,
                ]);
                // 2 is AF_INET everywhere; 24/28/30 are what some BSDs use, but
                // Npcap's loopback is 2, so only that is accepted.
                (family == 2).then_some(4)
            }
        }
    }
}

/// What a reply says about the port that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynReply {
    /// SYN-ACK: something is listening.
    Open,
    /// RST: nothing is.
    Closed,
}

/// A reply that carried our own sequence number back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynAnswer {
    pub host: Ipv4Addr,
    pub port: u16,
    pub reply: SynReply,
}

/// The sequence number that identifies one probe.
///
/// Replies are matched by arithmetic rather than a per-probe lookup table. The
/// runner keeps only two result bits per probe so retries can skip answers. The
/// secret is drawn once per run: without one, anybody could compute the number
/// that makes a forged reply look genuine.
pub fn syn_cookie(secret: u64, host: Ipv4Addr, port: u16, source_port: u16) -> u32 {
    let mut value = secret;
    value ^= u64::from(u32::from_be_bytes(host.octets()));
    value = value.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    value ^= (u64::from(port) << 16) | u64::from(source_port);
    value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value ^= value >> 31;
    let folded = ((value >> 32) ^ value) as u32;
    // Zero stays free so a caller can use it to mean "no cookie".
    if folded == 0 {
        1
    } else {
        folded
    }
}

/// One's complement sum, as every IP checksum is defined.
///
/// Takes the parts separately because the TCP checksum covers a pseudo header
/// that is never sent, and copying the two together to add them up would be
/// the largest allocation in the sweep.
fn checksum16(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carried: Option<u8> = None;
    for part in parts {
        let mut bytes: &[u8] = part;
        if let Some(high) = carried.take() {
            match bytes.split_first() {
                Some((low, rest)) => {
                    sum += u32::from(u16::from_be_bytes([high, *low]));
                    bytes = rest;
                }
                None => {
                    carried = Some(high);
                    continue;
                }
            }
        }
        let mut pairs = bytes.chunks_exact(2);
        for pair in &mut pairs {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let [odd] = pairs.remainder() {
            carried = Some(*odd);
        }
    }
    if let Some(high) = carried {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// The frame one SYN probe is sent as, framed for the adapter it goes out on.
///
/// pcap writes at the link layer, so the header before the IP packet is ours
/// to fill in - and it differs by adapter (see `LinkLayer`). Getting it wrong
/// returns no answers rather than wrong ones, which is why the caller passes
/// the adapter's own link type.
pub fn build_syn_frame(
    link: LinkLayer,
    source_ip: Ipv4Addr,
    host: Ipv4Addr,
    source_port: u16,
    port: u16,
    sequence: u32,
    ip_id: u16,
) -> Vec<u8> {
    build_tcp_frame(
        link,
        source_ip,
        host,
        source_port,
        port,
        sequence,
        ip_id,
        TCP_FLAG_SYN,
    )
}

/// The frame that closes a half-open connection our SYN opened.
///
/// A probe that finds an open port leaves the target holding a half-open
/// connection until its own timeout, retransmitting the SYN-ACK meanwhile,
/// because the scanning host's firewall drops the reply rather than resetting
/// it. On a device whose backlog is a slot or two - a printer, a controller -
/// that slot is unavailable to a legitimate connection for the best part of a
/// minute. The reset gives it straight back.
///
/// The sequence is the one the target is waiting to hear: the SYN's, plus one.
pub fn build_rst_frame(
    link: LinkLayer,
    source_ip: Ipv4Addr,
    host: Ipv4Addr,
    source_port: u16,
    port: u16,
    sequence: u32,
    ip_id: u16,
) -> Vec<u8> {
    build_tcp_frame(
        link,
        source_ip,
        host,
        source_port,
        port,
        sequence,
        ip_id,
        TCP_FLAG_RST,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_tcp_frame(
    link: LinkLayer,
    source_ip: Ipv4Addr,
    host: Ipv4Addr,
    source_port: u16,
    port: u16,
    sequence: u32,
    ip_id: u16,
    flags: u8,
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(TCP_MIN_HEADER_LEN);
    tcp.extend_from_slice(&source_port.to_be_bytes());
    tcp.extend_from_slice(&port.to_be_bytes());
    tcp.extend_from_slice(&sequence.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&1024u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());

    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&source_ip.octets());
    pseudo.extend_from_slice(&host.octets());
    pseudo.push(0);
    pseudo.push(IP_PROTO_TCP);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    let tcp_checksum = checksum16(&[&pseudo, &tcp]);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

    let total_length = (IPV4_MIN_HEADER_LEN + tcp.len()) as u16;
    let mut ip = Vec::with_capacity(IPV4_MIN_HEADER_LEN);
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&total_length.to_be_bytes());
    ip.extend_from_slice(&ip_id.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes());
    ip.push(64);
    ip.push(IP_PROTO_TCP);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&source_ip.octets());
    ip.extend_from_slice(&host.octets());
    let ip_checksum = checksum16(&[&ip]);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let header = link.header();
    let mut frame = Vec::with_capacity(header.len() + ip.len() + tcp.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

/// Read a captured frame and say what it answers, if it answers us at all.
///
/// None for everything that is not a reply to one of our own probes: other
/// protocols, other hosts talking among themselves, and a reply whose
/// acknowledgement does not carry the cookie back. That last check is what
/// makes a stateless sweep safe to believe.
pub fn parse_syn_reply(link: LinkLayer, frame: &[u8], secret: u64) -> Option<SynAnswer> {
    let ip = frame.get(link.ip_offset(frame)?..)?;
    let version_and_length = *ip.first()?;
    if version_and_length >> 4 != 4 {
        return None;
    }
    let ip_header_len = usize::from(version_and_length & 0x0F) * 4;
    if ip_header_len < IPV4_MIN_HEADER_LEN || *ip.get(9)? != IP_PROTO_TCP {
        return None;
    }
    let host = Ipv4Addr::new(*ip.get(12)?, *ip.get(13)?, *ip.get(14)?, *ip.get(15)?);

    let tcp = ip.get(ip_header_len..)?;
    if tcp.len() < TCP_MIN_HEADER_LEN {
        return None;
    }
    let port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let source_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let acknowledgement = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let flags = tcp[13];

    let expected = syn_cookie(secret, host, port, source_port).wrapping_add(1);
    if acknowledgement != expected {
        return None;
    }

    // A RST carries no SYN, so it is read first: a peer that refuses answers
    // with RST-ACK, and testing SYN first would leave that unclassified.
    let reply = if flags & TCP_FLAG_RST != 0 {
        SynReply::Closed
    } else if flags & TCP_FLAG_SYN != 0 && flags & TCP_FLAG_ACK != 0 {
        SynReply::Open
    } else {
        return None;
    };
    Some(SynAnswer { host, port, reply })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const NEXT_HOP_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const SECRET: u64 = 0x0123_4567_89AB_CDEF;

    fn eth() -> LinkLayer {
        LinkLayer::Ethernet {
            source_mac: SOURCE_MAC,
            next_hop_mac: NEXT_HOP_MAC,
        }
    }

    fn source() -> Ipv4Addr {
        Ipv4Addr::new(163, 163, 41, 200)
    }

    fn target() -> Ipv4Addr {
        Ipv4Addr::new(163, 163, 41, 111)
    }

    /// The checksum of a header that already carries its own checksum is zero.
    /// That is the property every receiver tests, so it is the one to test.
    #[test]
    fn a_built_frame_checks_out_where_it_is_received() {
        let frame = build_syn_frame(
            eth(),
            source(),
            target(),
            40000,
            445,
            syn_cookie(SECRET, target(), 445, 40000),
            0x1234,
        );
        let ip = &frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN];
        assert_eq!(checksum16(&[ip]), 0, "the IP header does not verify");

        let tcp = &frame[ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN..];
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&source().octets());
        pseudo.extend_from_slice(&target().octets());
        pseudo.push(0);
        pseudo.push(IP_PROTO_TCP);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        assert_eq!(
            checksum16(&[&pseudo, tcp]),
            0,
            "the TCP header does not verify"
        );
    }

    #[test]
    fn a_reset_carries_the_sequence_the_target_is_waiting_for() {
        // A target that answered SYN-ACK holds the half-open until it times
        // out, because the scanning host's firewall drops the reply rather than
        // resetting it - measured, four SYN-ACKs and no reset. The reset must
        // carry the sequence after the SYN's or the target ignores it.
        let cookie = syn_cookie(SECRET, target(), 445, 40000);
        let frame = build_rst_frame(eth(), source(), target(), 40000, 445, cookie + 1, 9);

        let tcp = &frame[ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN..];
        assert_eq!(tcp[13], TCP_FLAG_RST, "a reset and nothing else");
        assert_eq!(
            u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
            cookie + 1
        );
        let ip = &frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN];
        assert_eq!(checksum16(&[ip]), 0, "the IP header does not verify");
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&source().octets());
        pseudo.extend_from_slice(&target().octets());
        pseudo.push(0);
        pseudo.push(IP_PROTO_TCP);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        assert_eq!(
            checksum16(&[&pseudo, tcp]),
            0,
            "the TCP header does not verify"
        );
    }

    #[test]
    fn the_frame_says_what_it_should_to_a_reader() {
        let frame = build_syn_frame(eth(), source(), target(), 40000, 445, 0xDEAD_BEEF, 7);
        assert_eq!(&frame[0..6], &NEXT_HOP_MAC, "destination is the next hop");
        assert_eq!(&frame[6..12], &SOURCE_MAC);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETHERTYPE_IPV4);
        let tcp = &frame[ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN..];
        assert_eq!(u16::from_be_bytes([tcp[0], tcp[1]]), 40000);
        assert_eq!(u16::from_be_bytes([tcp[2], tcp[3]]), 445);
        assert_eq!(
            u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
            0xDEAD_BEEF
        );
        assert_eq!(tcp[13], TCP_FLAG_SYN, "a sweep sends SYN and nothing else");
    }

    /// Build the reply a peer would send, so the parser is read against a
    /// packet shaped the way the wire shapes one.
    fn reply_frame(host: Ipv4Addr, port: u16, source_port: u16, flags: u8, ack: u32) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&SOURCE_MAC);
        frame.extend_from_slice(&NEXT_HOP_MAC);
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&40u16.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.push(64);
        ip.push(IP_PROTO_TCP);
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&host.octets());
        ip.extend_from_slice(&source().octets());
        frame.extend_from_slice(&ip);
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&port.to_be_bytes());
        tcp.extend_from_slice(&source_port.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.extend_from_slice(&ack.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(flags);
        tcp.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&tcp);
        frame
    }

    #[test]
    fn a_syn_ack_that_returns_the_cookie_is_an_open_port() {
        let ack = syn_cookie(SECRET, target(), 445, 40000).wrapping_add(1);
        let answer = parse_syn_reply(
            eth(),
            &reply_frame(target(), 445, 40000, TCP_FLAG_SYN | TCP_FLAG_ACK, ack),
            SECRET,
        );
        assert_eq!(
            answer,
            Some(SynAnswer {
                host: target(),
                port: 445,
                reply: SynReply::Open
            })
        );
    }

    #[test]
    fn a_reset_that_returns_the_cookie_is_a_closed_port() {
        let ack = syn_cookie(SECRET, target(), 8080, 40001).wrapping_add(1);
        let answer = parse_syn_reply(
            eth(),
            &reply_frame(target(), 8080, 40001, TCP_FLAG_RST | TCP_FLAG_ACK, ack),
            SECRET,
        );
        assert_eq!(
            answer,
            Some(SynAnswer {
                host: target(),
                port: 8080,
                reply: SynReply::Closed
            })
        );
    }

    #[test]
    fn a_packet_we_did_not_send_is_not_an_answer() {
        // Right shape, wrong acknowledgement: someone else's traffic, or a
        // forgery. Believing it would put a port in the report that was never
        // found, which is worse than missing one.
        let flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
        assert_eq!(
            parse_syn_reply(
                eth(),
                &reply_frame(target(), 445, 40000, flags, 12345),
                SECRET
            ),
            None
        );

        // Right cookie, but computed for a different port than it arrived on.
        let elsewhere = syn_cookie(SECRET, target(), 22, 40000).wrapping_add(1);
        assert_eq!(
            parse_syn_reply(
                eth(),
                &reply_frame(target(), 445, 40000, flags, elsewhere),
                SECRET
            ),
            None
        );

        // Right cookie for the port, but from a host we did not probe.
        let other_host = Ipv4Addr::new(163, 163, 41, 112);
        let ours = syn_cookie(SECRET, target(), 445, 40000).wrapping_add(1);
        assert_eq!(
            parse_syn_reply(
                eth(),
                &reply_frame(other_host, 445, 40000, flags, ours),
                SECRET
            ),
            None
        );

        // And a run with a different secret does not accept the other run's.
        assert_eq!(
            parse_syn_reply(
                eth(),
                &reply_frame(target(), 445, 40000, flags, ours),
                SECRET ^ 1
            ),
            None
        );
    }

    #[test]
    fn traffic_that_is_not_a_tcp_reply_is_ignored() {
        let ack = syn_cookie(SECRET, target(), 445, 40000).wrapping_add(1);
        // ARP rather than IPv4.
        let mut arp = reply_frame(target(), 445, 40000, TCP_FLAG_SYN | TCP_FLAG_ACK, ack);
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert_eq!(parse_syn_reply(eth(), &arp, SECRET), None);

        // UDP rather than TCP.
        let mut udp = reply_frame(target(), 445, 40000, TCP_FLAG_SYN | TCP_FLAG_ACK, ack);
        udp[ETHERNET_HEADER_LEN + 9] = 17;
        assert_eq!(parse_syn_reply(eth(), &udp, SECRET), None);

        // A plain SYN is somebody connecting to us, not answering us.
        assert_eq!(
            parse_syn_reply(
                eth(),
                &reply_frame(target(), 445, 40000, TCP_FLAG_SYN, ack),
                SECRET
            ),
            None
        );

        // Truncated frames must not panic.
        for cut in 0..54 {
            let short = reply_frame(target(), 445, 40000, TCP_FLAG_SYN | TCP_FLAG_ACK, ack);
            assert_eq!(
                parse_syn_reply(eth(), &short[..cut], SECRET),
                None,
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn ip_options_do_not_shift_the_parser_off_the_tcp_header() {
        // A reply may carry IP options, which moves the TCP header along. The
        // header length field is the only thing that says where it starts.
        let ack = syn_cookie(SECRET, target(), 445, 40000).wrapping_add(1);
        let base = reply_frame(target(), 445, 40000, TCP_FLAG_SYN | TCP_FLAG_ACK, ack);
        let mut framed = base[..ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN].to_vec();
        framed[ETHERNET_HEADER_LEN] = 0x46; // six-word header: four bytes of options
        framed.extend_from_slice(&[1, 1, 1, 0]);
        framed.extend_from_slice(&base[ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN..]);
        assert_eq!(
            parse_syn_reply(eth(), &framed, SECRET),
            Some(SynAnswer {
                host: target(),
                port: 445,
                reply: SynReply::Open
            })
        );
    }

    #[test]
    fn the_cookie_separates_probes_that_differ_in_any_one_field() {
        let base = syn_cookie(SECRET, target(), 445, 40000);
        assert_ne!(base, syn_cookie(SECRET, target(), 446, 40000), "port");
        assert_ne!(
            base,
            syn_cookie(SECRET, target(), 445, 40001),
            "source port"
        );
        assert_ne!(
            base,
            syn_cookie(SECRET, Ipv4Addr::new(163, 163, 41, 112), 445, 40000),
            "host"
        );
        assert_ne!(base, syn_cookie(SECRET ^ 1, target(), 445, 40000), "secret");
        assert_eq!(
            base,
            syn_cookie(SECRET, target(), 445, 40000),
            "and is stable"
        );
    }

    #[test]
    fn no_probe_is_given_the_reserved_cookie() {
        // Zero is kept free to mean "no cookie", so it must never be issued.
        let host = Ipv4Addr::new(10, 0, 0, 1);
        for port in 1..2000u16 {
            assert_ne!(syn_cookie(SECRET, host, port, 40000), 0);
        }
    }
}
