//! The test the pure logic cannot do for itself: put a real SYN on the wire
//! through Npcap and read what comes back. It runs over the loopback adapter,
//! so it needs no network and no remote host, and it exercises the two things
//! only a driver can - that a frame we built actually transmits, and that a
//! listening port answers it with the SYN-ACK the parser is written to read.
//!
//! Two ports are used: one held open by a TcpListener, one nothing listens on.
//! An open port answers SYN with SYN-ACK; a closed one answers with RST. Both
//! carry our cookie back, and the parser must sort them.
//!
//! Run elevated with: cargo run --features syn-sweep --example loopback_roundtrip

use std::net::{Ipv4Addr, TcpListener};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[path = "../src/syn_sweep.rs"]
mod syn_sweep;
use syn_sweep::{build_syn_frame, parse_syn_reply, syn_cookie, LinkLayer, SynReply};

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
const ZERO_MAC: [u8; 6] = [0; 6];
const SOURCE_PORT: u16 = 54321;

fn loopback_device() -> pcap::Device {
    pcap::Device::list()
        .expect("list interfaces")
        .into_iter()
        .find(|d| d.name.to_lowercase().contains("loopback"))
        .expect("Npcap loopback adapter - installed with loopback support?")
}

fn main() {
    // A port held open for the whole run, and a port nobody listens on. Binding
    // the second and dropping it frees it; nothing else is racing for it here.
    let open_listener = TcpListener::bind((LOOPBACK, 0)).expect("bind an open port");
    let open_port = open_listener.local_addr().unwrap().port();
    let closed_port = {
        let probe = TcpListener::bind((LOOPBACK, 0)).unwrap();
        probe.local_addr().unwrap().port()
    };
    println!("open port {open_port}, closed port {closed_port}");

    let secret: u64 = 0xA5A5_5A5A_1234_ABCD;
    let device = loopback_device();
    let datalink = pcap::Capture::from_device(device.clone())
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap()
        .get_datalink();
    println!(
        "loopback datalink: {datalink:?} ({})",
        datalink.get_name().unwrap_or_default()
    );
    // DLT_NULL is 0, DLT_EN10MB is 1. The loopback adapter is the former.
    let link = if datalink.0 == 1 {
        LinkLayer::Ethernet {
            source_mac: ZERO_MAC,
            next_hop_mac: ZERO_MAC,
        }
    } else {
        LinkLayer::Null
    };

    // The reader runs on its own thread: capture blocks, and the probes have to
    // go out while it is listening or the answers arrive before anyone reads.
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (answer_tx, answer_rx) = mpsc::channel();
    let reader_device = device.clone();
    let reader_link = link;
    let reader = std::thread::spawn(move || {
        let mut capture = pcap::Capture::from_device(reader_device)
            .unwrap()
            .immediate_mode(true)
            .timeout(200)
            .open()
            .unwrap();
        // Only TCP to our source port comes back to us; the filter keeps the
        // loop from waking on every packet the machine sends itself.
        let _ = capture.filter(&format!("tcp and dst port {SOURCE_PORT}"), true);
        ready_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            match capture.next_packet() {
                Ok(packet) => {
                    if let Some(answer) = parse_syn_reply(reader_link, packet.data, secret) {
                        if answer_tx.send(answer).is_err() {
                            return;
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(_) => return,
            }
        }
    });
    ready_rx.recv().unwrap();
    std::thread::sleep(Duration::from_millis(100));

    // A sender handle on the same adapter. On the loopback link Npcap wraps the
    // IP packet in an ethernet header with zero MACs, so that is what we build.
    let mut sender = pcap::Capture::from_device(device).unwrap().open().unwrap();
    for (label, port) in [("open", open_port), ("closed", closed_port)] {
        let cookie = syn_cookie(secret, LOOPBACK, port, SOURCE_PORT);
        let frame = build_syn_frame(link, LOOPBACK, LOOPBACK, SOURCE_PORT, port, cookie, 1);
        match sender.sendpacket(&frame[..]) {
            Ok(()) => println!("sent SYN to the {label} port {port}"),
            Err(error) => {
                eprintln!("could not send on loopback: {error}");
                std::process::exit(2);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Collect what came back for a moment, then judge it.
    let mut open_seen = false;
    let mut closed_seen = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match answer_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(answer) if answer.port == open_port && answer.reply == SynReply::Open => {
                println!("open port answered SYN-ACK");
                open_seen = true;
            }
            Ok(answer) if answer.port == closed_port && answer.reply == SynReply::Closed => {
                println!("closed port answered RST");
                closed_seen = true;
            }
            Ok(answer) => println!("other reply: {answer:?}"),
            Err(_) => {}
        }
        if open_seen && closed_seen {
            break;
        }
    }
    drop(reader);

    // The send path is proven the moment either answer is read - a reply means
    // the SYN reached the stack. The open/closed split is the parser proven on
    // real packets rather than the ones the tests build.
    if open_seen && closed_seen {
        println!("ok: both classifications confirmed on the wire");
    } else if open_seen || closed_seen {
        println!(
            "partial: send and capture work; got open={open_seen} closed={closed_seen}. \
             The loopback stack may not answer injected SYNs the way a remote host does."
        );
    } else {
        eprintln!(
            "no replies captured. Send may work while the loopback stack ignores \
             injected SYNs; a wire test against a real host is the fallback."
        );
        std::process::exit(3);
    }
    let _ = open_listener;
}
