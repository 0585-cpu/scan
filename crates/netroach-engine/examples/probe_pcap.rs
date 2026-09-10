//! A standing-start check that Npcap is reachable from Rust on this machine:
//! link against wpcap, list the interfaces, and open the one the loopback
//! traffic will ride. Nothing here is part of the engine - it is the smallest
//! program that proves the driver, the SDK and the crate line up before any of
//! the sweep is wired in.
//!
//! Run with: cargo run --features syn-sweep --example probe_pcap

fn main() {
    let devices = match pcap::Device::list() {
        Ok(devices) => devices,
        Err(error) => {
            eprintln!("pcap could not list interfaces: {error}");
            std::process::exit(1);
        }
    };
    println!("interfaces: {}", devices.len());
    for device in &devices {
        let description = device.desc.as_deref().unwrap_or("");
        let addresses: Vec<String> = device
            .addresses
            .iter()
            .map(|a| a.addr.to_string())
            .collect();
        println!(
            "  {} [{}] {}",
            device.name,
            description,
            addresses.join(", ")
        );
    }

    // The loopback device carries a frame back to us without touching the wire,
    // which is how the sweep is tested without a network.
    let loopback = devices.iter().find(|d| {
        d.desc
            .as_deref()
            .is_some_and(|desc| desc.contains("Loopback") || desc.contains("Adapter for loopback"))
            || d.name.to_lowercase().contains("loopback")
    });
    match loopback {
        Some(device) => {
            println!(
                "loopback: {} [{}]",
                device.name,
                device.desc.as_deref().unwrap_or("")
            );
            match pcap::Capture::from_device(device.clone())
                .and_then(|c| c.immediate_mode(true).open())
            {
                Ok(_) => println!("opened the loopback device"),
                Err(error) => {
                    eprintln!("could not open the loopback device: {error}");
                    std::process::exit(2);
                }
            }
        }
        None => {
            eprintln!("no loopback device - was Npcap installed with loopback support?");
            std::process::exit(3);
        }
    }
    println!("ok");
}
