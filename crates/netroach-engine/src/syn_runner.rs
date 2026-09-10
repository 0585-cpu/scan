//! Windows/Npcap orchestration for the optional IPv4 SYN sweep.
#![cfg(all(windows, feature = "syn-sweep"))]

use anyhow::{anyhow, Context, Result};
use pcap::{Active, Capture, Device, Linktype};
use std::collections::hash_map::RandomState;
use std::collections::BTreeMap;
use std::hash::{BuildHasher, Hasher};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Instant};

use crate::netlink::{pcap_device_for_interface, resolve_route, Route};
use crate::syn_sweep::{
    build_syn_frame, parse_syn_reply, syn_cookie, LinkLayer, SynAnswer, SynReply,
};
use crate::RateLimiter;

const SYN_RATE_LIMIT_PER_SEC: u64 = 5_000;
const RESPONSE_POLL_INTERVAL: Duration = Duration::from_millis(5);
const CAPTURE_READ_TIMEOUT_MS: i32 = 100;
const ANSWER_QUEUE_CAPACITY: usize = 16_384;

#[derive(Clone, Copy, Debug)]
pub struct SynSweepConfig {
    pub timeout: Duration,
    pub rate_limit_per_sec: u64,
    pub retries: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeState {
    Unanswered = 0,
    Open = 1,
    Closed = 2,
}

#[derive(Debug)]
pub struct ProbeStates {
    bytes: Vec<u8>,
    len: usize,
}

impl ProbeStates {
    pub fn new(len: usize) -> Self {
        Self {
            bytes: vec![0; len.div_ceil(4)],
            len,
        }
    }

    pub fn get(&self, index: usize) -> ProbeState {
        assert!(index < self.len, "probe state index out of bounds");
        let shift = (index % 4) * 2;
        match (self.bytes[index / 4] >> shift) & 0b11 {
            1 => ProbeState::Open,
            2 => ProbeState::Closed,
            _ => ProbeState::Unanswered,
        }
    }

    pub fn record(&mut self, index: usize, reply: SynReply) -> bool {
        let current = self.get(index);
        let next = match reply {
            SynReply::Open => ProbeState::Open,
            SynReply::Closed if current == ProbeState::Unanswered => ProbeState::Closed,
            SynReply::Closed => current,
        };
        if current == next {
            return false;
        }
        let shift = (index % 4) * 2;
        let mask = 0b11 << shift;
        self.bytes[index / 4] = (self.bytes[index / 4] & !mask) | ((next as u8) << shift);
        true
    }

    pub fn unanswered_indices(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.len).filter(|&index| self.get(index) == ProbeState::Unanswered)
    }

    #[cfg(test)]
    fn storage_bytes(&self) -> usize {
        self.bytes.len()
    }
}

pub(crate) fn probe_indices(host_count: usize, port_count: usize) -> impl Iterator<Item = usize> {
    0..host_count.saturating_mul(port_count)
}

pub(crate) fn probe_coordinates(index: usize, host_count: usize) -> (usize, usize) {
    (index % host_count, index / host_count)
}

pub(crate) fn effective_rate(requested: u64) -> u64 {
    requested.min(SYN_RATE_LIMIT_PER_SEC)
}

fn ensure_remote_target(target: Ipv4Addr, source_ip: Ipv4Addr) -> Result<()> {
    if target == source_ip {
        return Err(anyhow!(
            "SYN target {target} is the selected local interface address; use connect scanning"
        ));
    }
    Ok(())
}

fn link_for_datalink(datalink: Linktype) -> Result<LinkLayer> {
    match datalink {
        Linktype::ETHERNET => Ok(LinkLayer::Ethernet {
            source_mac: [0; 6],
            next_hop_mac: [0; 6],
        }),
        Linktype::NULL => Ok(LinkLayer::Null),
        other => Err(anyhow!("unsupported Npcap datalink type {}", other.0)),
    }
}

fn answer_index(answer: &SynAnswer, targets: &[Ipv4Addr], ports: &[u16]) -> Option<usize> {
    let host_index = targets.binary_search(&answer.host).ok()?;
    let port_index = ports.binary_search(&answer.port).ok()?;
    port_index
        .checked_mul(targets.len())?
        .checked_add(host_index)
}

enum CaptureMessage {
    Answer(SynAnswer),
}

#[derive(Default)]
struct CaptureFailure(Mutex<Option<String>>);

impl CaptureFailure {
    fn record(&self, error: String) {
        let mut stored = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if stored.is_none() {
            *stored = Some(error);
        }
    }

    fn check(&self) -> Result<()> {
        let stored = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match stored.as_ref() {
            Some(error) => Err(anyhow!(error.clone())),
            None => Ok(()),
        }
    }
}

fn queue_capture_answer(
    sender: &mpsc::SyncSender<CaptureMessage>,
    answer: SynAnswer,
    failure: &CaptureFailure,
) -> bool {
    match sender.try_send(CaptureMessage::Answer(answer)) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(_)) => {
            failure.record("Npcap capture answer queue overflow".to_string());
            false
        }
        Err(mpsc::TrySendError::Disconnected(_)) => false,
    }
}

struct CaptureReaders {
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    failure: Arc<CaptureFailure>,
}

impl CaptureReaders {
    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Release);
        for handle in self.handles.drain(..) {
            if handle.join().is_err() {
                self.failure
                    .record("Npcap capture reader panicked".to_string());
            }
        }
    }

    fn finish(&mut self) -> Result<()> {
        self.stop_and_join();
        self.failure.check()
    }
}

impl Drop for CaptureReaders {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn spawn_capture_reader(
    device: Device,
    source_port: u16,
    secret: u64,
    stop: Arc<AtomicBool>,
    ready: mpsc::Sender<Result<(), String>>,
    answers: mpsc::SyncSender<CaptureMessage>,
    failure: Arc<CaptureFailure>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let panic_failure = failure.clone();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let opened = Capture::from_device(device.clone())
                .and_then(|capture| {
                    capture
                        .immediate_mode(true)
                        .timeout(CAPTURE_READ_TIMEOUT_MS)
                        .open()
                })
                .map_err(|error| format!("could not open Npcap device {}: {error}", device.name));
            let mut capture = match opened {
                Ok(capture) => capture,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            let link = match link_for_datalink(capture.get_datalink()) {
                Ok(link) => link,
                Err(error) => {
                    let _ = ready.send(Err(error.to_string()));
                    return;
                }
            };
            if let Err(error) = capture.filter(&format!("tcp and dst port {source_port}"), true) {
                let _ = ready.send(Err(format!(
                    "could not apply Npcap filter on {}: {error}",
                    device.name
                )));
                return;
            }
            if ready.send(Ok(())).is_err() {
                return;
            }

            while !stop.load(Ordering::Acquire) {
                match capture.next_packet() {
                    Ok(packet) => {
                        if let Some(answer) = parse_syn_reply(link, packet.data, secret) {
                            if !queue_capture_answer(&answers, answer, &failure) {
                                return;
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(error) => {
                        failure.record(format!("Npcap receive failed on {}: {error}", device.name));
                        return;
                    }
                }
            }
        }));
        if outcome.is_err() {
            panic_failure.record("Npcap capture reader panicked".to_string());
        }
    })
}

fn drain_answers(
    receiver: &mpsc::Receiver<CaptureMessage>,
    states: &mut ProbeStates,
    targets: &[Ipv4Addr],
    ports: &[u16],
    failure: &CaptureFailure,
) -> Result<()> {
    failure.check()?;
    loop {
        match receiver.try_recv() {
            Ok(CaptureMessage::Answer(answer)) => {
                if let Some(index) = answer_index(&answer, targets, ports) {
                    states.record(index, answer.reply);
                }
            }
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => {
                return failure.check()
            }
        }
    }
}

async fn collect_until(
    deadline: Instant,
    receiver: &mpsc::Receiver<CaptureMessage>,
    states: &mut ProbeStates,
    targets: &[Ipv4Addr],
    ports: &[u16],
    failure: &CaptureFailure,
) -> Result<()> {
    while Instant::now() < deadline {
        drain_answers(receiver, states, targets, ports, failure)?;
        sleep(RESPONSE_POLL_INTERVAL).await;
    }
    drain_answers(receiver, states, targets, ports, failure)
}

fn sweep_secret() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    hasher.write_u64(now.as_secs());
    hasher.write_u32(now.subsec_nanos());
    hasher.finish()
}

fn source_port(secret: u64) -> u16 {
    49_152 + (secret % 16_384) as u16
}

pub async fn run_syn_sweep(
    targets: &[Ipv4Addr],
    ports: &[u16],
    config: SynSweepConfig,
) -> Result<ProbeStates> {
    if targets.is_empty() || ports.is_empty() {
        return Ok(ProbeStates::new(0));
    }
    if config.timeout.is_zero() {
        return Err(anyhow!("SYN response timeout must be greater than zero"));
    }
    if config.rate_limit_per_sec == 0 {
        return Err(anyhow!("SYN rate limit must be greater than zero"));
    }
    if config.retries > 2 {
        return Err(anyhow!("SYN retries must be between 0 and 2"));
    }

    let total = targets
        .len()
        .checked_mul(ports.len())
        .ok_or_else(|| anyhow!("SYN probe count overflow"))?;
    let devices = Device::list().context("could not list Npcap devices")?;
    let mut routes = Vec::with_capacity(targets.len());
    let mut adapter_devices = BTreeMap::<u32, Device>::new();
    for &target in targets {
        let route = resolve_route(target)
            .with_context(|| format!("could not route SYN target {target}"))?;
        ensure_remote_target(target, route.source_ip)?;
        let device = pcap_device_for_interface(route.interface_index, &devices)
            .with_context(|| format!("could not map SYN target {target} to Npcap"))?;
        if let Some(existing) = adapter_devices.get(&route.interface_index) {
            if !existing.name.eq_ignore_ascii_case(&device.name) {
                return Err(anyhow!(
                    "interface {} mapped to multiple Npcap device names",
                    route.interface_index
                ));
            }
        } else {
            adapter_devices.insert(route.interface_index, device);
        }
        routes.push(route);
    }

    let secret = sweep_secret();
    let source_port = source_port(secret);
    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = mpsc::channel();
    let (answer_tx, answer_rx) = mpsc::sync_channel(ANSWER_QUEUE_CAPACITY);
    let capture_failure = Arc::new(CaptureFailure::default());
    let mut readers = CaptureReaders {
        stop: stop.clone(),
        handles: Vec::with_capacity(adapter_devices.len()),
        failure: capture_failure.clone(),
    };
    for device in adapter_devices.values().cloned() {
        readers.handles.push(spawn_capture_reader(
            device,
            source_port,
            secret,
            stop.clone(),
            ready_tx.clone(),
            answer_tx.clone(),
            capture_failure.clone(),
        ));
    }
    drop(ready_tx);
    drop(answer_tx);
    for _ in 0..adapter_devices.len() {
        let status = ready_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| anyhow!("timed out while opening an Npcap capture device"))?;
        status.map_err(|error| anyhow!(error))?;
    }

    let mut senders = BTreeMap::<u32, Capture<Active>>::new();
    for (&interface_index, device) in &adapter_devices {
        let sender = Capture::from_device(device.clone())
            .and_then(Capture::open)
            .with_context(|| format!("could not open Npcap sender on {}", device.name))?;
        senders.insert(interface_index, sender);
    }

    let limiter = RateLimiter::new(effective_rate(config.rate_limit_per_sec));
    let mut states = ProbeStates::new(total);
    let mut ip_id = 1_u16;
    for round in 0..=config.retries {
        if round > 0 && states.unanswered_indices().next().is_none() {
            break;
        }
        for index in probe_indices(targets.len(), ports.len()) {
            drain_answers(&answer_rx, &mut states, targets, ports, &capture_failure)?;
            if round > 0 && states.get(index) != ProbeState::Unanswered {
                continue;
            }
            limiter.wait().await;
            let (host_index, port_index) = probe_coordinates(index, targets.len());
            let route: Route = routes[host_index];
            let target = targets[host_index];
            let port = ports[port_index];
            let cookie = syn_cookie(secret, target, port, source_port);
            let frame = build_syn_frame(
                route.link,
                route.source_ip,
                target,
                source_port,
                port,
                cookie,
                ip_id,
            );
            ip_id = ip_id.wrapping_add(1);
            senders
                .get_mut(&route.interface_index)
                .ok_or_else(|| {
                    anyhow!(
                        "missing Npcap sender for interface {}",
                        route.interface_index
                    )
                })?
                .sendpacket(&frame[..])
                .with_context(|| format!("could not send SYN to {target}:{port}"))?;
        }
        collect_until(
            Instant::now() + config.timeout,
            &answer_rx,
            &mut states,
            targets,
            ports,
            &capture_failure,
        )
        .await?;
    }
    readers.finish()?;
    Ok(states)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pcap::Linktype;

    use crate::syn_sweep::{LinkLayer, SynAnswer};

    use super::*;

    #[test]
    fn packs_four_probe_states_into_one_byte() {
        let mut states = ProbeStates::new(4);
        states.record(0, SynReply::Open);
        states.record(1, SynReply::Closed);

        assert_eq!(states.storage_bytes(), 1);
        assert_eq!(states.get(0), ProbeState::Open);
        assert_eq!(states.get(1), ProbeState::Closed);
        assert_eq!(states.get(2), ProbeState::Unanswered);
        assert_eq!(states.get(3), ProbeState::Unanswered);
    }

    #[test]
    fn duplicate_replies_do_not_change_state_twice() {
        let mut states = ProbeStates::new(1);

        assert!(states.record(0, SynReply::Closed));
        assert!(!states.record(0, SynReply::Closed));
    }

    #[test]
    fn an_open_reply_wins_over_a_later_reset() {
        let mut states = ProbeStates::new(1);

        assert!(states.record(0, SynReply::Open));
        assert!(!states.record(0, SynReply::Closed));
        assert_eq!(states.get(0), ProbeState::Open);
    }

    #[test]
    fn a_later_open_reply_upgrades_a_closed_observation() {
        let mut states = ProbeStates::new(1);

        assert!(states.record(0, SynReply::Closed));
        assert!(states.record(0, SynReply::Open));
        assert_eq!(states.get(0), ProbeState::Open);
    }

    #[test]
    fn retry_indices_contain_only_unanswered_probes() {
        let mut states = ProbeStates::new(5);
        states.record(1, SynReply::Open);
        states.record(3, SynReply::Closed);

        assert_eq!(
            states.unanswered_indices().collect::<Vec<_>>(),
            vec![0, 2, 4]
        );
    }

    #[test]
    fn probe_order_spreads_each_port_across_hosts() {
        let order = probe_indices(3, 2).collect::<Vec<_>>();

        assert_eq!(order, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(probe_coordinates(4, 3), (1, 1));
    }

    #[test]
    fn syn_rate_is_capped_at_five_thousand() {
        assert_eq!(effective_rate(400), 400);
        assert_eq!(effective_rate(50_000), 5_000);
    }

    #[test]
    fn rejects_a_selected_local_interface_address() {
        let local = Ipv4Addr::new(192, 0, 2, 10);

        assert!(ensure_remote_target(local, local)
            .unwrap_err()
            .to_string()
            .contains("local interface"));
        assert!(ensure_remote_target(Ipv4Addr::new(192, 0, 2, 11), local).is_ok());
    }

    #[test]
    fn accepts_only_ethernet_and_null_datalinks() {
        assert_eq!(
            link_for_datalink(Linktype::ETHERNET).unwrap(),
            LinkLayer::Ethernet {
                source_mac: [0; 6],
                next_hop_mac: [0; 6],
            }
        );
        assert_eq!(link_for_datalink(Linktype::NULL).unwrap(), LinkLayer::Null);
        assert!(link_for_datalink(Linktype(12)).is_err());
    }

    #[test]
    fn maps_a_reply_back_to_its_port_major_probe_index() {
        let targets = [Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)];
        let ports = [22, 80, 443];
        let answer = SynAnswer {
            host: targets[1],
            port: 80,
            reply: SynReply::Open,
        };

        assert_eq!(answer_index(&answer, &targets, &ports), Some(3));
    }

    #[test]
    fn ignores_a_cookie_valid_reply_outside_the_requested_workload() {
        let targets = [Ipv4Addr::new(10, 0, 0, 1)];
        let ports = [443];
        let answer = SynAnswer {
            host: Ipv4Addr::new(10, 0, 0, 2),
            port: 443,
            reply: SynReply::Open,
        };

        assert_eq!(answer_index(&answer, &targets, &ports), None);
    }

    #[test]
    fn a_full_capture_queue_fails_instead_of_blocking() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let failure = CaptureFailure::default();
        let answer = SynAnswer {
            host: Ipv4Addr::new(10, 0, 0, 1),
            port: 443,
            reply: SynReply::Open,
        };

        assert!(queue_capture_answer(&sender, answer, &failure));
        assert!(!queue_capture_answer(&sender, answer, &failure));
        assert!(failure.check().unwrap_err().to_string().contains("queue"));
    }

    #[test]
    fn a_panicked_capture_reader_fails_the_sweep() {
        let failure = Arc::new(CaptureFailure::default());
        let mut readers = CaptureReaders {
            stop: Arc::new(AtomicBool::new(false)),
            handles: vec![std::thread::spawn(|| panic!("capture died"))],
            failure,
        };

        assert!(readers
            .finish()
            .unwrap_err()
            .to_string()
            .contains("panicked"));
    }
}
