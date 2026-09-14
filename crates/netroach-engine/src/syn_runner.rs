//! Windows/Npcap orchestration for the optional IPv4 SYN sweep.
#![cfg(all(windows, feature = "syn-sweep"))]

use anyhow::{anyhow, Context, Result};
use pcap::sendqueue::{SendQueue, SendSync};
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
use windows_sys::Win32::System::LibraryLoader::{
    LoadLibraryA, LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH,
};

use crate::netlink::{self, pcap_device_for_interface, resolve_route, Route};
use crate::syn_sweep::{
    build_rst_frame, build_syn_frame, parse_syn_reply, syn_cookie, LinkLayer, SynAnswer, SynReply,
};
use crate::RateLimiter;

/// The rate a sweep may use however few hosts it has, and the floor the
/// per-host allowance is measured against: no workload sweeps slower than this
/// because of the spread rule.
///
/// Set where the measured answer stops depending on luck. Against the same
/// gateway over 512 ports with one retry: at 5,000 a second the open port was
/// missed outright; at 1,000 it was found two runs in three with thirty to
/// fifty ports left unanswered; at 500 it was found every run with none. The
/// unanswered count tracked it exactly - the run that missed the port had
/// thirty-eight of them - which is why that count is the reliability gauge.
///
/// Tuned against one device, so it is a defensible default rather than a
/// guarantee: a target that rate-limits harder will still leave ports
/// unanswered, and that is the signal to lower the rate again.
const SYN_RATE_FLOOR_PER_SEC: u64 = 500;
/// The cap on the connect follow-up that probes services on the ports a sweep
/// found open. Connect keeps its own state and the OS retransmits for it, so it
/// is not subject to the loss the sweep floor is set against.
const SYN_FOLLOW_UP_RATE_PER_SEC: u64 = 5_000;
/// What one host may be asked to answer per second.
///
/// Probes go out port-major, so a wide sweep's rate is shared across its hosts:
/// at 5,000 a second over three thousand hosts each device sees under two
/// packets a second, which is far gentler than the single-host case the 5,000
/// was chosen to survive. Budgeting per host lets a wide sweep go as fast as
/// the hosts in it can carry, rather than pacing every scan as if it were
/// pointed at one fragile device.
const SYN_PER_HOST_RATE_PER_SEC: u64 = 10;
/// The most this machine will send however wide the sweep.
///
/// Measured on the scanning machine with batched sends: the rate tracked the
/// setting to about 20,000 a second and levelled off near 35,000. Past that the
/// setting is a number the send path cannot meet, and the link and the capture
/// side have to carry it too.
const SYN_RATE_CEILING_PER_SEC: u64 = 35_000;
const RESPONSE_POLL_INTERVAL: Duration = Duration::from_millis(5);
const CAPTURE_READ_TIMEOUT_MS: i32 = 100;
const ANSWER_QUEUE_CAPACITY: usize = 16_384;
const PROGRESS_REPORT_INTERVAL: Duration = Duration::from_secs(1);
/// Frames handed to the driver in one call.
///
/// Sending one frame per call costs a driver round trip each time, which held
/// the sweep to about 2,400 probes a second however high the rate was set - the
/// call, not the rate limit, was the ceiling. Npcap takes a queue of frames in
/// a single call, and the cost is paid once for the batch.
const SEND_BATCH_MAX: usize = 256;
/// Bytes reserved per queued frame: a SYN frame plus the per-packet header the
/// queue stores alongside it, rounded up with room to spare.
const SEND_QUEUE_BYTES_PER_FRAME: u32 = 256;
/// Neighbour lookups that may be in flight at once.
///
/// An address on this segment that nothing answers for costs about 3.2
/// seconds, measured against empty addresses on the scanning machine's own
/// subnet, where Windows retransmits its ARP and then gives up. Asked one
/// after another, a /24 holding thirty live machines spends twelve minutes on
/// the two hundred that are gone before one SYN reaches the wire, and the
/// progress strip has nothing to show because no probe has been sent yet.
///
/// The wait belongs to the kernel rather than this machine, so the threads are
/// asleep and the number is not a core count. It is held down instead by what
/// is on the wire: an ARP request is a broadcast every host on the segment
/// takes in, so this is how many of those may be outstanding at once. Sixty
/// four clears a /24 in about thirteen seconds while keeping that broadcast
/// well under what an ordinary host does when it boots.
const ARP_RESOLVE_THREADS: usize = 64;

/// How many frames to gather before handing them to the driver.
///
/// Capped by the host count because probes go out port-major, one per host in
/// turn: a batch no larger than the number of hosts puts at most one frame per
/// host in each burst, which keeps the smoothness the ordering exists to give.
/// A single-host sweep therefore batches one frame - it is already fast enough,
/// and bursting at one device is what the rate limit is there to prevent.
fn send_batch_size(host_count: usize) -> usize {
    host_count.clamp(1, SEND_BATCH_MAX)
}

#[derive(Clone, Copy, Debug)]
pub struct SynSweepConfig {
    pub timeout: Duration,
    pub rate_limit_per_sec: u64,
    pub retries: u8,
}

/// How far a running sweep has got.
///
/// A sweep holds every result back until the last retry has settled, so without
/// this a scan of tens of millions of probes shows nothing at all for an hour
/// and cannot be told apart from one that never started. Reported separately
/// from results so the results themselves stay final when they are written: a
/// closed probe can still be upgraded to open by a later reply, and publishing
/// one early would put a wrong state in the report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SweepProgress {
    /// Which pass this is: 0 is the first sweep, then one per retry.
    pub round: u8,
    /// Probes sent in this round.
    pub sent: usize,
    /// Probes this round set out to send.
    pub round_total: usize,
    /// Probes with a definite state so far, across all rounds.
    pub answered: usize,
    /// Probes in the whole sweep.
    pub total: usize,
}

/// What a sweep found, and which hosts it could not address at all.
#[derive(Debug)]
pub struct SweepOutcome {
    pub states: ProbeStates,
    /// Hosts that never answered ARP, so nothing was sent to them. Their probes
    /// are unanswered because they were never asked, which is a different thing
    /// from a port that stayed quiet.
    pub unreachable: std::collections::HashMap<Ipv4Addr, &'static str>,
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
    // Counted as answers land, because progress is reported while a sweep of
    // tens of millions of probes runs and scanning the bitmap for each report
    // would cost more than the sweep it is reporting on.
    answered: usize,
}

impl ProbeStates {
    pub fn new(len: usize) -> Self {
        Self {
            bytes: vec![0; len.div_ceil(4)],
            len,
            answered: 0,
        }
    }

    /// How many probes have a definite state. The rest are still unanswered.
    pub fn answered(&self) -> usize {
        self.answered
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
        if current == ProbeState::Unanswered {
            self.answered += 1;
        }
        let shift = (index % 4) * 2;
        let mask = 0b11 << shift;
        self.bytes[index / 4] = (self.bytes[index / 4] & !mask) | ((next as u8) << shift);
        true
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
    requested.min(SYN_FOLLOW_UP_RATE_PER_SEC)
}

/// The rate a sweep of this many hosts may use.
///
/// The per-host budget only ever raises the ceiling: a sweep is allowed the
/// greater of the flat limit and what its hosts can carry between them, and
/// never more than the machine can send or the caller asked for. A narrow sweep
/// therefore paces exactly as it did before this existed, and a wide one is no
/// longer held to a rate chosen for a single device.
pub(crate) fn sweep_rate(requested: u64, host_count: usize) -> u64 {
    let spread = (host_count as u64).saturating_mul(SYN_PER_HOST_RATE_PER_SEC);
    let allowed = spread
        .max(SYN_RATE_FLOOR_PER_SEC)
        .min(SYN_RATE_CEILING_PER_SEC);
    requested.min(allowed)
}

/// Whether the loader can resolve this library on this machine.
fn library_loadable(name: &std::ffi::CStr) -> bool {
    // SAFETY: a null-terminated string, and the handle is only tested. Not
    // freed: where it resolves, this is a library the caller is about to use
    // anyway, and dropping our reference would buy nothing.
    !unsafe { LoadLibraryA(name.as_ptr().cast()) }.is_null()
}

/// Where Npcap puts its libraries, which is not a directory the loader searches.
fn npcap_directory() -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    std::path::PathBuf::from(root).join("System32").join("Npcap")
}

/// Load a library by its full path, letting its own directory satisfy what it
/// depends on in turn - wpcap needs Packet.dll from beside it.
fn load_library_from(path: &std::path::Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: a null-terminated wide path, and the handle is only tested.
    !unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            LOAD_WITH_ALTERED_SEARCH_PATH,
        )
    }
    .is_null()
}

/// Put Npcap's library in this process, or say why the sweep cannot run.
///
/// Two things make this necessary. wpcap is delay-loaded so the engine starts
/// and scans by connect without the driver - see build.rs - and an unresolved
/// delay-load raises a Win32 exception at the first pcap call rather than
/// returning, which would end the process mid-scan with nothing said.
///
/// And the loader does not find Npcap on its own. Npcap installs its libraries
/// into System32\Npcap, which is not on the default search path; only its
/// optional "Install Npcap in WinPcap API-compatible Mode" also drops a copy in
/// System32 where a plain load finds it. Left to the default search, an install
/// without that option reads as no install at all - a machine that can sweep
/// being told to go and install what it already has. So the directory is tried
/// by name too.
///
/// Loading it here is what makes the delay-load work afterwards: a later
/// resolution of "wpcap.dll" finds the module already in the process rather
/// than searching for it again.
fn ensure_npcap_present() -> Result<()> {
    if library_loadable(c"wpcap.dll") || load_library_from(&npcap_directory().join("wpcap.dll")) {
        return Ok(());
    }
    Err(anyhow!(
        "Npcap was not found on this machine, so the SYN sweep has no driver to send through. \
         Install it from the official Npcap installer, leaving \"Restrict Npcap driver's access \
         to Administrators only\" unchecked, and start Netroach again - or run this scan with TCP \
         connect scanning, which needs no driver. Looked for wpcap.dll on the library search \
         path and in {}.",
        npcap_directory().display()
    ))
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

/// Whether a slice is ascending with no duplicates, which is what the binary
/// searches in `answer_index` need to find a reply's probe slot.
fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

/// The probe slot a reply belongs to, or None when it names a host or port this
/// run did not probe.
///
/// The binary searches require `targets` and `ports` to be sorted; on unsorted
/// input they report "not found" rather than failing, which would drop a real
/// SYN-ACK and leave its probe looking unanswered - an open port reported as
/// filtered, with nothing to show anything went wrong. `run_syn_sweep` rejects
/// unsorted input up front so that cannot happen quietly.
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

            let mut read_loop = || {
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
                            failure.record(format!(
                                "Npcap receive failed on {}: {error}",
                                device.name
                            ));
                            return;
                        }
                    }
                }
            };
            read_loop();
            // A reply the driver threw away is a probe that looks unanswered,
            // which is an open port reported as filtered. The counter is the
            // only sign it happened, so a sweep that lost replies says so
            // rather than returning a clean-looking result.
            if let Ok(stats) = capture.stats() {
                let lost = stats.dropped.saturating_add(stats.if_dropped);
                if lost > 0 {
                    failure.record(format!(
                        "Npcap dropped {lost} captured packets on {}; replies were lost, so a                          port answered during the loss reads as filtered. Lower the rate and                          run again.",
                        device.name
                    ));
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
    opened: &mut Vec<(Ipv4Addr, u16)>,
) -> Result<()> {
    failure.check()?;
    loop {
        match receiver.try_recv() {
            Ok(CaptureMessage::Answer(answer)) => {
                if let Some(index) = answer_index(&answer, targets, ports) {
                    // Only the first time: a retransmitted SYN-ACK would
                    // otherwise have us reset a connection already closed.
                    if states.record(index, answer.reply) && answer.reply == SynReply::Open {
                        opened.push((answer.host, answer.port));
                    }
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
    opened: &mut Vec<(Ipv4Addr, u16)>,
) -> Result<()> {
    while Instant::now() < deadline {
        drain_answers(receiver, states, targets, ports, failure, opened)?;
        sleep(RESPONSE_POLL_INTERVAL).await;
    }
    drain_answers(receiver, states, targets, ports, failure, opened)
}

/// Hand one adapter's queued frames to the driver in a single call.
///
/// Does nothing for an empty queue, so the end-of-round flush can run over
/// every adapter without caring which ones have work left.
fn flush_queue(
    queues: &mut BTreeMap<u32, SendQueue>,
    senders: &mut BTreeMap<u32, Capture<Active>>,
    queued: &mut BTreeMap<u32, usize>,
    interface_index: u32,
) -> Result<()> {
    let pending = queued.entry(interface_index).or_insert(0);
    if *pending == 0 {
        return Ok(());
    }
    let queue = queues
        .get_mut(&interface_index)
        .ok_or_else(|| anyhow!("missing Npcap send queue for interface {interface_index}"))?;
    let sender = senders
        .get_mut(&interface_index)
        .ok_or_else(|| anyhow!("missing Npcap sender for interface {interface_index}"))?;
    // The frames are already paced by the rate limiter as they were queued, so
    // the driver sends them back to back rather than re-timing them.
    queue.transmit(sender, SendSync::Off).with_context(|| {
        format!("could not send queued SYN frames on interface {interface_index}")
    })?;
    *pending = 0;
    Ok(())
}

/// Reset the half-open connections the last drain found, giving each target
/// its backlog slot back instead of leaving it held until the target times out.
///
/// The resets share the probes' rate limiter and their send batch. Paced,
/// because a reset is a frame arriving at the target like any other and the
/// per-host budget the sweep is held to means nothing if one more frame per
/// probe goes out beside it unmetered - a host with many ports open is exactly
/// where that doubling lands. Batched, because flushing each reset on its own
/// cost a driver round trip per open port, which is the cost `SEND_BATCH_MAX`
/// exists to avoid. Whatever is left queued flies on the round's final flush.
#[allow(clippy::too_many_arguments)]
async fn close_opened(
    opened: &mut Vec<(Ipv4Addr, u16)>,
    targets: &[Ipv4Addr],
    routes: &[Option<Route>],
    queues: &mut BTreeMap<u32, SendQueue>,
    senders: &mut BTreeMap<u32, Capture<Active>>,
    queued: &mut BTreeMap<u32, usize>,
    limiter: &RateLimiter,
    batch_size: usize,
    secret: u64,
    source_port: u16,
    ip_id: &mut u16,
) -> Result<()> {
    for (host, port) in opened.drain(..) {
        let Ok(host_index) = targets.binary_search(&host) else {
            continue;
        };
        let Some(route) = routes[host_index] else {
            continue;
        };
        limiter.wait().await;
        // The target is waiting to hear the sequence after our SYN's.
        let sequence = syn_cookie(secret, host, port, source_port).wrapping_add(1);
        let frame = build_rst_frame(
            route.link,
            route.source_ip,
            host,
            source_port,
            port,
            sequence,
            *ip_id,
        );
        *ip_id = ip_id.wrapping_add(1);
        if let Some(queue) = queues.get_mut(&route.interface_index) {
            queue
                .queue(None, &frame[..])
                .with_context(|| format!("could not queue RST to {host}:{port}"))?;
            let pending = queued.entry(route.interface_index).or_insert(0);
            *pending += 1;
            if *pending >= batch_size {
                flush_queue(queues, senders, queued, route.interface_index)?;
            }
        }
    }
    Ok(())
}

/// Apply `f` to every item at once, keeping the input order.
///
/// The order is the whole point: the caller pairs each answer with the target
/// at the same index, so a merge that returned them out of order would address
/// frames to the wrong hosts rather than fail. Each thread takes one contiguous
/// slice, which is enough because the case this exists for - a segment full of
/// addresses nothing answers for - costs the same for every item, leaving
/// nothing for work stealing to even out.
fn map_in_parallel<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Result<Vec<R>> {
    let threads = threads.min(items.len()).max(1);
    // Never zero: `chunks` panics on a zero width, which an empty input would
    // otherwise produce.
    let per_thread = items.len().div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = items
            .chunks(per_thread)
            .map(|slice| scope.spawn(|| slice.iter().map(&f).collect::<Vec<_>>()))
            .collect();
        let mut mapped = Vec::with_capacity(items.len());
        for handle in handles {
            match handle.join() {
                Ok(slice) => mapped.extend(slice),
                Err(_) => return Err(anyhow!("a parallel worker thread panicked")),
            }
        }
        Ok(mapped)
    })
}

/// Resolve every target's route, several at a time.
fn resolve_routes(targets: &[Ipv4Addr]) -> Result<Vec<Result<Route, netlink::RouteError>>> {
    map_in_parallel(targets, ARP_RESOLVE_THREADS, |&target| {
        resolve_route(target)
    })
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
    mut on_progress: impl FnMut(SweepProgress),
) -> Result<SweepOutcome> {
    if targets.is_empty() || ports.is_empty() {
        return Ok(SweepOutcome {
            states: ProbeStates::new(0),
            unreachable: std::collections::HashMap::new(),
        });
    }
    if !is_sorted_unique(targets) {
        return Err(anyhow!("SYN targets must be sorted and unique"));
    }
    if !is_sorted_unique(ports) {
        return Err(anyhow!("SYN ports must be sorted and unique"));
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
    // Before the first pcap call, which is the device list below.
    ensure_npcap_present()?;

    let total = targets
        .len()
        .checked_mul(ports.len())
        .ok_or_else(|| anyhow!("SYN probe count overflow"))?;
    let devices = Device::list().context("could not list Npcap devices")?;
    let mut routes: Vec<Option<Route>> = Vec::with_capacity(targets.len());
    // Hosts nothing is sent to, and why. Their probes are unanswered because
    // they were never asked, which is a different thing from a port that stayed
    // quiet, and the two reasons are different from each other.
    let mut unreachable = std::collections::HashMap::<Ipv4Addr, &'static str>::new();
    let mut adapter_devices = BTreeMap::<u32, Device>::new();
    // Every target's route is resolved before this loop rather than inside it.
    // A dead address on this segment costs seconds of ARP each, and asking one
    // at a time put that cost end to end ahead of the first probe.
    let resolved = resolve_routes(targets)?;
    for (&target, resolution) in targets.iter().zip(resolved) {
        // A host that will not answer ARP is down, and there is nothing to
        // address a frame to. Skipped rather than failing the run: an empty
        // address is the ordinary case in a subnet sweep, and failing over one
        // would stop the scan the way a self-address once did.
        let route = match resolution {
            Ok(route) => route,
            Err(netlink::RouteError::NoNextHopMac(_)) => {
                unreachable.insert(target, "host did not answer ARP; no probe was sent");
                routes.push(None);
                continue;
            }
            Err(error) => {
                return Err(anyhow!("could not route SYN target {target}: {error}"));
            }
        };
        ensure_remote_target(target, route.source_ip)?;
        // A broadcast next hop puts the frame in front of every host on the
        // segment, and every one with that port open answers. The replies carry
        // their own addresses so none of them match the probe, so it is a
        // segment-wide disturbance that cannot even produce a result.
        if let LinkLayer::Ethernet { next_hop_mac, .. } = route.link {
            if next_hop_mac == [0xFF; 6] {
                unreachable.insert(
                    target,
                    "broadcast address; a sweep will not send to the whole segment",
                );
                routes.push(None);
                continue;
            }
        }
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
        routes.push(Some(route));
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

    // Sized by the hosts actually sent to. Sizing it by the targets asked for
    // made a batch of two hundred frames land on the one host that answered
    // ARP, which is the burst the cap exists to prevent.
    let probed_hosts = targets.len().saturating_sub(unreachable.len());
    let batch_size = send_batch_size(probed_hosts);
    let queue_bytes = (batch_size as u32 + 1) * SEND_QUEUE_BYTES_PER_FRAME;
    let mut senders = BTreeMap::<u32, Capture<Active>>::new();
    let mut queues = BTreeMap::<u32, SendQueue>::new();
    // Counted rather than read back from the queue: its own len() is the bytes
    // it holds, not the number of frames.
    let mut queued = BTreeMap::<u32, usize>::new();
    for (&interface_index, device) in &adapter_devices {
        let sender = Capture::from_device(device.clone())
            .and_then(Capture::open)
            .with_context(|| format!("could not open Npcap sender on {}", device.name))?;
        senders.insert(interface_index, sender);
        let queue = SendQueue::new(queue_bytes)
            .with_context(|| format!("could not allocate a send queue for {}", device.name))?;
        queues.insert(interface_index, queue);
    }

    // Budgeted over the hosts that will actually be sent to, not the targets
    // asked for. Skipping the ones that never answered ARP would otherwise
    // concentrate the whole rate on the few that remain: a /24 with two live
    // hosts would hit each of them with what was budgeted for two hundred.
    let limiter = RateLimiter::new(sweep_rate(config.rate_limit_per_sec, probed_hosts));
    let mut states = ProbeStates::new(total);
    let mut ip_id = 1_u16;
    // Ports found open since the last reset went out. Each holds a slot in its
    // target's backlog until we close it.
    let mut opened = Vec::<(Ipv4Addr, u16)>::new();
    let mut reported_at = Instant::now();
    for round in 0..=config.retries {
        let round_total = if round == 0 {
            total
        } else {
            total - states.answered()
        };
        if round > 0 && round_total == 0 {
            break;
        }
        let mut sent = 0usize;
        on_progress(SweepProgress {
            round,
            sent,
            round_total,
            answered: states.answered(),
            total,
        });
        for index in probe_indices(targets.len(), ports.len()) {
            drain_answers(
                &answer_rx,
                &mut states,
                targets,
                ports,
                &capture_failure,
                &mut opened,
            )?;
            close_opened(
                &mut opened,
                targets,
                &routes,
                &mut queues,
                &mut senders,
                &mut queued,
                &limiter,
                batch_size,
                secret,
                source_port,
                &mut ip_id,
            )
            .await?;
            if round > 0 && states.get(index) != ProbeState::Unanswered {
                continue;
            }
            let (host_index, port_index) = probe_coordinates(index, targets.len());
            let Some(route) = routes[host_index] else {
                // Nothing is sent, so nothing is paced: letting a skipped host
                // hold a slot spread one live host's probes over the whole run.
                continue;
            };
            limiter.wait().await;
            sent += 1;
            // Reported on a clock rather than a probe count: the useful signal
            // is that the sweep is still moving, and at 5,000 probes a second a
            // count-based tick would either flood the log or crawl.
            if reported_at.elapsed() >= PROGRESS_REPORT_INTERVAL {
                reported_at = Instant::now();
                on_progress(SweepProgress {
                    round,
                    sent,
                    round_total,
                    answered: states.answered(),
                    total,
                });
            }
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
            let queue = queues.get_mut(&route.interface_index).ok_or_else(|| {
                anyhow!(
                    "missing Npcap send queue for interface {}",
                    route.interface_index
                )
            })?;
            queue
                .queue(None, &frame[..])
                .with_context(|| format!("could not queue SYN to {target}:{port}"))?;
            let pending = queued.entry(route.interface_index).or_insert(0);
            *pending += 1;
            if *pending >= batch_size {
                flush_queue(
                    &mut queues,
                    &mut senders,
                    &mut queued,
                    route.interface_index,
                )?;
            }
        }
        // Whatever is left over from the last partial batch still has to fly,
        // or those probes are never sent and read as filtered.
        for &interface_index in adapter_devices.keys() {
            flush_queue(&mut queues, &mut senders, &mut queued, interface_index)?;
        }
        on_progress(SweepProgress {
            round,
            sent,
            round_total,
            answered: states.answered(),
            total,
        });
        collect_until(
            Instant::now() + config.timeout,
            &answer_rx,
            &mut states,
            targets,
            ports,
            &capture_failure,
            &mut opened,
        )
        .await?;
        close_opened(
            &mut opened,
            targets,
            &routes,
            &mut queues,
            &mut senders,
            &mut queued,
            &limiter,
            batch_size,
            secret,
            source_port,
            &mut ip_id,
        )
        .await?;
        // The resets this round's last drain produced are queued, not sent:
        // they ride the send batch now rather than paying a driver round trip
        // each. Nothing else flushes after this point, so a target whose slot
        // this frees would otherwise hold it until it timed out.
        for &interface_index in adapter_devices.keys() {
            flush_queue(&mut queues, &mut senders, &mut queued, interface_index)?;
        }
    }
    readers.finish()?;
    Ok(SweepOutcome {
        states,
        unreachable,
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pcap::Linktype;

    use crate::syn_sweep::{LinkLayer, SynAnswer};

    use super::*;

    #[test]
    fn npcap_is_looked_for_in_its_own_directory_too() {
        // Npcap installs into System32\Npcap, which the loader does not search.
        // Only its optional WinPcap-compatible mode also drops a copy where a
        // plain load finds it, so without this an ordinary install reads as no
        // install and the operator is told to go and get what they have.
        let directory = npcap_directory();

        assert!(directory.ends_with(std::path::Path::new("System32").join("Npcap")));
        // The mechanism that reaches it: a full path resolves, a wrong one does
        // not. Checked against a library every Windows machine has, so the
        // answer does not depend on what is installed here.
        assert!(load_library_from(
            &npcap_directory()
                .parent()
                .expect("System32")
                .join("kernel32.dll")
        ));
        assert!(!load_library_from(std::path::Path::new(
            r"C:\netroach-no-such-directory\wpcap.dll"
        )));
    }

    #[test]
    fn a_missing_driver_is_told_apart_from_a_present_one() {
        // The sweep asks this before its first pcap call, because wpcap is
        // delay-loaded: an unresolved delay-load raises a Win32 exception
        // instead of returning, which would end the process mid-scan with
        // nothing said. A wrong answer either way is therefore either a scan
        // refused on a machine that could run it, or that silent ending.
        assert!(library_loadable(c"kernel32.dll"));
        assert!(!library_loadable(c"netroach-no-such-library.dll"));
    }

    #[test]
    fn a_parallel_map_answers_in_the_order_it_was_asked() {
        // Enough items to be split over every thread, and a function whose
        // answer names its own input, so a chunk merged out of order shows up
        // as a value in the wrong slot rather than as a missing one.
        let items: Vec<usize> = (0..1_000).collect();

        let doubled = map_in_parallel(&items, ARP_RESOLVE_THREADS, |item| item * 2).unwrap();

        assert_eq!(doubled.len(), items.len());
        assert!(doubled.iter().enumerate().all(|(at, got)| *got == at * 2));
    }

    #[test]
    fn a_parallel_map_over_nothing_starts_no_threads() {
        let empty: [usize; 0] = [];

        assert!(map_in_parallel(&empty, 8, |item| *item).unwrap().is_empty());
    }

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
    fn the_answered_count_drives_what_a_retry_round_resends() {
        // Counted rather than scanned: a retry round asks how much is left, and
        // walking tens of millions of probe slots to answer would cost more than
        // the round itself.
        let mut states = ProbeStates::new(5);
        states.record(1, SynReply::Open);
        states.record(3, SynReply::Closed);

        assert_eq!(states.answered(), 2);
        assert_eq!(
            (0..5)
                .filter(|&i| states.get(i) == ProbeState::Unanswered)
                .collect::<Vec<_>>(),
            vec![0, 2, 4]
        );
    }

    #[test]
    fn an_upgraded_probe_is_not_counted_answered_twice() {
        let mut states = ProbeStates::new(2);
        states.record(0, SynReply::Closed);
        states.record(0, SynReply::Open);

        assert_eq!(states.answered(), 1);
    }

    #[test]
    fn probe_order_spreads_each_port_across_hosts() {
        let order = probe_indices(3, 2).collect::<Vec<_>>();

        assert_eq!(order, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(probe_coordinates(4, 3), (1, 1));
    }

    #[test]
    fn the_per_host_budget_only_ever_raises_the_ceiling() {
        // The rule exists because a wide sweep shares its rate across hosts: at
        // the flat limit three thousand hosts see under two packets a second
        // each. It must never make a narrow sweep slower than it already was,
        // or a single-host scan would crawl at the per-host figure.
        assert_eq!(sweep_rate(100_000, 1), SYN_RATE_FLOOR_PER_SEC);
        assert_eq!(sweep_rate(100_000, 20), SYN_RATE_FLOOR_PER_SEC);
        // Above the floor the per-host budget governs, at ten a host exactly.
        assert_eq!(sweep_rate(100_000, 253), 2_530);

        // Past the point where the hosts can carry more between them, they do.
        assert_eq!(
            sweep_rate(100_000, 3_072),
            3_072 * SYN_PER_HOST_RATE_PER_SEC
        );

        // Never past what the machine can send, and never past what was asked.
        assert_eq!(sweep_rate(100_000, 1_000_000), SYN_RATE_CEILING_PER_SEC);
        assert_eq!(
            sweep_rate(800, 3_072),
            800,
            "the caller's limit still caps it"
        );
    }

    #[test]
    fn a_batch_never_puts_more_than_one_frame_per_host_in_a_burst() {
        // Probes go out port-major, one per host in turn, so a batch bounded by
        // the host count holds at most one frame for any host. That is what
        // keeps batching from turning the rate limit into a burst at one
        // device - the single-host sweep batches one frame and sends as before.
        assert_eq!(send_batch_size(1), 1);
        assert_eq!(send_batch_size(2), 2);
        assert_eq!(send_batch_size(253), 253);
        // And a wide scan stops growing the burst once the batch pays for
        // itself, rather than queueing a whole /16 before anything flies.
        assert_eq!(send_batch_size(65_536), SEND_BATCH_MAX);
        assert_eq!(
            send_batch_size(0),
            1,
            "an empty target list still sends nothing safely"
        );
    }

    #[test]
    fn syn_rate_is_capped_at_five_thousand() {
        assert_eq!(effective_rate(400), 400);
        assert_eq!(effective_rate(50_000), SYN_FOLLOW_UP_RATE_PER_SEC);
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
    fn unsorted_targets_would_lose_a_real_reply() {
        // Why run_syn_sweep refuses unsorted input: the search does not fail, it
        // reports "not found", so an open port would be recorded as filtered.
        // Some unsorted arrangements still answer correctly by luck, which is
        // the point - the result is unreliable rather than reliably wrong.
        let unsorted = [
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
            Ipv4Addr::new(10, 0, 0, 1),
        ];
        let ports = [80];
        let answer = SynAnswer {
            host: unsorted[2],
            port: 80,
            reply: SynReply::Open,
        };

        assert!(!is_sorted_unique(&unsorted));
        assert_eq!(answer_index(&answer, &unsorted, &ports), None);
    }

    #[test]
    fn sorted_unique_accepts_only_ascending_distinct_input() {
        assert!(is_sorted_unique(&[1, 2, 3]));
        assert!(is_sorted_unique::<u16>(&[]));
        assert!(is_sorted_unique(&[7]));
        assert!(!is_sorted_unique(&[2, 1]));
        assert!(!is_sorted_unique(&[1, 1]));
    }

    #[tokio::test]
    async fn a_sweep_refuses_unsorted_input_instead_of_reporting_filtered() {
        let config = SynSweepConfig {
            timeout: Duration::from_millis(10),
            rate_limit_per_sec: 100,
            retries: 0,
        };
        let targets = [Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1)];

        let error = run_syn_sweep(&targets, &[80], config, |_| {})
            .await
            .expect_err("unsorted targets must fail the sweep");

        assert!(error.to_string().contains("sorted"));
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
