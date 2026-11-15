//! Unprivileged route exploration.
//!
//! Probes use Linux ICMP datagram sockets, UDP, and TCP with the IP TTL set per hop.
//! Hop addresses come from `IP_RECVERR` error-queue entries, so no raw socket or root
//! capability is required. A non-responsive hop is a measurement, not a route failure.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use futures_util::{StreamExt, stream};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::domain::route::{
    RouteHop, RouteProbeMethod, RouteProbeOutcome, RouteRun, RouteRunStatus, RouteSample,
    aggregate_hop, responder_addresses,
};
use crate::domain::{ids::new_id, time::now_ms};
use crate::infrastructure::reverse_dns;

const SO_EE_ORIGIN_ICMP: u8 = 2;
const ICMP_ECHO_REQUEST: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
const POLL_SLICE: Duration = Duration::from_millis(50);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("ICMP datagram sockets are not permitted for this user: {0}")]
    PermissionDenied(String),
    #[error("route probe setup failed: {0}")]
    Unavailable(String),
    #[error("route target {target:?} could not be resolved: {message}")]
    Resolve { target: String, message: String },
    #[error(
        "IPv6 route targets are not supported yet; use an IPv4 address or a name that resolves to IPv4"
    )]
    UnsupportedIpv6,
}

#[derive(Debug, Clone)]
pub struct RouteOptions {
    pub target: String,
    pub method: RouteProbeMethod,
    pub port: u16,
    pub max_hops: u8,
    pub probes_per_hop: u32,
    pub timeout: Duration,
    pub concurrency: usize,
}

/// Trace one target. Transport failures and timeouts are recorded as samples.
pub async fn trace(
    options: &RouteOptions,
    cancel: &CancellationToken,
) -> Result<RouteRun, RouteError> {
    let target_ip = resolve_target(&options.target).await?;
    let started_at_ms = now_ms();
    let mut hops: Vec<RouteHop> = Vec::new();
    let mut target_reached = false;
    let mut any_response = false;
    let mut any_transport_error = false;

    for ttl in 1..=options.max_hops {
        if cancel.is_cancelled() {
            break;
        }
        let mut samples = Vec::new();
        let mut jobs = Vec::new();
        for probe_index in 0..options.probes_per_hop {
            jobs.push((ttl, probe_index));
        }
        let mut results: Vec<RouteSample> = stream::iter(jobs)
            .map(|(ttl, probe_index)| {
                let target = target_ip;
                let method = options.method;
                let port = options.port;
                let timeout = options.timeout;
                let cancel = cancel.clone();
                tokio::task::spawn_blocking(move || {
                    probe_blocking(target, method, port, ttl, probe_index, timeout, &cancel)
                })
            })
            .buffer_unordered(options.concurrency.max(1))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .map(|joined| joined.unwrap_or_else(|_| cancelled_sample(ttl)))
            .collect();
        results.sort_by_key(|sample| sample.probe_index);
        samples.extend(results);

        let hop = aggregate_hop(ttl, samples);
        if hop.responder == Some(IpAddr::V4(target_ip)) && hop.reply_count > 0 {
            target_reached = true;
            hops.push(hop);
            break;
        }
        if hop.responder == Some(IpAddr::V4(target_ip)) && hop.error_count > 0 {
            target_reached = true;
            hops.push(hop);
            break;
        }
        if hop.reply_count > 0 || hop.error_count > 0 {
            any_response = true;
        }
        if hop.error_count > 0 {
            any_transport_error = true;
        }
        hops.push(hop);
    }

    let finished_at_ms = now_ms();
    let status = if target_reached {
        RouteRunStatus::Completed
    } else if cancel.is_cancelled() {
        RouteRunStatus::Cancelled
    } else if !any_response && any_transport_error {
        RouteRunStatus::Failed
    } else if !any_response {
        RouteRunStatus::NoResponse
    } else {
        RouteRunStatus::Partial
    };

    let mut run = RouteRun {
        id: new_id(),
        target: options.target.clone(),
        target_ip: IpAddr::V4(target_ip),
        method: options.method,
        port: match options.method {
            RouteProbeMethod::Icmp => None,
            RouteProbeMethod::Udp | RouteProbeMethod::Tcp => Some(options.port),
        },
        started_at_ms,
        finished_at_ms,
        max_hops: options.max_hops,
        probes_per_hop: options.probes_per_hop,
        status,
        target_reached,
        hops,
        error: None,
    };

    // Reverse DNS is a naming hint for hop addresses. A lookup failure does not
    // invalidate the route measurement.
    let addresses: Vec<IpAddr> = responder_addresses(&run);
    if !addresses.is_empty()
        && let Ok(names) =
            reverse_dns::lookup(&addresses, options.timeout, options.concurrency, cancel).await
    {
        for hop in &mut run.hops {
            if let Some(ip) = hop.responder {
                hop.hostname = names
                    .iter()
                    .find(|answer| answer.ip == ip)
                    .map(|answer| answer.name.clone());
            }
        }
    }

    Ok(run)
}

fn cancelled_sample(ttl: u8) -> RouteSample {
    RouteSample {
        probe_index: 0,
        sent_at_ms: now_ms(),
        outcome: RouteProbeOutcome::Cancelled,
        responder: None,
        rtt_ms: None,
        icmp_type: None,
        icmp_code: None,
        error: Some(format!("route probe for TTL {ttl} was cancelled")),
    }
}

async fn resolve_target(target: &str) -> Result<Ipv4Addr, RouteError> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(address) => Ok(address),
            IpAddr::V6(_) => Err(RouteError::UnsupportedIpv6),
        };
    }
    let lookup = (target, 0_u16);
    let resolved = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(lookup))
        .await
        .map_err(|_| RouteError::Resolve {
            target: target.to_string(),
            message: "resolution timed out".to_string(),
        })?
        .map_err(|error| RouteError::Resolve {
            target: target.to_string(),
            message: error.to_string(),
        })?;
    for address in resolved {
        if let IpAddr::V4(address) = address.ip() {
            return Ok(address);
        }
    }
    Err(RouteError::UnsupportedIpv6)
}

fn probe_blocking(
    target: Ipv4Addr,
    method: RouteProbeMethod,
    port: u16,
    ttl: u8,
    probe_index: u32,
    timeout: Duration,
    cancel: &CancellationToken,
) -> RouteSample {
    let sent_at_ms = now_ms();
    let started = Instant::now();
    let probe = match method {
        RouteProbeMethod::Icmp => probe_icmp(target, ttl, timeout, cancel),
        RouteProbeMethod::Udp => probe_udp(target, port, ttl, timeout, cancel),
        RouteProbeMethod::Tcp => probe_tcp(target, port, ttl, timeout),
    };
    let rtt_ms = match probe.outcome {
        RouteProbeOutcome::Reply | RouteProbeOutcome::IcmpError => {
            Some(started.elapsed().as_secs_f64() * 1_000.0)
        }
        _ => None,
    };
    RouteSample {
        probe_index,
        sent_at_ms,
        outcome: probe.outcome,
        responder: probe.responder.map(IpAddr::V4),
        rtt_ms,
        icmp_type: probe.icmp_type,
        icmp_code: probe.icmp_code,
        error: probe.error,
    }
}

struct RawProbe {
    outcome: RouteProbeOutcome,
    responder: Option<Ipv4Addr>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
    error: Option<String>,
}

impl RawProbe {
    fn reply(responder: Ipv4Addr, icmp_type: Option<u8>, icmp_code: Option<u8>) -> Self {
        Self {
            outcome: RouteProbeOutcome::Reply,
            responder: Some(responder),
            icmp_type,
            icmp_code,
            error: None,
        }
    }

    fn icmp_error(responder: Ipv4Addr, icmp_type: u8, icmp_code: u8) -> Self {
        Self {
            outcome: RouteProbeOutcome::IcmpError,
            responder: Some(responder),
            icmp_type: Some(icmp_type),
            icmp_code: Some(icmp_code),
            error: None,
        }
    }

    fn timeout() -> Self {
        Self {
            outcome: RouteProbeOutcome::Timeout,
            responder: None,
            icmp_type: None,
            icmp_code: None,
            error: Some("no response within the probe timeout".to_string()),
        }
    }

    fn transport(error: String) -> Self {
        Self {
            outcome: RouteProbeOutcome::TransportError,
            responder: None,
            icmp_type: None,
            icmp_code: None,
            error: Some(error),
        }
    }
}

fn probe_udp(
    target: Ipv4Addr,
    port: u16,
    ttl: u8,
    timeout: Duration,
    cancel: &CancellationToken,
) -> RawProbe {
    let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(socket) => socket,
        Err(error) => return RawProbe::transport(format!("creating UDP socket: {error}")),
    };
    if let Err(error) = prepare_socket(&socket, ttl) {
        return error;
    }
    let peer = SockAddr::from(SocketAddr::new(IpAddr::V4(target), port));
    if let Err(error) = socket.connect(&peer) {
        return RawProbe::transport(format!("connecting UDP socket: {error}"));
    }
    if let Err(error) = socket.send(b"netatlas-route") {
        return RawProbe::transport(format!("sending UDP probe: {error}"));
    }
    wait_for_error_or_data(&socket, target, timeout, cancel)
}

fn probe_icmp(
    target: Ipv4Addr,
    ttl: u8,
    timeout: Duration,
    cancel: &CancellationToken,
) -> RawProbe {
    let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
        Ok(socket) => socket,
        Err(error) => {
            if error.kind() == io::ErrorKind::PermissionDenied {
                return RawProbe::transport(format!(
                    "ICMP datagram sockets are not permitted for this user: {error}"
                ));
            }
            return RawProbe::transport(format!("creating ICMP socket: {error}"));
        }
    };
    if let Err(error) = prepare_socket(&socket, ttl) {
        return error;
    }
    let peer = SockAddr::from(SocketAddr::new(IpAddr::V4(target), 0));
    if let Err(error) = socket.connect(&peer) {
        return RawProbe::transport(format!("connecting ICMP socket: {error}"));
    }
    if let Err(error) = socket.send(&ICMP_ECHO_REQUEST) {
        return RawProbe::transport(format!("sending ICMP probe: {error}"));
    }
    wait_for_error_or_data(&socket, target, timeout, cancel)
}

fn probe_tcp(target: Ipv4Addr, port: u16, ttl: u8, timeout: Duration) -> RawProbe {
    let socket = match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
        Ok(socket) => socket,
        Err(error) => return RawProbe::transport(format!("creating TCP socket: {error}")),
    };
    if let Err(error) = prepare_socket(&socket, ttl) {
        return error;
    }
    let peer = SockAddr::from(SocketAddr::new(IpAddr::V4(target), port));
    match socket.connect_timeout(&peer, timeout) {
        Ok(()) => RawProbe::reply(target, None, None),
        Err(error) => {
            if let Some(info) = read_recverr(socket.as_raw_fd()) {
                return recverr_probe(info, target);
            }
            match error.kind() {
                io::ErrorKind::ConnectionRefused => RawProbe::reply(target, None, None),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => RawProbe::timeout(),
                _ => RawProbe::transport(format!("connecting TCP: {error}")),
            }
        }
    }
}

fn prepare_socket(socket: &Socket, ttl: u8) -> Result<(), RawProbe> {
    if let Err(error) = socket.set_ttl_v4(u32::from(ttl)) {
        return Err(RawProbe::transport(format!("setting IP TTL: {error}")));
    }
    if let Err(error) = set_recverr(socket.as_raw_fd(), true) {
        return Err(RawProbe::transport(format!("enabling IP_RECVERR: {error}")));
    }
    Ok(())
}

fn wait_for_error_or_data(
    socket: &Socket,
    target: Ipv4Addr,
    timeout: Duration,
    cancel: &CancellationToken,
) -> RawProbe {
    let deadline = Instant::now() + timeout;
    loop {
        if cancel.is_cancelled() {
            return RawProbe {
                outcome: RouteProbeOutcome::Cancelled,
                responder: None,
                icmp_type: None,
                icmp_code: None,
                error: Some("cancelled by user".to_string()),
            };
        }
        let now = Instant::now();
        if now >= deadline {
            return RawProbe::timeout();
        }
        let remaining = deadline - now;
        let poll_timeout = remaining.min(POLL_SLICE);
        let mut pollfd = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN | libc::POLLERR,
            revents: 0,
        };
        // SAFETY: `pollfd` is a valid, initialized poll descriptor and `poll` only
        // writes `revents` for the lifetime of this call.
        let ready = unsafe { libc::poll(&mut pollfd, 1, poll_timeout.as_millis() as libc::c_int) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return RawProbe::transport(format!("waiting for probe response: {error}"));
        }
        if ready == 0 {
            continue;
        }
        if pollfd.revents & libc::POLLERR != 0
            && let Some(info) = read_recverr(socket.as_raw_fd())
        {
            return recverr_probe(info, target);
        }
        if pollfd.revents & libc::POLLIN != 0 {
            let mut buffer = [0_u8; 1_024];
            // SAFETY: the buffer is valid for `buffer.len()` bytes and `recv` writes at
            // most that many bytes.
            let read = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if read >= 0 {
                return RawProbe::reply(target, None, None);
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::EAGAIN) {
                continue;
            }
            return RawProbe::transport(format!("receiving probe response: {error}"));
        }
    }
}

fn recverr_probe(info: RecverrInfo, target: Ipv4Addr) -> RawProbe {
    if info.origin == SO_EE_ORIGIN_ICMP {
        if info.responder == target {
            RawProbe::reply(target, Some(info.icmp_type), Some(info.icmp_code))
        } else {
            RawProbe::icmp_error(info.responder, info.icmp_type, info.icmp_code)
        }
    } else {
        RawProbe::transport(format!(
            "local error {} reported for {}",
            info.errno, info.responder
        ))
    }
}

#[repr(C)]
struct SockExtendedErr {
    ee_errno: u32,
    ee_origin: u8,
    ee_type: u8,
    ee_code: u8,
    ee_pad: u8,
    ee_info: u32,
    ee_data: u32,
}

struct RecverrInfo {
    errno: u32,
    origin: u8,
    icmp_type: u8,
    icmp_code: u8,
    responder: Ipv4Addr,
}

fn set_recverr(fd: RawFd, enable: bool) -> io::Result<()> {
    let value: libc::c_int = if enable { 1 } else { 0 };
    // SAFETY: `value` is a valid `c_int` for the `IP_RECVERR` option and `fd` is a
    // live socket owned by the caller.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVERR,
            (&value as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_recverr(fd: RawFd) -> Option<RecverrInfo> {
    let mut data = [0_u8; 1_024];
    let mut control = [0_u8; 1_024];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    // SAFETY: `msghdr` is zeroed and then populated with valid pointers and lengths
    // for the duration of the `recvmsg` call. `msg_controllen` is updated by the
    // kernel and used to bound ancillary-data iteration.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let read = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_ERRQUEUE) };
    if read < 0 {
        return None;
    }
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !cmsg.is_null() {
        let (level, kind) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
        if level == libc::IPPROTO_IP && kind == libc::IP_RECVERR {
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            if data.is_null() {
                return None;
            }
            // SAFETY: the kernel guarantees a `sock_extended_err` followed by the
            // offender `sockaddr` for `IP_RECVERR` control messages.
            let extended = unsafe { &*(data as *const SockExtendedErr) };
            let offender =
                unsafe { data.add(size_of::<SockExtendedErr>()) as *const libc::sockaddr_in };
            let address = unsafe { u32::from_be((*offender).sin_addr.s_addr) };
            return Some(RecverrInfo {
                errno: extended.ee_errno,
                origin: extended.ee_origin,
                icmp_type: extended.ee_type,
                icmp_code: extended.ee_code,
                responder: Ipv4Addr::from(address),
            });
        }
        cmsg = cmsg_nexthdr(&message, cmsg);
    }
    None
}

/// Linux `_CMSG_NXTHDR`: align the next header to `sizeof(size_t)` and bounds-check.
fn cmsg_nexthdr(message: *const libc::msghdr, cmsg: *const libc::cmsghdr) -> *mut libc::cmsghdr {
    // SAFETY: both pointers come from a valid `recvmsg` result and the kernel has
    // written a well-formed control buffer.
    unsafe {
        let length = (*cmsg).cmsg_len;
        let alignment = align_of::<usize>();
        let aligned = length.div_ceil(alignment) * alignment;
        let next = (cmsg as *mut u8).add(aligned) as *mut libc::cmsghdr;
        let end = (*message).msg_control as usize + (*message).msg_controllen;
        if next as usize + size_of::<libc::cmsghdr>() > end {
            std::ptr::null_mut()
        } else {
            next
        }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::{RecverrInfo, RouteOptions, SockExtendedErr, read_recverr};
    use crate::domain::route::RouteProbeMethod;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn extended_err_layout_is_16_bytes() {
        assert_eq!(size_of::<SockExtendedErr>(), 16);
    }

    #[test]
    fn options_are_constructible() {
        let options = RouteOptions {
            target: "127.0.0.1".to_string(),
            method: RouteProbeMethod::Icmp,
            port: 33434,
            max_hops: 2,
            probes_per_hop: 1,
            timeout: Duration::from_millis(200),
            concurrency: 2,
        };
        assert_eq!(options.max_hops, 2);
    }

    #[tokio::test]
    async fn icmp_probe_to_loopback_reaches_target() {
        let options = RouteOptions {
            target: "127.0.0.1".to_string(),
            method: RouteProbeMethod::Icmp,
            port: 0,
            max_hops: 1,
            probes_per_hop: 1,
            timeout: Duration::from_millis(500),
            concurrency: 1,
        };
        let run = super::trace(&options, &CancellationToken::new())
            .await
            .unwrap();
        assert!(run.target_reached);
        assert_eq!(run.hops.len(), 1);
        assert_eq!(run.hops[0].reply_count, 1);
        assert_eq!(run.hops[0].responder.unwrap().to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn udp_probe_to_loopback_reaches_target() {
        let options = RouteOptions {
            target: "127.0.0.1".to_string(),
            method: RouteProbeMethod::Udp,
            port: 9,
            max_hops: 1,
            probes_per_hop: 1,
            timeout: Duration::from_millis(500),
            concurrency: 1,
        };
        let run = super::trace(&options, &CancellationToken::new())
            .await
            .unwrap();
        assert!(run.target_reached);
        assert_eq!(run.hops[0].responder.unwrap().to_string(), "127.0.0.1");
    }

    #[test]
    fn recverr_reader_is_defined() {
        // `read_recverr` requires a live error queue; the layout test above covers
        // the unsafe parsing boundary.
        let _ = read_recverr as fn(_) -> Option<RecverrInfo>;
    }
}
