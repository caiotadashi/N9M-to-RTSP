use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::AppState;

const RTP_MTU: usize = 1200;
/// H.264 RTP clock (RFC 6184).
const RTP_CLOCK_HZ: f64 = 90_000.0;

type AccessUnitPackets = Vec<Vec<u8>>;

#[derive(Clone)]
pub struct StreamHub {
    inner: Arc<Mutex<HubInner>>,
}

struct HubInner {
    channels: [ChannelHub; 4],
}

struct RtspSubscriber {
    sender: Sender<AccessUnitPackets>,
    /// Skip access units until the first IDR after this client connects.
    needs_idr: bool,
}

struct ChannelHub {
    subscribers: HashMap<u64, RtspSubscriber>,
    next_subscriber: u64,
    sequence: u16,
    /// Last RTP timestamp sent (monotonic).
    timestamp: u32,
    /// Wall-clock anchor for variable frame rate (90 kHz).
    stream_epoch: Option<Instant>,
    sps: Option<Vec<u8>>,
    pps: Option<Vec<u8>>,
}

impl StreamHub {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HubInner {
                channels: [
                    ChannelHub::new(),
                    ChannelHub::new(),
                    ChannelHub::new(),
                    ChannelHub::new(),
                ],
            })),
        }
    }

    pub fn publish_annexb(&self, channel: usize, annexb: &[u8]) {
        if !(1..=4).contains(&channel) {
            return;
        }
        let nals = split_annexb(annexb);
        if nals.is_empty() {
            return;
        }
        let mut guard = self.inner.lock().unwrap();
        let ch = &mut guard.channels[channel - 1];

        let rtp_nals = reorder_nals_for_decode(collect_rtp_nals(&nals, ch));
        let has_idr = rtp_nals
            .iter()
            .any(|nal| matches!(nal_type(nal), Some(5)));
        let has_pframe = rtp_nals
            .iter()
            .any(|nal| matches!(nal_type(nal), Some(1)));
        if !has_idr && !has_pframe {
            return;
        }

        let timestamp = next_rtp_timestamp(ch, Instant::now());
        let ssrc = 0x4e394d00u32 | channel as u32;
        let au_refs: Vec<&[u8]> = rtp_nals;
        let mut packets = Vec::new();
        packetize_access_unit(&au_refs, timestamp, ssrc, ch, &mut packets);
        ch.subscribers.retain(|_, sub| {
            if sub.needs_idr {
                if !has_idr || ch.sps.is_none() {
                    return true;
                }
                sub.needs_idr = false;
            }
            sub.sender.send(packets.clone()).is_ok()
        });
    }

    pub fn subscribe(&self, channel: usize) -> Option<(u64, Receiver<AccessUnitPackets>)> {
        if !(1..=4).contains(&channel) {
            return None;
        }
        let (tx, rx) = mpsc::channel();
        let mut guard = self.inner.lock().ok()?;
        let ch = &mut guard.channels[channel - 1];
        let id = ch.next_subscriber;
        ch.next_subscriber += 1;
        ch.subscribers.insert(
            id,
            RtspSubscriber {
                sender: tx,
                needs_idr: true,
            },
        );
        Some((id, rx))
    }

    pub fn unsubscribe(&self, channel: usize, id: u64) {
        if !(1..=4).contains(&channel) {
            return;
        }
        if let Ok(mut guard) = self.inner.lock() {
            guard.channels[channel - 1].subscribers.remove(&id);
        }
    }

    pub fn client_count(&self, channel: usize) -> usize {
        if !(1..=4).contains(&channel) {
            return 0;
        }
        self.inner
            .lock()
            .map(|g| g.channels[channel - 1].subscribers.len())
            .unwrap_or(0)
    }

    fn sdp(&self, channel: usize, host: &str) -> String {
        let guard = self.inner.lock().unwrap();
        let ch = &guard.channels[channel - 1];
        let fmtp = if let Some(sps) = &ch.sps {
            let profile = if sps.len() >= 4 {
                format!("{:02x}{:02x}{:02x}", sps[1], sps[2], sps[3])
            } else {
                "42e01f".to_string()
            };
            // No sprop: MDVR PPS changes every frame; ffmpeg mis-parses SPS-only extradata
            // before the first in-band PPS (spurious "pps_id out of range" at connect).
            format!("a=fmtp:96 packetization-mode=1;profile-level-id={profile}\r\n")
        } else {
            "a=fmtp:96 packetization-mode=1\r\n".to_string()
        };
        format!(
            "v=0\r\n\
             o=- 0 0 IN IP4 {host}\r\n\
             s=N9M Channel {channel}\r\n\
             c=IN IP4 0.0.0.0\r\n\
             t=0 0\r\n\
             a=control:*\r\n\
             m=video 0 RTP/AVP 96\r\n\
             a=rtpmap:96 H264/90000\r\n\
             {fmtp}\
             a=control:trackID=0\r\n"
        )
    }
}

impl ChannelHub {
    fn new() -> Self {
        Self {
            subscribers: HashMap::new(),
            next_subscriber: 1,
            sequence: 1,
            timestamp: 0,
            stream_epoch: None,
            sps: None,
            pps: None,
        }
    }
}

pub fn serve(bind: &str, hub: StreamHub, state: AppState) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind)?;
    for stream in listener.incoming() {
        let stream = stream?;
        let hub = hub.clone();
        let state = state.clone();
        thread::spawn(move || handle_client(stream, hub, state));
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, hub: StreamHub, _state: AppState) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let mut channel = 1usize;
    let mut session = String::new();
    let mut subscribed: Option<(usize, u64)> = None;
    loop {
        let request = match read_rtsp_request(&mut stream) {
            Ok(Some(req)) => req,
            Ok(None) => return,
            Err(_) => return,
        };
        let cseq = header(&request, "CSeq").unwrap_or("1");
        let first = request.lines().next().unwrap_or("");
        let parts: Vec<&str> = first.split_whitespace().collect();
        let method = parts.first().copied().unwrap_or("");
        if let Some(path) = parts.get(1) {
            if let Some(ch) = parse_channel(path) {
                channel = ch;
            }
        }
        let host = local_ip_hint(&stream);
        match method {
            "OPTIONS" => {
                let body = "";
                let _ = write_response(
                    &mut stream,
                    200,
                    cseq,
                    &[("Public", "OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN")],
                    body,
                );
            }
            "DESCRIBE" => {
                let body = hub.sdp(channel, &host);
                let _ = write_response(
                    &mut stream,
                    200,
                    cseq,
                    &[
                        ("Content-Type", "application/sdp"),
                        ("Content-Base", &format!("rtsp://{host}/channel/{channel}/")),
                    ],
                    &body,
                );
            }
            "SETUP" => {
                session = new_session_id();
                let _ = write_response(
                    &mut stream,
                    200,
                    cseq,
                    &[
                        ("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1"),
                        ("Session", &session),
                    ],
                    "",
                );
            }
            "PLAY" => {
                let (id, rx) = match hub.subscribe(channel) {
                    Some(sub) => sub,
                    None => {
                        let _ = write_response(&mut stream, 404, cseq, &[], "");
                        continue;
                    }
                };
                subscribed = Some((channel, id));
                let _ = write_response(
                    &mut stream,
                    200,
                    cseq,
                    &[("Session", &session), ("RTP-Info", "url=trackID=0;seq=0;rtptime=0")],
                    "",
                );
                while let Ok(batch) = rx.recv() {
                    let mut ok = true;
                    for packet in &batch {
                        if write_interleaved_frame(&mut stream, 0, packet).is_err() {
                            ok = false;
                            break;
                        }
                    }
                    if !ok || stream.flush().is_err() {
                        break;
                    }
                }
                if let Some((ch, sub_id)) = subscribed.take() {
                    hub.unsubscribe(ch, sub_id);
                }
                return;
            }
            "TEARDOWN" => {
                let _ = write_response(&mut stream, 200, cseq, &[("Session", &session)], "");
                break;
            }
            _ => {
                let _ = write_response(&mut stream, 405, cseq, &[], "");
            }
        }
    }
    if let Some((ch, sub_id)) = subscribed {
        hub.unsubscribe(ch, sub_id);
    }
}

/// MDVR IDR access units often arrive as `PPS, SPS, PPS, SEI, IDR`. ffmpeg needs SPS
/// before the first PPS of the access unit.
fn reorder_nals_for_decode<'a>(nals: Vec<&'a [u8]>) -> Vec<&'a [u8]> {
    let mut sps = Vec::new();
    let mut pps = Vec::new();
    let mut sei = Vec::new();
    let mut vcl = Vec::new();
    for nal in nals {
        match nal_type(nal) {
            Some(7) => sps.push(nal),
            Some(8) => pps.push(nal),
            Some(6) => sei.push(nal),
            Some(1) | Some(5) => vcl.push(nal),
            _ => {}
        }
    }
    let mut out = Vec::with_capacity(sps.len() + pps.len() + sei.len() + vcl.len());
    out.extend(sps);
    out.extend(pps);
    out.extend(sei);
    out.extend(vcl);
    out
}

fn collect_rtp_nals<'a>(nals: &'a [&'a [u8]], ch: &mut ChannelHub) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    for nal in nals {
        if nal.is_empty() {
            continue;
        }
        if matches!(nal_type(nal), Some(9)) {
            continue;
        }
        match nal_type(nal) {
            Some(7) => ch.sps = Some(nal.to_vec()),
            Some(8) => ch.pps = Some(nal.to_vec()),
            _ => {}
        }
        out.push(*nal);
    }
    out
}

/// Map wall-clock elapsed time to 90 kHz RTP timestamps (variable device fps).
fn next_rtp_timestamp(ch: &mut ChannelHub, now: Instant) -> u32 {
    if ch.stream_epoch.is_none() {
        ch.stream_epoch = Some(now);
    }
    let epoch = ch.stream_epoch.unwrap();
    let elapsed = now.duration_since(epoch);
    let mut ts = (elapsed.as_secs_f64() * RTP_CLOCK_HZ).round() as u32;
    if ch.timestamp > 0 && ts <= ch.timestamp {
        ts = ch.timestamp.saturating_add(1);
    }
    ch.timestamp = ts;
    ts
}

/// One RTP packet per NAL (marker on last). ffmpeg and most depayers handle this
/// more reliably than STAP-A for per-frame inline PPS.
fn packetize_access_unit(
    nals: &[&[u8]],
    timestamp: u32,
    ssrc: u32,
    ch: &mut ChannelHub,
    out: &mut Vec<Vec<u8>>,
) {
    if nals.is_empty() {
        return;
    }
    for (idx, nal) in nals.iter().enumerate() {
        let marker = idx + 1 == nals.len();
        packetize_nal(nal, marker, timestamp, ssrc, ch, out);
    }
}

fn packetize_nal(nal: &[u8], marker: bool, timestamp: u32, ssrc: u32, ch: &mut ChannelHub, out: &mut Vec<Vec<u8>>) {
    if nal.is_empty() {
        return;
    }
    if nal.len() <= RTP_MTU {
        out.push(rtp_packet(ch.next_sequence(), timestamp, ssrc, marker, nal));
        return;
    }
    let nal_header = nal[0];
    let nri = nal_header & 0x60;
    let nal_type = nal_header & 0x1f;
    let fu_indicator = nri | 28;
    let mut offset = 1;
    let max_payload = RTP_MTU - 2;
    while offset < nal.len() {
        let remaining = nal.len() - offset;
        let take = remaining.min(max_payload);
        let start = offset == 1;
        let end = offset + take >= nal.len();
        let fu_header = (if start { 0x80 } else { 0 }) | (if end { 0x40 } else { 0 }) | nal_type;
        let mut payload = Vec::with_capacity(take + 2);
        payload.push(fu_indicator);
        payload.push(fu_header);
        payload.extend_from_slice(&nal[offset..offset + take]);
        out.push(rtp_packet(ch.next_sequence(), timestamp, ssrc, marker && end, &payload));
        offset += take;
    }
}

impl ChannelHub {
    fn next_sequence(&mut self) -> u16 {
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        seq
    }
}

fn rtp_packet(seq: u16, timestamp: u32, ssrc: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + payload.len());
    out.push(0x80);
    out.push(if marker { 0xe0 } else { 0x60 });
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&ssrc.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn nal_type(nal: &[u8]) -> Option<u8> {
    nal.first().map(|b| b & 0x1f)
}

fn split_annexb(data: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 < data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            starts.push((i, 3));
            i += 3;
        } else if i + 4 < data.len()
            && data[i] == 0
            && data[i + 1] == 0
            && data[i + 2] == 0
            && data[i + 3] == 1
        {
            starts.push((i, 4));
            i += 4;
        } else {
            i += 1;
        }
    }
    let mut nals = Vec::new();
    for (idx, (start, prefix)) in starts.iter().enumerate() {
        let nal_start = start + prefix;
        let nal_end = starts.get(idx + 1).map(|(next, _)| *next).unwrap_or(data.len());
        if nal_start < nal_end {
            nals.push(&data[nal_start..nal_end]);
        }
    }
    nals
}

fn read_rtsp_request(stream: &mut TcpStream) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(None);
        }
        buf.push(tmp[0]);
        if buf.len() > 16 * 1024 {
            return Ok(None);
        }
    }
    Ok(Some(String::from_utf8_lossy(&buf).to_string()))
}

fn write_response(
    stream: &mut TcpStream,
    code: u16,
    cseq: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    write!(stream, "RTSP/1.0 {code} {reason}\r\nCSeq: {cseq}\r\n")?;
    for (k, v) in headers {
        write!(stream, "{k}: {v}\r\n")?;
    }
    write!(stream, "Content-Length: {}\r\n\r\n{}", body.len(), body)?;
    stream.flush()
}

fn write_interleaved_frame(stream: &mut TcpStream, channel: u8, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len() as u16;
    stream.write_all(&[b'$', channel])?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)
}

fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    for line in request.lines() {
        let (k, v) = line.split_once(':')?;
        if k.eq_ignore_ascii_case(name) {
            return Some(v.trim());
        }
    }
    None
}

fn parse_channel(path: &str) -> Option<usize> {
    let marker = "/channel/";
    let start = path.find(marker)? + marker.len();
    let rest = &path[start..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    let ch = digits.parse::<usize>().ok()?;
    (1..=4).contains(&ch).then_some(ch)
}

fn local_ip_hint(stream: &TcpStream) -> String {
    stream
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "127.0.0.1:8554".to_string())
}

fn new_session_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{now:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn annexb(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in parts {
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.extend_from_slice(part);
        }
        out
    }

    fn drain(rx: &Receiver<AccessUnitPackets>) {
        while rx.try_recv().is_ok() {}
    }

    fn recv_batch_count(rx: &Receiver<AccessUnitPackets>) -> usize {
        let mut n = 0;
        while rx.try_recv().is_ok() {
            n += 1;
        }
        n
    }

    fn rtp_payload(packet: &[u8]) -> &[u8] {
        &packet[12..]
    }

    #[test]
    fn publish_one_rtp_packet_per_nal() {
        let hub = StreamHub::new();
        let sps = &[0x67, 0x42, 0xe0, 0x1f];
        let pps = &[0x68, 0xce, 0x3c, 0x80];
        let slice = &[0x41, 0x88, 0x84];
        let idr = &[0x65, 0xdd];
        let (_, rx) = hub.subscribe(1).unwrap();
        hub.publish_annexb(1, &annexb(&[pps, sps, idr]));
        drain(&rx);
        hub.publish_annexb(1, &annexb(&[pps, slice]));
        let batch = rx.try_recv().expect("one access unit");
        assert_eq!(recv_batch_count(&rx), 0);
        assert_eq!(batch.len(), 2);
        assert_eq!(rtp_payload(&batch[0])[0] & 0x1f, 8);
        assert_eq!(rtp_payload(&batch[1])[0] & 0x1f, 1);
        assert_eq!(batch[1][1] & 0x80, 0x80);
    }

    #[test]
    fn publish_skips_aud_and_keeps_decode_order() {
        let hub = StreamHub::new();
        let sps = &[0x67, 0x42, 0xe0, 0x1f];
        let pps = &[0x68, 0x01];
        let aud = &[0x09, 0x10];
        let slice = &[0x41, 0x02];
        let idr = &[0x65, 0xdd];
        let (_, rx) = hub.subscribe(1).unwrap();
        hub.publish_annexb(1, &annexb(&[pps, sps, idr]));
        drain(&rx);
        hub.publish_annexb(1, &annexb(&[pps, aud, slice]));
        let batch = rx.try_recv().expect("pps+slice au");
        assert_eq!(batch.len(), 2);
        assert_eq!(rtp_payload(&batch[0])[0] & 0x1f, 8);
        assert_eq!(rtp_payload(&batch[1])[0] & 0x1f, 1);
    }

    #[test]
    fn rtp_timestamp_tracks_wall_clock() {
        let mut ch = ChannelHub::new();
        let t0 = Instant::now();
        let ts0 = next_rtp_timestamp(&mut ch, t0);
        assert_eq!(ts0, 0);
        let ts1 = next_rtp_timestamp(&mut ch, t0 + Duration::from_millis(100));
        assert!(ts1 >= 9000 && ts1 <= 9100);
        let ts2 = next_rtp_timestamp(&mut ch, t0 + Duration::from_millis(250));
        assert!(ts2 > ts1);
    }

    #[test]
    fn reorder_puts_sps_before_leading_pps_on_idr() {
        let pps1 = &[0x68, 0x01];
        let sps = &[0x67, 0x42, 0xe0, 0x1f];
        let pps2 = &[0x68, 0x02];
        let idr = &[0x65, 0x88];
        let ordered = reorder_nals_for_decode(vec![pps1, sps, pps2, idr]);
        assert_eq!(ordered.len(), 4);
        assert_eq!(ordered[0], sps);
        assert_eq!(ordered[1], pps1);
        assert_eq!(ordered[2], pps2);
        assert_eq!(ordered[3], idr);
    }

}
