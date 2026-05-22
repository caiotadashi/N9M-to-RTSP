use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use crate::crypto::hmac_md5_hex;
use crate::rtsp::StreamHub;
use crate::{register_bridge_socket, AppConfig, AppState};

#[derive(Clone)]
pub struct BridgeConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub stream_name: String,
    pub channels: [bool; 4],
}

impl From<AppConfig> for BridgeConfig {
    fn from(value: AppConfig) -> Self {
        Self {
            host: value.host,
            port: value.port,
            user: value.user,
            password: value.password,
            stream_name: value.stream_name,
            channels: value.channels,
        }
    }
}

#[derive(Clone, Copy)]
pub struct ChannelStats {
    pub channel: usize,
    pub enabled: bool,
    pub frames: u64,
    pub bytes: u64,
    pub clients: usize,
    pub first_frame_ms: u128,
    pub last_frame_ms: u128,
    pub nal_units: u64,
    pub idr_frames: u64,
    pub sps_units: u64,
    pub pps_units: u64,
    pub multi_nal_frames: u64,
    pub fragmented_nals: u64,
    pub max_frame_bytes: u64,
    pub max_nal_bytes: u64,
}

impl ChannelStats {
    pub const fn new(channel: usize) -> Self {
        Self {
            channel,
            enabled: true,
            frames: 0,
            bytes: 0,
            clients: 0,
            first_frame_ms: 0,
            last_frame_ms: 0,
            nal_units: 0,
            idr_frames: 0,
            sps_units: 0,
            pps_units: 0,
            multi_nal_frames: 0,
            fragmented_nals: 0,
            max_frame_bytes: 0,
            max_nal_bytes: 0,
        }
    }

    pub fn reset(&mut self) {
        self.frames = 0;
        self.bytes = 0;
        self.clients = 0;
        self.first_frame_ms = 0;
        self.last_frame_ms = 0;
        self.nal_units = 0;
        self.idr_frames = 0;
        self.sps_units = 0;
        self.pps_units = 0;
        self.multi_nal_frames = 0;
        self.fragmented_nals = 0;
        self.max_frame_bytes = 0;
        self.max_nal_bytes = 0;
    }
}

#[derive(Default)]
struct H264Summary {
    nal_units: u64,
    has_idr: bool,
    sps_units: u64,
    pps_units: u64,
    fragmented_nals: u64,
    max_nal_bytes: u64,
}

#[derive(Debug)]
struct Package {
    payload: Vec<u8>,
}

pub fn run_bridge(
    cfg: BridgeConfig,
    hub: StreamHub,
    state: AppState,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    set_status(&state, "connecting");
    let addr = format!("{}:{}", cfg.host, cfg.port);
    let mut control = TcpStream::connect(&addr).map_err(|err| format!("connect {addr}: {err}"))?;
    register_bridge_socket(&state, &control);
    control
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|err| err.to_string())?;
    control
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|err| err.to_string())?;

    let session = "00000003-6f72-41ca-9c73-b4710006c2f5".to_string();
    send_json(
        &mut control,
        &json_packet(
            "CERTIFICATE",
            "CONNECT",
            Some("{\"UK\":\"\"}"),
            None,
            &session,
        ),
    )?;

    let connect = read_json_response(&mut control, &stop)?;
    let s0 = json_get_string(&connect, "S0").ok_or("connect response did not contain S0")?;
    let session = json_get_string(&connect, "SESSION").unwrap_or(session);
    let verify = hmac_md5_hex(s0.as_bytes(), s0.as_bytes());
    send_json(
        &mut control,
        &json_packet(
            "CERTIFICATE",
            "VERIFY",
            Some(&format!("{{\"S0\":\"{}\"}}", json_escape(&verify))),
            None,
            &session,
        ),
    )?;

    let verify_response = read_json_response(&mut control, &stop)?;
    if json_get_u64(&verify_response, "ERRORCODE").unwrap_or(0) != 0 {
        return Err(format!("verify failed: {verify_response}"));
    }

    let login_params = format!(
        "{{\"CID\":0,\"MAC\":\"\",\"PASSWD\":\"{}\",\"PLAYDEVID\":\"\",\"USER\":\"{}\"}}",
        json_escape(&login_password_field(&cfg.password)),
        json_escape(&cfg.user)
    );
    send_json(
        &mut control,
        &json_packet(
            "CERTIFICATE",
            "LOGIN",
            Some(&login_params),
            None,
            &session,
        ),
    )?;
    let login = read_json_response(&mut control, &stop)?;
    if json_get_u64(&login, "ERRORCODE").unwrap_or(0) != 0 {
        return Err(format!("login failed: {login}"));
    }

    set_status(&state, "creating media stream");
    let mut media = TcpStream::connect(&addr).map_err(|err| format!("media connect {addr}: {err}"))?;
    register_bridge_socket(&state, &media);
    media
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|err| err.to_string())?;
    media
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|err| err.to_string())?;

    let create_params = format!(
        "{{\"STREAMNAME\":\"{}\"}}",
        json_escape(&cfg.stream_name)
    );
    send_json(
        &mut media,
        &json_packet(
            "CERTIFICATE",
            "CREATESTREAM",
            Some(&create_params),
            None,
            &session,
        ),
    )?;
    let create_response = read_json_response(&mut media, &stop)?;
    if json_get_u64(&create_response, "ERRORCODE").unwrap_or(0) != 0 {
        return Err(format!("create stream failed: {create_response}"));
    }

    for (idx, enabled) in cfg.channels.iter().enumerate() {
        if *enabled {
            start_live_channel(&mut control, &cfg.stream_name, &session, idx + 1, &stop)?;
        }
    }
    control
        .set_nonblocking(true)
        .map_err(|err| format!("control nonblocking: {err}"))?;

    {
        let mut guard = state.lock().unwrap();
        guard.status = "streaming".to_string();
        for (idx, enabled) in cfg.channels.iter().enumerate() {
            guard.stats[idx].enabled = *enabled;
        }
    }

    let start = Instant::now();
    let mut last_keepalive = Instant::now();
    let mut packet_buf = PacketReader::new();
    let mut control_buf = PacketReader::new();
    while !stop.load(Ordering::SeqCst) {
        if last_keepalive.elapsed() >= Duration::from_secs(20) {
            let _ = send_json(
                &mut control,
                &json_packet("CERTIFICATE", "KEEPALIVE", None, None, &session),
            );
            last_keepalive = Instant::now();
        }

        drain_control(&mut control, &mut control_buf, &session);

        match packet_buf.read_package(&mut media, &stop) {
            Ok(Some(pack)) => {
                if let Some((channel, annexb)) = parse_media_payload(&pack.payload) {
                    if channel <= 4 && cfg.channels[channel - 1] && !annexb.is_empty() {
                        let h264 = inspect_annexb(&annexb);
                        hub.publish_annexb(channel, &annexb);
                        let mut guard = state.lock().unwrap();
                        let stats = &mut guard.stats[channel - 1];
                        stats.frames += 1;
                        stats.bytes += annexb.len() as u64;
                        stats.clients = hub.client_count(channel);
                        stats.nal_units += h264.nal_units;
                        stats.idr_frames += u64::from(h264.has_idr);
                        stats.sps_units += h264.sps_units;
                        stats.pps_units += h264.pps_units;
                        stats.multi_nal_frames += u64::from(h264.nal_units > 1);
                        stats.fragmented_nals += h264.fragmented_nals;
                        stats.max_frame_bytes = stats.max_frame_bytes.max(annexb.len() as u64);
                        stats.max_nal_bytes = stats.max_nal_bytes.max(h264.max_nal_bytes);
                        let frame_ms = start.elapsed().as_millis();
                        if stats.first_frame_ms == 0 {
                            stats.first_frame_ms = frame_ms;
                        }
                        stats.last_frame_ms = frame_ms;
                    }
                } else if is_json(&pack.payload) {
                    handle_json_package(&mut media, &session, &pack.payload);
                }
            }
            Ok(None) => {}
            Err(err) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                return Err(err);
            }
        }
    }

    set_status(&state, "stopped");
    Ok(())
}

fn start_live_channel(
    stream: &mut TcpStream,
    stream_name: &str,
    session: &str,
    channel: usize,
    stop: &Arc<AtomicBool>,
) -> Result<(), String> {
    let channel_mask = 1usize << (channel - 1);
    let request_params = format!(
        "{{\"AUDIOVALID\":{},\"CHANNEL\":{},\"STREAMNAME\":\"{}\",\"STREAMTYPE\":2}}",
        channel_mask,
        channel_mask,
        json_escape(stream_name)
    );
    send_json(
        stream,
        &json_packet(
            "MEDIASTREAMMODEL",
            "REQUESTALIVEVIDEO",
            Some(&request_params),
            None,
            session,
        ),
    )?;

    let response = read_json_for_operation(
        stream,
        stop,
        session,
        "MEDIASTREAMMODEL",
        "REQUESTALIVEVIDEO",
        Duration::from_secs(15),
    )?;
    if json_get_u64(&response, "ERRORCODE").unwrap_or(0) != 0 {
        return Err(format!("REQUESTALIVEVIDEO failed for channel {channel}: {response}"));
    }
    let ssrc = json_get_u64(&response, "SSRC").ok_or_else(|| {
        format!("REQUESTALIVEVIDEO response missing SSRC for channel {channel}: {response}")
    })?;

    let task_params = format!(
        "{{\"IPANDPORT\":\":0\",\"PT\":2,\"SSRC\":{},\"STREAMNAME\":\"{}\"}}",
        ssrc,
        json_escape(stream_name)
    );
    send_json(
        stream,
        &json_packet(
            "MEDIASTREAMMODEL",
            "MEDIATASKSTART",
            Some(&task_params),
            None,
            session,
        ),
    )?;

    let control_params = format!(
        "{{\"CMD\":1,\"PT\":2,\"SSRC\":{},\"STREAMNAME\":\"{}\",\"STREAMTYPE\":0}}",
        ssrc,
        json_escape(stream_name)
    );
    send_json(
        stream,
        &json_packet(
            "MEDIASTREAMMODEL",
            "CONTROLSTREAM",
            Some(&control_params),
            None,
            session,
        ),
    )?;

    Ok(())
}

fn drain_control(stream: &mut TcpStream, reader: &mut PacketReader, session: &str) {
    if let Ok(packages) = reader.read_available(stream) {
        for pack in packages {
            if is_json(&pack.payload) {
                handle_json_package(stream, session, &pack.payload);
            }
        }
    }
}

fn handle_json_package(stream: &mut TcpStream, session: &str, payload: &[u8]) {
    let text = String::from_utf8_lossy(payload);
    if text.contains("\"OPERATION\":\"KEEPALIVE\"") {
        let _ = send_json(
            stream,
            &json_packet("CERTIFICATE", "KEEPALIVE", None, None, session),
        );
    }
}

fn read_json_response(stream: &mut TcpStream, stop: &Arc<AtomicBool>) -> Result<String, String> {
    read_json_for_operation(stream, stop, "", "", "", Duration::from_secs(30))
}

fn read_json_for_operation(
    stream: &mut TcpStream,
    stop: &Arc<AtomicBool>,
    session: &str,
    module: &str,
    operation: &str,
    timeout: Duration,
) -> Result<String, String> {
    let mut reader = PacketReader::new();
    let deadline = Instant::now() + timeout;
    let filter = !module.is_empty() && !operation.is_empty();
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for {module}.{operation} on control socket"
            ));
        }
        match reader.read_package(stream, stop)? {
            Some(pack) if is_json(&pack.payload) => {
                let text = String::from_utf8_lossy(trim_nul(&pack.payload)).to_string();
                if filter {
                    if json_matches_operation(&text, module, operation) {
                        return Ok(text);
                    }
                    handle_json_package(stream, session, &pack.payload);
                    continue;
                }
                return Ok(text);
            }
            Some(_) => {}
            None => {
                if stop.load(Ordering::SeqCst) {
                    return Err("stopped".to_string());
                }
            }
        }
    }
}

fn json_matches_operation(json: &str, module: &str, operation: &str) -> bool {
    json_get_string(json, "MODULE").as_deref() == Some(module)
        && json_get_string(json, "OPERATION").as_deref() == Some(operation)
}

fn parse_media_payload(payload: &[u8]) -> Option<(usize, Vec<u8>)> {
    if payload.len() < 16 || payload.get(2) != Some(&b'd') || payload.get(3) != Some(&b'c') {
        return None;
    }
    let rec_type = payload[1];
    if rec_type != b'2' && rec_type != b'3' {
        return None;
    }
    let start = find_annexb_start(payload)?;
    let video_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
    let end = start.saturating_add(video_len).min(payload.len());
    if end <= start {
        return None;
    }
    let channel = payload[0] as usize + 1;
    Some((channel, payload[start..end].to_vec()))
}

fn find_annexb_start(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 4 <= buf.len() {
        if buf[i] == 0 && buf[i + 1] == 0 {
            if buf[i + 2] == 1 {
                return Some(i);
            }
            if i + 3 < buf.len() && buf[i + 2] == 0 && buf[i + 3] == 1 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn inspect_annexb(data: &[u8]) -> H264Summary {
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

    let mut summary = H264Summary::default();
    for (idx, (start, prefix)) in starts.iter().enumerate() {
        let nal_start = start + prefix;
        let nal_end = starts.get(idx + 1).map(|(next, _)| *next).unwrap_or(data.len());
        if nal_start >= nal_end {
            continue;
        }
        let nal = &data[nal_start..nal_end];
        let nal_len = nal.len() as u64;
        summary.nal_units += 1;
        summary.max_nal_bytes = summary.max_nal_bytes.max(nal_len);
        if nal_len > 1200 {
            summary.fragmented_nals += 1;
        }
        match nal[0] & 0x1f {
            5 => summary.has_idr = true,
            7 => summary.sps_units += 1,
            8 => summary.pps_units += 1,
            _ => {}
        }
    }
    summary
}

fn is_json(payload: &[u8]) -> bool {
    trim_nul(payload).first() == Some(&b'{')
}

fn trim_nul(payload: &[u8]) -> &[u8] {
    payload
        .iter()
        .rposition(|b| *b != 0 && *b != b'\n' && *b != b'\r')
        .map(|idx| &payload[..=idx])
        .unwrap_or(payload)
}

fn set_status(state: &AppState, status: &str) {
    if let Ok(mut guard) = state.lock() {
        guard.status = status.to_string();
    }
}

fn send_json(stream: &mut TcpStream, json: &str) -> Result<(), String> {
    let mut payload = json.as_bytes().to_vec();
    payload.push(0);
    let mut out = Vec::with_capacity(payload.len() + 12);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&[0x52, 0, 0, 0]);
    out.extend_from_slice(&payload);
    stream.write_all(&out).map_err(|err| err.to_string())
}

fn json_packet(module: &str, operation: &str, parameter: Option<&str>, response: Option<&str>, session: &str) -> String {
    let mut s = format!(
        "{{\"MODULE\":\"{}\",\"OPERATION\":\"{}\"",
        json_escape(module),
        json_escape(operation)
    );
    if let Some(parameter) = parameter {
        s.push_str(",\"PARAMETER\":");
        s.push_str(parameter);
    }
    if let Some(response) = response {
        s.push_str(",\"RESPONSE\":");
        s.push_str(response);
    }
    s.push_str(&format!(",\"SESSION\":\"{}\"}}", json_escape(session)));
    s
}

fn json_get_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":\"", key);
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn json_get_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn json_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn login_password_field(password: &str) -> String {
    if password.trim().is_empty() {
        String::new()
    } else if password.len() == 32 && password.bytes().all(|b| b.is_ascii_hexdigit()) {
        password.to_ascii_lowercase()
    } else {
        hmac_md5_hex(b"streaming", password.as_bytes())
    }
}

struct PacketReader {
    buf: Vec<u8>,
}

impl PacketReader {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn read_package(
        &mut self,
        stream: &mut TcpStream,
        stop: &Arc<AtomicBool>,
    ) -> Result<Option<Package>, String> {
        loop {
            if let Some(pack) = self.try_parse()? {
                return Ok(Some(pack));
            }

            let mut tmp = [0u8; 4096];
            match stream.read(&mut tmp) {
                Ok(0) => return Err("device closed the connection".to_string()),
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if stop.load(Ordering::SeqCst) {
                        return Ok(None);
                    }
                    return Ok(None);
                }
                Err(err) => return Err(err.to_string()),
            }
        }
    }

    fn read_available(&mut self, stream: &mut TcpStream) -> Result<Vec<Package>, String> {
        let mut packages = Vec::new();
        loop {
            while let Some(pack) = self.try_parse()? {
                packages.push(pack);
            }

            let mut tmp = [0u8; 4096];
            match stream.read(&mut tmp) {
                Ok(0) => return Err("device closed the connection".to_string()),
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(err) => return Err(err.to_string()),
            }
        }

        while let Some(pack) = self.try_parse()? {
            packages.push(pack);
        }
        Ok(packages)
    }

    fn try_parse(&mut self) -> Result<Option<Package>, String> {
        while self.buf.len() >= 12 {
            let marker_ok = self.buf[8] == 0x52 && self.buf[9] == 0 && self.buf[10] == 0 && self.buf[11] == 0;
            if !marker_ok {
                self.buf.remove(0);
                continue;
            }
            let len = u32::from_be_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]]) as usize;
            if len > 16 * 1024 * 1024 {
                self.buf.remove(0);
                continue;
            }
            if self.buf.len() < 12 + len {
                return Ok(None);
            }
            let payload = self.buf[12..12 + len].to_vec();
            self.buf.drain(..12 + len);
            return Ok(Some(Package { payload }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_matches_operation_filters_evem_status() {
        let evem = r#"{"MODULE":"EVEM","OPERATION":"SENDRECORDSTATUS","PARAMETER":{},"SESSION":"x"}"#;
        let alive = r#"{"MODULE":"MEDIASTREAMMODEL","OPERATION":"REQUESTALIVEVIDEO","RESPONSE":{"ERRORCODE":0,"SSRC":3},"SESSION":"x"}"#;
        assert!(!json_matches_operation(evem, "MEDIASTREAMMODEL", "REQUESTALIVEVIDEO"));
        assert!(json_matches_operation(
            alive,
            "MEDIASTREAMMODEL",
            "REQUESTALIVEVIDEO"
        ));
    }
}
