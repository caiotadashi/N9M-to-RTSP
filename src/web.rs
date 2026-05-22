use std::io::{Read, Write};
use std::net::TcpStream;

use crate::rtsp::StreamHub;
use crate::{start_bridge, stop_bridge, AppConfig, AppState};

const INDEX: &str = include_str!("../static/index.html");
const STYLE: &str = include_str!("../static/styles.css");
const APP: &str = include_str!("../static/app.js");

pub fn handle_http(mut stream: TcpStream, state: AppState, hub: StreamHub) {
    let request = match read_request(&mut stream) {
        Ok(req) => req,
        Err(err) => {
            let _ = write_response(&mut stream, 400, "text/plain", &err);
            return;
        }
    };
    let (method, path) = first_line(&request);
    let body = request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");

    let result = match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => write_response(&mut stream, 200, "text/html; charset=utf-8", INDEX),
        ("GET", "/styles.css") => write_response(&mut stream, 200, "text/css; charset=utf-8", STYLE),
        ("GET", "/app.js") => write_response(&mut stream, 200, "application/javascript; charset=utf-8", APP),
        ("GET", "/api/status") => write_json(&mut stream, 200, &status_json(&state, &hub)),
        ("GET", "/api/config") => {
            let config = state.lock().unwrap().config.clone();
            write_json(&mut stream, 200, &config_json(&config))
        }
        ("POST", "/api/config") => {
            update_config(&state, body);
            let config = state.lock().unwrap().config.clone();
            write_json(&mut stream, 200, &config_json(&config))
        }
        ("POST", "/api/start") => match start_bridge(&state, &hub) {
            Ok(()) => write_json(&mut stream, 200, "{\"ok\":true}"),
            Err(err) => write_json(&mut stream, 409, &format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&err))),
        },
        ("POST", "/api/stop") => {
            stop_bridge(&state);
            write_json(&mut stream, 200, "{\"ok\":true}")
        }
        _ => write_response(&mut stream, 404, "text/plain; charset=utf-8", "not found"),
    };

    if let Err(err) = result {
        eprintln!("http write failed: {err}");
    }
}

fn read_request(stream: &mut TcpStream) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).map_err(|err| err.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&buf).to_string();
            let content_length = header_value(&header, "Content-Length")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let body_start = header.find("\r\n\r\n").unwrap() + 4;
            while buf.len() < body_start + content_length {
                let n = stream.read(&mut tmp).map_err(|err| err.to_string())?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            break;
        }
        if buf.len() > 128 * 1024 {
            return Err("request too large".to_string());
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn first_line(request: &str) -> (&str, &str) {
    let line = request.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    (parts.next().unwrap_or(""), parts.next().unwrap_or(""))
}

fn header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    for line in request.lines() {
        let (k, v) = line.split_once(':')?;
        if k.eq_ignore_ascii_case(name) {
            return Some(v.trim());
        }
    }
    None
}

fn write_json(stream: &mut TcpStream, code: u16, body: &str) -> std::io::Result<()> {
    write_response(stream, code, "application/json; charset=utf-8", body)
}

fn write_response(stream: &mut TcpStream, code: u16, content_type: &str, body: &str) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
        body.as_bytes().len(),
        body
    )?;
    stream.flush()
}

fn status_json(state: &AppState, hub: &StreamHub) -> String {
    let mut guard = state.lock().unwrap();
    for idx in 0..4 {
        guard.stats[idx].clients = hub.client_count(idx + 1);
    }
    let config = guard.config.clone();
    let mut channels = String::new();
    for (idx, stat) in guard.stats.iter().enumerate() {
        if idx > 0 {
            channels.push(',');
        }
        let fps = channel_fps(stat.frames, stat.first_frame_ms, stat.last_frame_ms);
        channels.push_str(&format!(
            "{{\"channel\":{},\"enabled\":{},\"frames\":{},\"bytes\":{},\"clients\":{},\"fps\":{:.2},\"lastFrameMs\":{},\"nalUnits\":{},\"idrFrames\":{},\"spsUnits\":{},\"ppsUnits\":{},\"multiNalFrames\":{},\"fragmentedNals\":{},\"maxFrameBytes\":{},\"maxNalBytes\":{},\"rtspUrl\":\"rtsp://localhost:8554/channel/{}\"}}",
            stat.channel,
            bool_json(config.channels[idx]),
            stat.frames,
            stat.bytes,
            stat.clients,
            fps,
            stat.last_frame_ms,
            stat.nal_units,
            stat.idr_frames,
            stat.sps_units,
            stat.pps_units,
            stat.multi_nal_frames,
            stat.fragmented_nals,
            stat.max_frame_bytes,
            stat.max_nal_bytes,
            stat.channel
        ));
    }
    format!(
        "{{\"running\":{},\"status\":\"{}\",\"source\":\"{}:{}\",\"channels\":[{}]}}",
        bool_json(guard.running),
        json_escape(&guard.status),
        json_escape(&config.host),
        config.port,
        channels
    )
}

fn channel_fps(frames: u64, first_frame_ms: u128, last_frame_ms: u128) -> f64 {
    if frames < 2 || last_frame_ms <= first_frame_ms {
        return 0.0;
    }
    let elapsed = (last_frame_ms - first_frame_ms) as f64 / 1000.0;
    (frames - 1) as f64 / elapsed
}

fn config_json(config: &AppConfig) -> String {
    format!(
        "{{\"host\":\"{}\",\"port\":{},\"user\":\"{}\",\"password\":\"{}\",\"streamName\":\"{}\",\"channels\":[{},{},{},{}],\"httpBind\":\"{}\",\"rtspBind\":\"{}\"}}",
        json_escape(&config.host),
        config.port,
        json_escape(&config.user),
        json_escape(&config.password),
        json_escape(&config.stream_name),
        bool_json(config.channels[0]),
        bool_json(config.channels[1]),
        bool_json(config.channels[2]),
        bool_json(config.channels[3]),
        json_escape(&config.http_bind),
        json_escape(&config.rtsp_bind)
    )
}

fn update_config(state: &AppState, body: &str) {
    let mut guard = state.lock().unwrap();
    if guard.running {
        guard.status = "configuration changes apply after stop/start".to_string();
    }
    if let Some(host) = json_string(body, "host") {
        guard.config.host = host;
    }
    if let Some(port) = json_u16(body, "port") {
        guard.config.port = port;
    }
    if let Some(user) = json_string(body, "user") {
        guard.config.user = user;
    }
    if let Some(password) = json_string(body, "password") {
        guard.config.password = password;
    }
    if let Some(stream_name) = json_string(body, "streamName") {
        guard.config.stream_name = stream_name;
    }
    if let Some(channels) = json_bool_array(body, "channels") {
        guard.config.channels = channels;
    }
}

fn json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)?;
    let rest = &json[pos + needle.len()..];
    let colon = rest.find(':')?;
    let rest = rest[colon + 1..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let mut escaped = false;
    for c in rest[1..].chars() {
        if escaped {
            out.push(match c {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Some(out);
        } else {
            out.push(c);
        }
    }
    None
}

fn json_u16(json: &str, key: &str) -> Option<u16> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)?;
    let rest = &json[pos + needle.len()..];
    let colon = rest.find(':')?;
    let rest = rest[colon + 1..].trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn json_bool_array(json: &str, key: &str) -> Option<[bool; 4]> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)?;
    let rest = &json[pos + needle.len()..];
    let open = rest.find('[')?;
    let close = rest[open..].find(']')? + open;
    let values: Vec<bool> = rest[open + 1..close]
        .split(',')
        .map(|v| v.trim() == "true")
        .collect();
    if values.len() != 4 {
        return None;
    }
    Some([values[0], values[1], values[2], values[3]])
}

fn bool_json(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn json_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}
