mod crypto;
mod n9m;
mod rtsp;
mod web;

use std::env;
use std::fs;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;

use n9m::{BridgeConfig, ChannelStats};
use rtsp::StreamHub;

#[derive(Clone)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub stream_name: String,
    pub channels: [bool; 4],
    pub http_bind: String,
    pub rtsp_bind: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 9006,
            user: String::new(),
            password: String::new(),
            stream_name: "N9M-RTSP".to_string(),
            channels: [true, true, true, true],
            http_bind: "0.0.0.0:8080".to_string(),
            rtsp_bind: "0.0.0.0:8554".to_string(),
        }
    }
}

impl AppConfig {
    fn load() -> Self {
        let mut config = Self::default();
        let path = env::var("N9M_CONFIG").unwrap_or_else(|_| "n9m.local.conf".to_string());
        let Ok(contents) = fs::read_to_string(&path) else {
            return config;
        };

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = unquote(value.trim());
            match key.trim() {
                "host" => config.host = value,
                "port" => {
                    if let Ok(port) = value.parse() {
                        config.port = port;
                    }
                }
                "user" => config.user = value,
                "password" => config.password = value,
                "stream_name" => config.stream_name = value,
                "channels" => {
                    if let Some(channels) = parse_channels(&value) {
                        config.channels = channels;
                    }
                }
                "http_bind" => config.http_bind = value,
                "rtsp_bind" => config.rtsp_bind = value,
                _ => {}
            }
        }

        config
    }
}

fn unquote(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn parse_channels(value: &str) -> Option<[bool; 4]> {
    let mut channels = [false; 4];
    for part in value.split(',').map(str::trim).filter(|part| !part.is_empty()) {
        let channel = part.strip_prefix("CH").unwrap_or(part);
        let idx: usize = channel.parse().ok()?;
        if !(1..=4).contains(&idx) {
            return None;
        }
        channels[idx - 1] = true;
    }
    Some(channels)
}

pub struct SharedState {
    pub config: AppConfig,
    pub running: bool,
    pub status: String,
    pub stats: [ChannelStats; 4],
    pub stop: Option<Arc<AtomicBool>>,
    pub sockets: Vec<TcpStream>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            config: AppConfig::load(),
            running: false,
            status: "idle".to_string(),
            stats: [
                ChannelStats::new(1),
                ChannelStats::new(2),
                ChannelStats::new(3),
                ChannelStats::new(4),
            ],
            stop: None,
            sockets: Vec::new(),
        }
    }
}

pub type AppState = Arc<Mutex<SharedState>>;

fn main() {
    let state = Arc::new(Mutex::new(SharedState::new()));
    let hub = StreamHub::new();

    let rtsp_state = state.clone();
    let rtsp_hub = hub.clone();
    let rtsp_bind = state.lock().unwrap().config.rtsp_bind.clone();
    thread::spawn(move || {
        if let Err(err) = rtsp::serve(&rtsp_bind, rtsp_hub, rtsp_state) {
            eprintln!("rtsp server stopped: {err}");
        }
    });

    let http_state = state.clone();
    let http_hub = hub.clone();
    let http_bind = state.lock().unwrap().config.http_bind.clone();
    println!("UI:   http://{http_bind}");
    println!("RTSP: rtsp://<host>:8554/channel/1");
    let listener = TcpListener::bind(&http_bind).unwrap_or_else(|err| {
        panic!("failed to bind HTTP UI on {http_bind}: {err}");
    });

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = http_state.clone();
                let hub = http_hub.clone();
                thread::spawn(move || web::handle_http(stream, state, hub));
            }
            Err(err) => eprintln!("http accept failed: {err}"),
        }
    }
}

pub fn start_bridge(state: &AppState, hub: &StreamHub) -> Result<(), String> {
    let (config, stop) = {
        let mut guard = state.lock().map_err(|_| "state lock poisoned")?;
        if guard.running {
            return Ok(());
        }
        for slot in &mut guard.stats {
            slot.reset();
        }
        let stop = Arc::new(AtomicBool::new(false));
        guard.stop = Some(stop.clone());
        guard.running = true;
        guard.status = "starting".to_string();
        (guard.config.clone(), stop)
    };

    let state_clone = state.clone();
    let hub_clone = hub.clone();
    thread::spawn(move || {
        let bridge_config = BridgeConfig::from(config);
        let result = n9m::run_bridge(bridge_config, hub_clone, state_clone.clone(), stop.clone());
        let mut guard = state_clone.lock().unwrap();
        guard.running = false;
        guard.stop = None;
        guard.sockets.clear();
        guard.status = match result {
            Ok(()) if stop.load(Ordering::SeqCst) => "stopped".to_string(),
            Ok(()) => "finished".to_string(),
            Err(err) => format!("error: {err}"),
        };
    });

    Ok(())
}

pub fn stop_bridge(state: &AppState) {
    if let Ok(mut guard) = state.lock() {
        if let Some(stop) = &guard.stop {
            stop.store(true, Ordering::SeqCst);
            for socket in &guard.sockets {
                let _ = socket.shutdown(Shutdown::Both);
            }
            guard.status = "stopping".to_string();
        } else {
            guard.running = false;
            guard.status = "stopped".to_string();
        }
    }
}

pub fn register_bridge_socket(state: &AppState, socket: &TcpStream) {
    if let Ok(mut guard) = state.lock() {
        if let Ok(cloned) = socket.try_clone() {
            guard.sockets.push(cloned);
        }
    }
}
