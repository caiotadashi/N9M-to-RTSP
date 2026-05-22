# N9M to RTSP

Single-binary bridge for Intelbras/GIEC N9M live video streams. It connects to the MVD device on TCP `9006`, performs the certificate handshake, requests live H.264 channels, and serves each channel as RTSP over TCP.

## Setup

This project builds with Rust. If `cargo run --release` prints `cargo: command not found`, install Rust first.

### Linux / Jetson

On Ubuntu, Debian, Jetson Nano, or Jetson Orin:

```bash
sudo apt update
sudo apt install -y curl ca-certificates build-essential

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

cargo --version
```

### macOS

Install Apple's command line tools and Rust:

```bash
xcode-select --install

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

cargo --version
```

## Run

Copy the public-safe example config and fill in the private device values:

```bash
cp n9m.example.conf n9m.local.conf
```

`n9m.local.conf` is ignored by git. You can also point the app at another config file:

```bash
N9M_CONFIG=/path/to/private.conf cargo run --release
```

```bash
cargo run --release
```

Open the UI at `http://localhost:8080`.

RTSP URLs:

```text
rtsp://localhost:8554/channel/1
rtsp://localhost:8554/channel/2
rtsp://localhost:8554/channel/3
rtsp://localhost:8554/channel/4
```

Use TCP transport with ffplay/VLC if needed:

```bash
ffplay -rtsp_transport tcp rtsp://localhost:8554/channel/1
```

## Notes

- The device protocol is JSON-over-TCP plus binary media packages framed by a 12-byte N9M header.
- Certificate verification uses `HMAC-MD5(key=S0, message=S0)`, matching the behavior observed in the packet capture and in public N9M client code.
- Login `PASSWD` uses `HMAC-MD5(key="streaming", message=<password>)` as 32 lowercase hex. Supplying an already-hex 32-character password leaves it unchanged for reverse-engineering tests.
- H.264 is not transcoded. The bridge extracts Annex-B NAL units and packetizes them into RTP, which keeps CPU use low on small Linux devices such as Jetson Nano.
- The current RTSP server supports interleaved RTP over RTSP/TCP.
