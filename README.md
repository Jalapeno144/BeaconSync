# BeaconSync
A covert channel that supports the transmission of encrypted information

## NOTICE THIS PROJECT IS UNDER PROCESSING AND PLANNED TO REWRITE CLIENT IN RUST

## 🛠️ Tech Stack

- Language: Go
- Networking: net/http
- Protocols: HTTP, WebSocket (planned), SOCKS5 (planned), UDP(planned), TCP(planned)

## 📂 Project Structure

```text
    beaconsync/
    ├── server/                              # Go server
    │   ├── cmd/
    │   │   └── server/
    │   │       └── main.go                  # server entry point
    │   │
    │   ├── configs/
    │   │   └── config.yaml                  # default server configuration
    │   │
    │   ├── internal/
    │   │   ├── cli/
    │   │   │   ├── cli.go
    │   │   │   ├── cli_connect.go
    │   │   │   ├── cli_heartbeat.go
    │   │   │   └── cli_send.go
    │   │   │
    │   │   ├── config/
    │   │   │   └── config.go
    │   │   │
    │   │   ├── scheduler/
    │   │   │   ├── heartbeat.go
    │   │   │   └── scheduler.go
    │   │   │
    │   │   ├── transport/
    │   │   │   ├── transport.go             # Transport interface
    │   │   │   │
    │   │   │   ├── http/
    │   │   │   │   └── http.go
    │   │   │   │
    │   │   │   ├── websocket/
    │   │   │   │   └── websocket.go
    │   │   │   │
    │   │   │   ├── socks5/
    │   │   │   │   └── socks5.go
    │   │   │   │
    │   │   │   └── dns/
    │   │   │       ├── dns.go
    │   │   │       ├── handler.go
    │   │   │       └── obfuscation.go
    │   │   │
    │   │   ├── protocol/
    │   │   ├── sessions/
    │   │   ├── codec/
    │   │   ├── crypto/
    │   │   │   ├── crypto.go
    │   │   │   ├── aead.go
    │   │   │   ├── ecdh.go
    │   │   │   ├── hkdf.go
    │   │   │   └── random.go
    │   │   │
    │   │   ├── executor/
    │   │   ├── storage/
    │   │   ├── validator/
    │   │   └── logger/
    │   │
    │   ├── go.mod
    │   └── go.sum
    │
    ├── client/                              # Rust agent
    │   ├── Cargo.toml
    │   ├── Cargo.lock
    │   │
    │   └── src/
    │       ├── main.rs                      # client entry point
    │       │
    │       ├── config/
    │       │
    │       ├── scheduler/
    │       │
    │       ├── transport/
    │       │   ├── mod.rs
    │       │   ├── http.rs
    │       │   ├── websocket.rs
    │       │   ├── socks5.rs
    │       │   └── dns.rs
    │       │
    │       ├── protocol/
    │       │
    │       ├── codec/
    │       │
    │       ├── crypto/
    │       │   ├── mod.rs
    │       │   ├── aead.rs
    │       │   ├── ecdh.rs
    │       │   ├── hkdf.rs
    │       │   └── random.rs
    │       │
    │       ├── executor/
    │       │
    │       ├── evasion/
    │       │   ├── mod.rs
    │       │   ├── sleep.rs                 # sleep obfuscation
    │       │   ├── timing.rs
    │       │   │
    │       │   └── sandbox/
    │       │       ├── mod.rs
    │       │       ├── cpu.rs
    │       │       ├── memory.rs
    │       │       ├── disk.rs
    │       │       ├── process.rs
    │       │       ├── registry.rs
    │       │       ├── network.rs
    │       │       ├── user.rs
    │       │       └── score.rs
    │       │
    │       ├── platform/
    │       │   ├── mod.rs
    │       │   │
    │       │   └── windows/
    │       │       ├── mod.rs
    │       │       ├── error.rs
    │       │       ├── memory.rs            # VirtualAlloc / VirtualFree
    │       │       ├── timer.rs             # WaitableTimer
    │       │       ├── process.rs
    │       │       ├── token.rs
    │       │       ├── registry.rs
    │       │       ├── filesystem.rs
    │       │       └── network.rs
    │       │
    │       └── utils/
    │
    ├── docs/
    │   ├── architecture.md
    │   ├── protocol.md
    │   ├── transport.md
    │   └── crypto.md
    │
    ├── tests/                               # integration tests
    │
    ├── scripts/
    │
    ├── .gitignore
    ├── LICENSE
    ├── README.md
    └── CHANGELOG.md
```

## ⚙️ Core Modules Detail

### 🔄 Resilience Engine: Scheduler & Heartbeat (`internal/scheduler`)

The `scheduler` and `heartbeat` modules cooperate to manage the lifecycle, task execution timing, and connection persistence of the agent. Instead of a naive, static polling mechanism, BeaconSync implements an advanced, fluid scheduling engine tailored for **covert communication resilience** and **traffic obfuscation**.

#### 1. Heartbeat Engine (`heartbeat.go`)
Maintains session state and connection persistence between the client and the server with traffic signature evasion in mind.
* **Dynamic Jittering:** Implements randomized intervals (using standard $[-Jitter, +Jitter]$ distributions) to eliminate fixed-frequency traffic signatures, rendering statistical traffic analysis (JA3/JA4, packet timing analysis) ineffective.
* **State Alignment:** Seamlessly synchronizes client status with the server's session manager without transmitting predictable or repetitive metadata.

#### 2. Intelligent Task Scheduler (`scheduler.go`)
Acts as the central control loop for task polling, execution timing, and network failure recovery.
* **Exponential Backoff Retry:** In case of network drops or server unreadiness, the scheduler dynamically scales its sleep intervals ($Interval \times Multiplier^n$) to prevent "reconnection storms" and minimize exposure during network anomalies.
* **Decoupled Execution:** Tasks received via heartbeats are offloaded to asynchronous queues, ensuring that heavy command execution (`internal/executor`) never blocks the core communication heartbeat.
* **Graceful Degradation:** Automatically throttles traffic density or switches to dormant mode when anomalies are detected, ensuring maximum agent longevity.

### 🚄 Pluggable Transport Layer (`internal/transport`)
Provides a highly abstracted communication interface that decouples the upper-tier agent logic from underlying network protocols.
* **Unified Interface:** Defines standard behavior primitives for connection initialization and raw data streaming, allowing seamless protocol switching at runtime.
* **HTTP Covert Channel:** Simulates normal web browsing behaviors by mimicking standard HTTP headers, cookies, and body structures to evaluate deep packet inspection (DPI) resilience.
* **HTTPS Covert Channel:** Simulates normal https behaviors. It allows to verify temporary CA provided by controller meanwhile not intercepted by enterprise proxies.


### 🛡️ Crypto & Data Processing (`internal/crypto, encoder, decoder`)
Handles end-to-end payload security and wire-format transformation.
* **Cryptographic Primitives:** Implements modern symmetric and asymmetric encryption algorithms to establish secure sessions, preventing man-in-the-middle (MITM) inspection.
* **Traffic Obfuscation:** Streamlines the transformation of structured commands into raw byte arrays. Designed to plug into custom obfuscation layers (e.g., Base64, XOR, or binary padding) to destroy predictable traffic entropy.

### 🎛️ Session & Client Control (`internal/sessions, cli`)
Implements the central nervous system on the server-side to orchestrate distributed remote agents.
* **Concurrent Session Manager:** Utilizes Go’s native concurrent primitives (sync.Map or channel-backed states) to track and manage hundreds of active remote connections safely without race conditions.
* **Interactive Control Interface:** A robust Command Line Interface designed for operators to seamlessly list active sessions, fetch telemetries, and dispatch tasks.

### ⚙️ Command Execution Engine (`internal/executor`)
The dedicated worker routine on the client side responsible for local task consumption and isolation.
* **Non-Blocking Worker Pool:** Spawns asynchronous goroutines to execute incoming system instructions, ensuring the core heartbeat loop remains completely uninterrupted.
* **Stream Capture & Sanitization:** Safely executes commands, captures stdout/stderr streams, and feeds the output back into the transport queue while gracefully handling execution timeouts.

## ⚠️ Disclaimer
This project is created strictly for **educational purposes, academic research, and authorized security testing (Red/Blue Teaming).**
* Do not use this tool against infrastructure you do not own or do not have explicit, written authorization to test.
* The author assumes no liability and is not responsible for any misuse or damage caused by this or any derivative products of the program

## 🚧 Project Status & Roadmap

### 🟢 Implemented (Done)
- **Core Architecture:** Basic client-server communication hub.

### 🟡 Under Development
- **Pluggable Transports:** Modular core architecture (`internal/transport`) to dynamically switch protocols. ![In Progress](https://img.shields.io/badge/-In%20Progress-blue)
- **Interactive CLI:** Control interface (`internal/cli`) for seamless agent management. ![In Progress](https://img.shields.io/badge/-In%20Progress-blue)
- **HTTP Transport:** Covert channel over standard HTTP protocol. ![In Progress](https://img.shields.io/badge/-In%20Progress-blue)
- **Data Encoding:** Fast and reliable JSON serialization. ![In Progress](https://img.shields.io/badge/-In%20Progress-blue)

### ⏳ Planned (Roadmap)
- **Advanced Protocols:** Integration of WebSocket, SOCKS5, TCP, and UDP channels. ![Planned](https://img.shields.io/badge/-Planned-orange)
- **Resilience Engine:** Intelligent heartbeat scheduler (with jitter) and exponential backoff retry mechanism. ![Planned](https://img.shields.io/badge/-Planned-orange)
- **Security & Privacy:** - Dynamic data encoders/decoders to obfuscate traffic. ![Planned](https://img.shields.io/badge/-Planned-orange)
  - Robust cryptographic primitives and end-to-end key management. ![Planned](https://img.shields.io/badge/-Planned-orange)
- **Session & Task Management:** - Multi-client session tracking (`internal/sessions`). ![Planned](https://img.shields.io/badge/-Planned-orange)
  - Native command execution worker (`internal/executor`). ![Planned](https://img.shields.io/badge/-Planned-orange)