# BeaconSync
A covert channel that supports the transmission of encrypted information

## 🛠️ Tech Stack

- Language: Go
- Networking: net/http
- Protocols: HTTP, WebSocket (planned), SOCKS5 (planned), UDP(planned), TCP(planned)

## 📂 Project Structure

```text
    beaconsync/
    ├── cmd/
    │   ├── client/
    │   │    ├── config.yaml       # default client configuration
    │   │    └── main.go           # source code of client
    │   └── server/
    │        ├── config.yaml       # default server configuration
    │        └── main.go           # source code of server
    ├── test/                      # store my unit testing
    ├── internal/
    │   ├── scheduler/
    │   ├── cli/                   # cli module
    │   │    └── cli.go 
    │   ├── transport/             # transportation module
    │   │    ├── transport.go      # define Transport interface
    │   │    ├── http.go           # HTTPTransport realization
    │   │    ├── websocket.go    
    │   │    └── socks5.go       
    │   ├── config/
    │   │    └── config.go         # load default config
    │   ├── protocol/
    │   ├── sessions/              # used to manage client sessions
    │   ├── encoder/               # encode data
    │   ├── decoder/               # decode data
    │   ├── crypto/                # cryptographic primitives and key management
    │   ├── executor/              # execute command on client machine
    │   ├── storage/
    │   └── validator/
    ├── pkg/
    ├── configs/
    ├── .gitignores
    ├── LICENSE                    # my license
    ├── docs/
    ├── go.mod
    └── README.md
```

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