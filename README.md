# BeaconSync
A configurable client-server framework for heartbeat-based telemetry and reliable data synchronization over HTTP.

## 🛠️ Tech Stack

- Language: Go
- Networking: net/http
- Protocols: HTTP, WebSocket (planned), SOCKS5 (planned)

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
    │   ├── transport/
    │   ├── encoder/
    │   ├── decoder/
    │   ├── storage/
    │   └── validator/
    ├── pkg/
    ├── configs/
    ├── docs/
    ├── go.mod
    └── README.md
```

## Status: 🚧 Under active development
Implemented:
- HTTP transport
- Basic server
- JSON encoding

Planned:
- Heartbeat scheduler
- Retry mechanism
- Pluggable transports
- Additional encoding strategies