// Package main provides the entry point for the BeaconSync client.
//
// The client is responsible for initializing runtime configuration,
// establishing communication with the remote server, scheduling
// heartbeat tasks, encoding outbound data, and synchronizing
// telemetry through the configured transport layer.
//
// Current features:
// - HTTP-based communication
// - JSON payload encoding
//
//	Planned features:
//
// - Configurable heartbeat scheduler
// - Retry and backoff mechanism
// - WebSocket and SOCKS5 transports
// - Additional encoding strategies
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type Heartbeat struct {
	Hostname string `json:"hostname"`
	Status   string `json:"status"`
}

func main() {
	hb := Heartbeat{
		Hostname: "client-01",
		Status:   "alive",
	}

	data, err := json.Marshal(hb)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post(
		"http://127.0.0.1:8080/heartbeat", // test server ip
		"application/json",
		bytes.NewBuffer(data),
	)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("Status:", resp.Status)
}
