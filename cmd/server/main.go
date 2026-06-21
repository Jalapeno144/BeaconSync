// Package main provides the entry point for the BeaconSync server.
//
// The server accepts client connections, processes incoming
// telemetry data, validates requests, distributes configuration
// updates, and coordinates synchronization with connected clients.
//
// Current features:
//   - HTTP listener
//
// Planned features:
//   - WebSocket and SOCKS5 transports
//   - Pluggable storage backends
//   - Advanced scheduling and policy distribution
//   - Basic request processing
//   - JSON payload decoding

package main

//! This is just a simplest version of server, which only realize the function of answering the request
import (
	"encoding/json"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := map[string]string{
		"status":  "ok",
		"version": "0.1",
		"server":  "BeaconSync",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/handshake", handler)

	log.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
