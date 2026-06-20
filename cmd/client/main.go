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
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

var (
	serverAddr   string = "127.0.0.1:8080"
	protocol     string = "http"
	globalClient *http.Client
)

// connectServer
func connectServer(addr string, proto string) error {
	tr := &http.Transport{
		// 限制最大空闲连接数，保持长连接
		MaxIdleConns:      10,
		IdleConnTimeout:   30 * time.Second,
		DisableKeepAlives: false, // Keep-Alive
	}

	// to avoid authentication
	if proto == "https" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	globalClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	// send a package to server to test the route
	fullURL := fmt.Sprintf("%s://%s/handshake", proto, addr)
	resp, err := globalClient.Get(fullURL)
	if err != nil {
		return fmt.Errorf("connection failed: %v", err)
	}
	defer resp.Body.Close() // 必须关闭，连接才会放回池中复用

	fmt.Printf("[+] Connection established successfully to %s\n", addr)
	return nil
}

// Main Menu
func help() {
	fmt.Println("======================================================")
	fmt.Println("              BeaconSync Interactive CLI              ")
	fmt.Println("======================================================")
	fmt.Println("Available commands:")
	fmt.Println("  use <ip:port>  - Set target server IP")
	fmt.Println("  send           - Send heartbeat payload")
	fmt.Println("  show           - Show current configuration")
	fmt.Println("  exit           - Exit program")
	fmt.Println("======================================================")
}

func main() {
	help()
}
