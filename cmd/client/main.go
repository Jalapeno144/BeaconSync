// Package main provides the entry point for the BeaconSync client.
//
// The client is responsible for initializing runtime configuration,
// establishing communication with the remote server, scheduling
// Make tasks, encoding outbound data, and synchronizing
// telemetry through the configured transport layer.
//
// Current features:
// - HTTP-based communication
// - JSON payload encoding
//
//	Planned features:
//
// - Configurable scheduler
// - Retry and backoff mechanism
// - WebSocket and SOCKS5 transports
// - Additional encoding strategies
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Define the structure corresponding to config.yaml.
type Config struct {
	Transport struct {
		ServerAddr string `yaml:"server_addr"`
		Protocol   string `yaml:"protocol"`
		Timeout    int    `yaml:"timeout"`
	} `yaml:"transport"`

	HTTPOptions struct {
		MaxIdleConns      int  `yaml:"max_idle_conns"`
		IdleConnTimeout   int  `yaml:"idle_conn_timeout"`
		DisableKeepAlives bool `yaml:"disable_keep_alives"`
	} `yaml:"http_options"`
}

var (
	// set default values, use these values if failed to resolve YAML
	serverAddr   string = "127.0.0.1:8080"
	protocol     string = "http"
	globalClient *http.Client
)

var useRegex = regexp.MustCompile(`^use\s+([a-zA-Z0-9_\-\.\:\[\]]+):(\d{1,5})$`)

// loadConfig
func loadConfig(filepath string) {
	file, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Printf("[!] Warning: Cannot read config file %s (%v), using hardcoded defaults.\n", filepath, err)
		return
	}

	var cfg Config
	err = yaml.Unmarshal(file, &cfg)
	if err != nil {
		fmt.Printf("[!] Warning: Error parsing YAML (%v), using hardcoded defaults.\n", err)
		return
	}

	// set config in YAML to global variables
	if cfg.Transport.ServerAddr != "" {
		serverAddr = cfg.Transport.ServerAddr
	}
	if cfg.Transport.Protocol != "" {
		protocol = strings.ToLower(cfg.Transport.Protocol)
	}

	fmt.Printf("[+] Configuration loaded successfully from %s\n", filepath)
}

func handleInput(input string) {
	input = strings.TrimSpace(input)

	// 1. Structure match
	if useRegex.MatchString(input) {
		matches := useRegex.FindStringSubmatch(input)
		host := matches[1] // possible choices: 127.0.0.1、example.com 或 [::1]
		port := matches[2] // port

		// use net package to test if the addr is valid
		ip := net.ParseIP(host)

		if ip != nil {
			fmt.Printf("[*] Tested valid IP address: %s\n", ip.String())
		} else {
			// not an ip: to test if it's a valid domain
			if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
				fmt.Println("[-] Error: Illegal domain")
				return
			}
			fmt.Printf("[*] Tested domain/server: %s\n", host)
		}

		serverAddr = fmt.Sprintf("%s:%s", host, port) // renew serverAddr
		fmt.Printf("[+] Target address correct, set connection to: %s\n", serverAddr)
		return
	}

	// 3. Show errors
	if strings.HasPrefix(input, "use") {
		fmt.Println("[!] Error! Correct usage:")
		fmt.Println("    - Domain: use example.com:8080")
		fmt.Println("    - IP  : use 192.168.1.1:8080")
		return
	}
}

// connectServer
func connectServer(addr string, proto string) error {
	tr := &http.Transport{
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

	fmt.Println()
	// send a package to server to test the route
	fullURL := fmt.Sprintf("%s://%s/handshake", proto, addr)
	resp, err := globalClient.Get(fullURL)
	if err != nil {
		return fmt.Errorf("connection failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[+] Connection established successfully to %s\n", addr)
	return nil
}

// Main Menu
func help() {
	fmt.Println("======================================================================================")
	fmt.Println("                                 BeaconSync Interactive CLI                           ")
	fmt.Println("======================================================================================")
	fmt.Println("Available commands:")
	fmt.Println("  use <ip:port>  - Set target (e.g., use 10.0.0.1:8080 or use api.sync.local:443)")
	fmt.Println("  send           - Send payload")
	fmt.Println("  show           - Show current configuration")
	fmt.Println("  exit           - Exit program")
	fmt.Println("======================================================================================")
}

func main() {
	// load yaml file
	loadConfig("config.yaml")

	help()
}
