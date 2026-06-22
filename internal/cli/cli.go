// Package cli provides the interactive command-line interface for the
// BeaconSync client. It owns the REPL loop, command dispatch, and the
// lifecycle of the underlying transport.
package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Jalapeno144/BeaconSync/internal/config"
	"github.com/Jalapeno144/BeaconSync/internal/transport"
)

// useRegex matches "use <host>:<port>" where host may be an IP, domain,
// or bracketed IPv6 address.
var useRegex = regexp.MustCompile(`^use\s+([a-zA-Z0-9_\-\.\:\[\]]+):(\d{1,5})$`)

// CLI is the interactive command-line interface.
type CLI struct {
	cfg       *config.Config
	tr        transport.Transport
	reader    *bufio.Reader
	connected bool
}

// New creates a CLI backed by the given configuration.
func New(cfg *config.Config) *CLI {
	return &CLI{
		cfg:    cfg,
		reader: bufio.NewReader(os.Stdin),
	}
}

// Run starts the read-eval-print loop. It blocks until the user issues
// an "exit" command or stdin returns an unrecoverable error.
func (c *CLI) Run() error {
	c.printBanner()
	c.printMenu()

	// Best-effort initial connection so the user sees status immediately.
	if err := c.connect(); err != nil {
		fmt.Printf("[!] WARNING: COULD NOT REACH %s — %v\n", c.cfg.Transport.ServerAddr, err)
		fmt.Println("[*] Use 'use <host:port>' to set a different target.")
	}

	for {
		fmt.Print("\nBeaconSync> ")
		line, err := c.reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "READ ERROR: %v\n", err)
			continue
		}

		if done := c.dispatch(strings.TrimSpace(line)); done {
			break
		}
	}

	// Cleanup
	if c.tr != nil {
		c.tr.Close()
	}
	fmt.Println("[*] Goodbye.")
	return nil
}

// dispatch routes a single command line. It returns true when the
// program should exit.
func (c *CLI) dispatch(input string) bool {
	if input == "" {
		return false
	}

	switch {
	case input == "exit" || input == "quit":
		return true

	case input == "help":
		c.printMenu()

	case input == "show":
		c.showConfig()

	case input == "send":
		c.sendBeacon()

	case useRegex.MatchString(input):
		c.handleUse(input)

	default:
		if strings.HasPrefix(input, "use") {
			fmt.Println("[!] INVALID FORMAT. CORRECT USAGE:")
			fmt.Println("      use example.com:8080")
			fmt.Println("      use 192.168.1.1:8080")
			fmt.Println("      use [::1]:8080          (IPv6)")
		} else {
			fmt.Printf("[-] Unknown command: %q — type 'help' for available commands.\n", input)
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

func (c *CLI) handleUse(input string) {
	matches := useRegex.FindStringSubmatch(input)
	host := matches[1]
	port := matches[2]

	// Validate the address component.
	ip := net.ParseIP(host)
	if ip != nil {
		fmt.Printf("[*] Valid IP address: %s\n", ip.String())
	} else {
		// Domain sanity checks.
		if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
			fmt.Println("[-] ERROR: INVALID DOMAIN NAME")
			return
		}
		fmt.Printf("[*] Using domain / server: %s\n", host)
	}

	c.cfg.Transport.ServerAddr = fmt.Sprintf("%s:%s", host, port)
	fmt.Printf("[+] Target set to %s, reconnecting...\n", c.cfg.Transport.ServerAddr)

	if err := c.connect(); err != nil {
		fmt.Printf("[!] CONNECTION FAILED: %v\n", err)
	}
}

// connect tears down any previous transport, creates a new one from the
// current config, and runs a Connect.
func (c *CLI) connect() error {
	if c.tr != nil {
		c.tr.Close()
	}
	c.connected = false

	opts := []transport.HTTPTransportOption{
		transport.WithTimeout(time.Duration(c.cfg.Transport.Timeout) * time.Second),
		transport.WithMaxIdleConns(c.cfg.HTTPOptions.MaxIdleConns),
		transport.WithIdleConnTimeout(time.Duration(c.cfg.HTTPOptions.IdleConnTimeout) * time.Second),
		transport.WithDisableKeepAlives(c.cfg.HTTPOptions.DisableKeepAlives),
	}

	c.tr = transport.NewHTTPTransport(
		c.cfg.Transport.ServerAddr,
		c.cfg.Transport.Protocol,
		opts...,
	)

	if err := c.tr.Connect(); err != nil {
		return err
	}

	c.connected = true
	fmt.Printf("[+] Connected to %s://%s\n", c.cfg.Transport.Protocol, c.cfg.Transport.ServerAddr)
	return nil
}

func (c *CLI) showConfig() {
	fmt.Println()
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("Current Configuration")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Server:          %s\n", c.cfg.Transport.ServerAddr)
	fmt.Printf("  Protocol:        %s\n", c.cfg.Transport.Protocol)
	fmt.Printf("  Timeout:         %ds\n", c.cfg.Transport.Timeout)
	fmt.Printf("  Max idle conns:  %d\n", c.cfg.HTTPOptions.MaxIdleConns)
	fmt.Printf("  Idle conn t/o:   %ds\n", c.cfg.HTTPOptions.IdleConnTimeout)
	fmt.Printf("  Keep-alive:      %v\n", !c.cfg.HTTPOptions.DisableKeepAlives)
	fmt.Printf("  Connected:       %v\n", c.connected)
	fmt.Println(strings.Repeat("-", 40))
}

func (c *CLI) sendBeacon() {
	if c.tr == nil || !c.connected {
		fmt.Println("[-] Not connected. Use 'use <host:port>' to connect first.")
		return
	}

	payload := map[string]interface{}{
		"type":      "beacon",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"client":    "BeaconSync",
		"version":   "0.1",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[-] Failed to marshal beacon: %v\n", err)
		return
	}

	fmt.Printf("[*] Sending beacon to %s://%s ...\n",
		c.cfg.Transport.Protocol, c.cfg.Transport.ServerAddr)

	if err := c.tr.Send(data); err != nil {
		fmt.Printf("[-] Send failed: %v\n", err)
		return
	}

	fmt.Println("[+] Beacon delivered.")
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

func (c *CLI) printBanner() {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 76))
	fmt.Println("                      BeaconSync Interactive CLI")
	fmt.Println(strings.Repeat("=", 76))
}

func (c *CLI) printMenu() {
	fmt.Println()
	fmt.Println(strings.Repeat("-", 56))
	fmt.Println("Available commands:")
	fmt.Println("  use <host:port>  Set target server    (use 10.0.0.1:8080)")
	fmt.Println("  send             Send a beacon payload")
	fmt.Println("  show             Display current configuration")
	fmt.Println("  help             Show this menu")
	fmt.Println("  exit             Exit the program")
	fmt.Println(strings.Repeat("-", 56))
}
