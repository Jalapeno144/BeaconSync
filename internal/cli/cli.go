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
	"strconv"
	"strings"
	"time"

	"github.com/Jalapeno144/BeaconSync/internal/config"
	"github.com/Jalapeno144/BeaconSync/internal/scheduler"
	"github.com/Jalapeno144/BeaconSync/internal/transport"
)

// useRegex matches "use <host>:<port>" where host may be an IP, domain,
// or bracketed IPv6 address.
var useRegex = regexp.MustCompile(`^use\s+([a-zA-Z0-9_\-\.\:\[\]]+):(\d{1,5})$`)

var (
	heartbeatSetRegex       = regexp.MustCompile(`^heartbeat\s+set\s+(\S+)$`)
	heartbeatJitterAbsRegex = regexp.MustCompile(`^heartbeat\s+jitter\s+abs\s+(\S+)$`)
	heartbeatJitterPctRegex = regexp.MustCompile(`^heartbeat\s+jitter\s+pct\s+(\S+)$`)
)

// CLI is the interactive command-line interface.
type CLI struct {
	cfg          *config.Config
	tr           transport.Transport
	reader       *bufio.Reader
	connected    bool
	heartbeatCfg scheduler.HeartbeatConfig
	sched        *scheduler.Scheduler
}

// New creates a CLI backed by the given configuration.
func New(cfg *config.Config) *CLI {
	return &CLI{
		cfg:          cfg,
		reader:       bufio.NewReader(os.Stdin),
		heartbeatCfg: scheduler.DefaultHeartbeatConfig(),
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

	case heartbeatSetRegex.MatchString(input):
		c.handleHeartbeatSet(input)
	case heartbeatJitterAbsRegex.MatchString(input):
		c.handleHeartbeatJitterAbs(input)
	case heartbeatJitterPctRegex.MatchString(input):
		c.handleHeartbeatJitterPct(input)
	case input == "heartbeat" || input == "heartbeat show":
		c.handleHeartbeatShow()

	default:
		if strings.HasPrefix(input, "use") {
			fmt.Println("[!] INVALID FORMAT. CORRECT USAGE:")
			fmt.Println("      use example.com:8080")
			fmt.Println("      use 192.168.1.1:8080")
			fmt.Println("      use [::1]:8080          (IPv6)")
		} else {
			fmt.Printf("[!] UNKNOWN COMMAND: %q — type 'help' for available commands.\n", input)
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
			fmt.Println("[!] ERROR: INVALID DOMAIN NAME")
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

	var err error
	c.tr, err = transport.NewHTTPTransport(
		c.cfg.Transport.ServerAddr,
		c.cfg.Transport.Protocol,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("[!] FAILED TO CREATE HTTP TRANSPORT: %w", err)
	}

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

	//TODO deal with response body of Send()
	if _, err := c.tr.Send(data); err != nil {
		fmt.Printf("[!] SEND FAILED: %v\n", err)
		return
	}

	fmt.Println("[+] Beacon delivered.")
}

// ---------------------------------------------------------------------------
// Heartbeat commands
// ---------------------------------------------------------------------------

func (c *CLI) handleHeartbeatShow() {
	fmt.Println()
	fmt.Println(strings.Repeat("-", 44))
	fmt.Println("Heartbeat Configuration")
	fmt.Println(strings.Repeat("-", 44))
	fmt.Printf("  Base interval:   %v\n", c.heartbeatCfg.BaseInterval)
	fmt.Printf("  Jitter (abs):    ±%v\n", c.heartbeatCfg.JitterAbs)
	fmt.Printf("  Min interval:    %v\n", c.heartbeatCfg.MinInterval)
	fmt.Printf("  Max interval:    %v\n", c.heartbeatCfg.MaxInterval)
	fmt.Printf("  Next interval:   %v  (sample)\n", c.heartbeatCfg.NextInterval())
	fmt.Println(strings.Repeat("-", 44))
}

func (c *CLI) handleHeartbeatSet(input string) {
	matches := heartbeatSetRegex.FindStringSubmatch(input)
	d, err := time.ParseDuration(matches[1])
	if err != nil {
		fmt.Printf("[!] INVALID DURATION %q — use formats like 90s, 2m, 1h\n", matches[1])
		return
	}
	if d <= 0 {
		fmt.Println("[!] INTERVAL MUST BE GREATER THAN ZERO")
		return
	}
	c.heartbeatCfg.SetBaseInterval(d)
	fmt.Printf("[+] Heartbeat base interval set to %v (jitter auto: ±%v)\n",
		c.heartbeatCfg.BaseInterval, c.heartbeatCfg.JitterAbs)
}

func (c *CLI) handleHeartbeatJitterAbs(input string) {
	matches := heartbeatJitterAbsRegex.FindStringSubmatch(input)
	d, err := time.ParseDuration(matches[1])
	if err != nil {
		fmt.Printf("[-] Invalid duration %q — use formats like 15s, 500ms\n", matches[1])
		return
	}
	if d <= 0 {
		fmt.Println("[-] Jitter must be greater than zero")
		return
	}
	if d >= c.heartbeatCfg.BaseInterval {
		fmt.Printf("[-] Jitter (%v) must be less than base interval (%v)\n", d, c.heartbeatCfg.BaseInterval)
		return
	}
	pct := float64(d) / float64(c.heartbeatCfg.BaseInterval)
	c.heartbeatCfg.SetJitterAbs(c.heartbeatCfg.BaseInterval, pct)
	fmt.Printf("[+] Jitter set to ±%v (%.0f%% of base interval)\n", c.heartbeatCfg.JitterAbs, pct*100)
}

func (c *CLI) handleHeartbeatJitterPct(input string) {
	matches := heartbeatJitterPctRegex.FindStringSubmatch(input)
	pct, err := strconv.ParseFloat(matches[1], 64)
	if err != nil || pct < 0 || pct > 1 {
		fmt.Println("[!] Invalid percentage — use 0.0–1.0, e.g., 0.2 for 20%")
		return
	}
	if pct == 0 {
		fmt.Println("[!] JITTER PERCENTAGE MUST BE GREATER THAN ZERO")
		return
	}
	c.heartbeatCfg.SetJitterAbs(c.heartbeatCfg.BaseInterval, pct)
	fmt.Printf("[+] Jitter set to ±%v (%.0f%% of base interval)\n", c.heartbeatCfg.JitterAbs, pct*100)
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
	fmt.Println("  use <host:port>         Set target server    (use 10.0.0.1:8080)")
	fmt.Println("  send                    Send a beacon payload")
	fmt.Println("  show                    Display transport configuration")
	fmt.Println("  heartbeat               Show heartbeat configuration")
	fmt.Println("  heartbeat set <d>       Set heartbeat base interval (heartbeat set 90s)")
	fmt.Println("  heartbeat jitter abs <d> Set absolute jitter (heartbeat jitter abs 15s)")
	fmt.Println("  heartbeat jitter pct <p> Set jitter percentage (heartbeat jitter pct 0.2)")
	fmt.Println("  help                    Show this menu")
	fmt.Println("  exit                    Exit the program")
	fmt.Println(strings.Repeat("-", 56))
}
