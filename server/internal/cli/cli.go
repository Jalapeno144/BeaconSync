// Package cli provides the interactive command-line interface for the
// BeaconSync client. It owns the REPL loop, command dispatch, and the
// lifecycle of the underlying transport.
package cli

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Jalapeno144/BeaconSync/server/internal/config"
	"github.com/Jalapeno144/BeaconSync/server/internal/scheduler"
	"github.com/Jalapeno144/BeaconSync/server/internal/transport"
)

// useRegex matches "use <host>:<port>" where host may be an IP, domain,
// or bracketed IPv6 address.
var useRegex = regexp.MustCompile(`^use\s+([a-zA-Z0-9_\-\.\:\[\]]+):(\d{1,5})$`)

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
