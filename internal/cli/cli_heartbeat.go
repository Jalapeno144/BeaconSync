package cli

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Heartbeat command patterns.
var (
	heartbeatSetRegex       = regexp.MustCompile(`^heartbeat\s+set\s+(\S+)$`)
	heartbeatJitterAbsRegex = regexp.MustCompile(`^heartbeat\s+jitter\s+abs\s+(\S+)$`)
	heartbeatJitterPctRegex = regexp.MustCompile(`^heartbeat\s+jitter\s+pct\s+(\S+)$`)
)

// ---------------------------------------------------------------------------
// Heartbeat commands
// ---------------------------------------------------------------------------

// handleHeartbeatShow prints the current heartbeat configuration.
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

// handleHeartbeatSet parses "heartbeat set <duration>" and updates the
// base heartbeat interval.
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

// handleHeartbeatJitterAbs parses "heartbeat jitter abs <duration>" and
// sets an absolute jitter value.
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

// handleHeartbeatJitterPct parses "heartbeat jitter pct <float>" and
// sets jitter as a percentage of the base interval.
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
