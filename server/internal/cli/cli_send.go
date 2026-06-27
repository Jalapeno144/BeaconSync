package cli

import (
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Beacon commands
// ---------------------------------------------------------------------------

// sendBeacon marshals and sends a beacon payload through the transport.
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
