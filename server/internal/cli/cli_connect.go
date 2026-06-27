package cli

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Jalapeno144/BeaconSync/server/internal/transport"
)

// ---------------------------------------------------------------------------
// Connection management commands
// ---------------------------------------------------------------------------

// handleUse parses "use <host>:<port>" and reconnects to the new target.
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

// showConfig prints the current transport configuration.
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
