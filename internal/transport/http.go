package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// TLS configuration Path
type TLSConfig struct {
	Mode   string `yaml:"mode"`    // "strict" | "skip" | "custom"
	CAPath string `yaml:"ca_path"` // optional
}

// httpTransportConfig holds internal configuration for HTTPTransport.
type httpTransportConfig struct {
	maxIdleConns      int
	idleConnTimeout   time.Duration
	disableKeepAlives bool
	timeout           time.Duration

	TLS TLSConfig `yaml:"tls"` // Add TLS configuration
}

// HTTPTransport implements Transport over HTTP and HTTPS.
type HTTPTransport struct {
	serverAddr string
	protocol   string
	client     *http.Client
	modifiers  []RequestModifier // Allow users to set request head
}

// HTTPTransportOption is a functional option for configuring HTTPTransport.
type HTTPTransportOption func(*httpTransportConfig)

// interface which allows users to modify their http request head
type RequestModifier func(*http.Request) error

// WithMaxIdleConns sets the maximum number of idle connections in the pool.
func WithMaxIdleConns(n int) HTTPTransportOption {
	return func(c *httpTransportConfig) { c.maxIdleConns = n }
}

// WithIdleConnTimeout sets how long an idle connection stays in the pool.
func WithIdleConnTimeout(d time.Duration) HTTPTransportOption {
	return func(c *httpTransportConfig) { c.idleConnTimeout = d }
}

// WithDisableKeepAlives disables HTTP keep-alive when set to true.
func WithDisableKeepAlives(b bool) HTTPTransportOption {
	return func(c *httpTransportConfig) { c.disableKeepAlives = b }
}

// WithTimeout sets the overall request timeout.
func WithTimeout(d time.Duration) HTTPTransportOption {
	return func(c *httpTransportConfig) { c.timeout = d }
}

// Set TLS Mode. Optional: strict | custom | skip
func WithTLSMode(mode string) HTTPTransportOption {
	return func(c *httpTransportConfig) {
		c.TLS.Mode = mode
	}
}

// Add temporary CA to communication
func WithCAPath(path string) HTTPTransportOption {
	return func(c *httpTransportConfig) {
		c.TLS.CAPath = path
	}
}

// NewHTTPTransport creates a new HTTPTransport with the given address,
// protocol ("http" or "https"), and optional configuration.
func NewHTTPTransport(addr, proto string, opts ...HTTPTransportOption) (*HTTPTransport, error) {
	cfg := &httpTransportConfig{
		maxIdleConns:      10,
		idleConnTimeout:   30 * time.Second,
		disableKeepAlives: false,
		timeout:           10 * time.Second,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	tr := &http.Transport{
		MaxIdleConns:      cfg.maxIdleConns,
		IdleConnTimeout:   cfg.idleConnTimeout,
		DisableKeepAlives: cfg.disableKeepAlives,
	}

	if proto == "https" {
		tlsCfg := &tls.Config{}

		switch cfg.TLS.Mode {
		case "skip":
			tlsCfg.InsecureSkipVerify = true

		case "custom":
			cert, err := os.ReadFile(cfg.TLS.CAPath)
			if err != nil {
				return nil, fmt.Errorf("[!] FAILED TO READ CA: %w", err)
			}

			// Start from the system pool so enterprise proxy CAs remain
			// trusted — the outer TLS passes through SSL-decrypting
			// middleboxes without raising alerts.
			pool, err := x509.SystemCertPool()
			if err != nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(cert) {
				// failed to interpret PEM
			}
			tlsCfg.RootCAs = pool

		case "strict", "":
			//! default behavior which we consider safe
		}

		tr.TLSClientConfig = tlsCfg
	}

	return &HTTPTransport{
		serverAddr: addr,
		protocol:   proto,
		client: &http.Client{
			Timeout:   cfg.timeout,
			Transport: tr,
		},
	}, nil
}

func SetContentType(ct string) RequestModifier {
	return func(req *http.Request) error {
		req.Header.Set("Content-Type", ct)
		return nil
	}
}

func SetXForWarderFor(xfwf string) RequestModifier {
	return func(req *http.Request) error {
		req.Header.Set("X-Forwarded-For", xfwf)
		return nil
	}
}

func SetUserAgent(ua string) RequestModifier {
	return func(req *http.Request) error {
		req.Header.Set("User-Agent", ua)
		return nil
	}
}

// Connect sends a GET request to the /Connect endpoint to verify
// connectivity with the server.
func (h *HTTPTransport) Connect() error {
	url := fmt.Sprintf("%s://%s/Connect", h.protocol, h.serverAddr)

	resp, err := h.client.Get(url)
	if err != nil {
		return fmt.Errorf("Connect failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Connect returned status %d", resp.StatusCode)
	}

	return nil
}

// Send transmits data to the server by POSTing to the /data endpoint.
func (h *HTTPTransport) Send(data []byte) ([]byte, error) {
	url := fmt.Sprintf("%s://%s/data", h.protocol, h.serverAddr)

	resp, err := h.client.Post(url, "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("send failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("send returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	return body, nil
}

// Close drains and closes idle connections in the underlying pool.
func (h *HTTPTransport) Close() error {
	h.client.CloseIdleConnections()
	return nil
}

// ServerAddr returns the currently configured server address (host:port).
func (h *HTTPTransport) ServerAddr() string { return h.serverAddr }

// Proto returns the protocol string ("http" or "https").
func (h *HTTPTransport) Proto() string { return h.protocol }

// Ensure HTTPTransport satisfies Transport at compile time.
var _ Transport = (*HTTPTransport)(nil)
