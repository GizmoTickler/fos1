package suricata

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

const defaultHTTPSCommandPath = "/suricata-command"

// Transport selects how the client reaches Suricata's command interface.
type Transport string

const (
	// TransportUnix reaches the pod-local Suricata Unix command socket.
	TransportUnix Transport = "unix"
	// TransportHTTPS reaches a TLS-wrapped TCP command endpoint.
	TransportHTTPS Transport = "https"
)

// ClientConfig contains the Suricata command client settings.
type ClientConfig struct {
	// Transport defaults to TransportUnix.
	Transport Transport
	// SocketPath is the Suricata Unix command socket path.
	SocketPath string
	// Timeout bounds each command round-trip.
	Timeout time.Duration
	// AuthToken, when set, is sent as an auth command before each Unix socket
	// command on the same connection. The value must never be logged.
	AuthToken string
	// AuthTokenFile, when set, is read per command to support Kubernetes
	// Secret volume rotation without putting the token value in argv.
	AuthTokenFile string
	// TLSEndpoint is the https:// endpoint for the TCP fallback.
	TLSEndpoint string
	// TLSCAFile is the PEM CA bundle used to verify the TLS endpoint.
	TLSCAFile string
	// TLSCertFile is the client certificate used for mTLS.
	TLSCertFile string
	// TLSKeyFile is the client private key used for mTLS.
	TLSKeyFile string
	// TLSServerName overrides certificate DNS-name verification.
	TLSServerName string
}

// Client communicates with a running Suricata instance through its Unix
// domain socket control interface or a TLS-wrapped TCP fallback.
type Client struct {
	config ClientConfig
	http   *http.Client
}

// NewClient creates a Suricata control socket client.
// socketPath is typically /var/run/suricata/suricata-command.socket.
func NewClient(socketPath string, timeout time.Duration) *Client {
	return NewClientWithConfig(ClientConfig{
		SocketPath: socketPath,
		Timeout:    timeout,
	})
}

// NewClientWithConfig creates a Suricata client with explicit transport
// settings. It also honors FOS1_SURICATA_* environment overrides so
// controllers can be moved from pod-local sockets to the TLS endpoint by
// manifest alone.
func NewClientWithConfig(config ClientConfig) *Client {
	applyEnvironmentConfig(&config)
	if config.Transport == "" {
		config.Transport = TransportUnix
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	return &Client{config: config}
}

// Execute sends an arbitrary Command to Suricata and returns the parsed Response.
func (c *Client) Execute(ctx context.Context, cmd Command) (*Response, error) {
	var (
		resp *Response
		err  error
	)
	if c.config.Transport == TransportHTTPS || c.config.TLSEndpoint != "" {
		resp, err = c.executeHTTPS(ctx, cmd)
	} else {
		resp, err = c.executeUnix(ctx, cmd)
	}
	if err != nil {
		return nil, fmt.Errorf("suricata execute %q: %w", cmd.Command, err)
	}
	if resp.Return != "OK" {
		return resp, fmt.Errorf("suricata command %q failed: return=%s message=%v", cmd.Command, resp.Return, resp.Message)
	}
	return resp, nil
}

func (c *Client) executeUnix(ctx context.Context, cmd Command) (*Response, error) {
	if c.config.SocketPath == "" {
		return nil, fmt.Errorf("unix transport requires SocketPath")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.config.Timeout)
	}

	dialer := net.Dialer{Timeout: c.config.Timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.config.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", c.config.SocketPath, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	if token, err := c.authToken(); err != nil {
		return nil, err
	} else if token != "" {
		auth := Command{
			Command: "auth",
			Arguments: map[string]any{
				"token": token,
			},
		}
		if err := enc.Encode(auth); err != nil {
			return nil, fmt.Errorf("write auth request: %w", err)
		}
		var authResp Response
		if err := dec.Decode(&authResp); err != nil {
			return nil, fmt.Errorf("read auth response: %w", err)
		}
		if authResp.Return != "OK" {
			return nil, fmt.Errorf("suricata socket authentication failed: return=%s", authResp.Return)
		}
	}

	if err := enc.Encode(cmd); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return &resp, nil
}

func (c *Client) executeHTTPS(ctx context.Context, cmd Command) (*Response, error) {
	if c.config.TLSEndpoint == "" {
		return nil, fmt.Errorf("https transport requires TLSEndpoint")
	}
	if c.config.TLSCAFile == "" || c.config.TLSCertFile == "" || c.config.TLSKeyFile == "" {
		return nil, fmt.Errorf("https transport requires TLSCAFile, TLSCertFile, and TLSKeyFile")
	}
	client, err := c.httpClient()
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	endpoint := strings.TrimRight(c.config.TLSEndpoint, "/") + defaultHTTPSCommandPath
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build https request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token, err := c.authToken(); err != nil {
		return nil, err
	} else if token != "" {
		req.Header.Set("X-FOS1-Suricata-Auth", token)
	}

	httpResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("https command failed: %w", err)
	}
	defer httpResp.Body.Close()

	var resp Response
	if err := json.NewDecoder(io.LimitReader(httpResp.Body, 1<<20)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode https response: %w", err)
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		return &resp, fmt.Errorf("https command failed: status %d", httpResp.StatusCode)
	}
	return &resp, nil
}

func (c *Client) httpClient() (*http.Client, error) {
	if c.http != nil {
		return c.http, nil
	}

	caPEM, err := os.ReadFile(c.config.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("read Suricata CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("Suricata CA bundle contained no PEM certificates")
	}
	cert, err := tls.LoadX509KeyPair(c.config.TLSCertFile, c.config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load Suricata client certificate: %w", err)
	}

	c.http = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				RootCAs:      roots,
				Certificates: []tls.Certificate{cert},
				ServerName:   c.config.TLSServerName,
			},
		},
	}
	return c.http, nil
}

func (c *Client) authToken() (string, error) {
	if c.config.AuthToken != "" {
		return c.config.AuthToken, nil
	}
	if c.config.AuthTokenFile == "" {
		return "", nil
	}
	data, err := os.ReadFile(c.config.AuthTokenFile)
	if err != nil {
		return "", fmt.Errorf("read Suricata auth token file: %w", err)
	}
	token := strings.TrimRight(string(data), "\r\n")
	if token == "" {
		return "", fmt.Errorf("Suricata auth token file is empty")
	}
	return token, nil
}

func applyEnvironmentConfig(config *ClientConfig) {
	if endpoint := os.Getenv("FOS1_SURICATA_COMMAND_ENDPOINT"); endpoint != "" {
		config.Transport = TransportHTTPS
		config.TLSEndpoint = endpoint
	}
	if value := os.Getenv("FOS1_SURICATA_COMMAND_SOCKET"); value != "" {
		config.SocketPath = value
	}
	if value := os.Getenv("FOS1_SURICATA_COMMAND_AUTH_TOKEN"); value != "" {
		config.AuthToken = value
	}
	if value := os.Getenv("FOS1_SURICATA_COMMAND_AUTH_TOKEN_FILE"); value != "" {
		config.AuthTokenFile = value
	}
	if value := os.Getenv("FOS1_SURICATA_COMMAND_CA_FILE"); value != "" {
		config.TLSCAFile = value
	}
	if value := os.Getenv("FOS1_SURICATA_COMMAND_CERT_FILE"); value != "" {
		config.TLSCertFile = value
	}
	if value := os.Getenv("FOS1_SURICATA_COMMAND_KEY_FILE"); value != "" {
		config.TLSKeyFile = value
	}
	if value := os.Getenv("FOS1_SURICATA_COMMAND_SERVER_NAME"); value != "" {
		config.TLSServerName = value
	}
}

// Version returns the Suricata version string.
func (c *Client) Version(ctx context.Context) (string, error) {
	resp, err := c.Execute(ctx, Command{Command: "version"})
	if err != nil {
		return "", err
	}
	version, ok := resp.Message.(string)
	if !ok {
		return fmt.Sprintf("%v", resp.Message), nil
	}
	return version, nil
}

// ReloadRules tells Suricata to reload its rule files.
func (c *Client) ReloadRules(ctx context.Context) error {
	_, err := c.Execute(ctx, Command{Command: "reload-rules"})
	if err != nil {
		return err
	}
	klog.V(2).Info("Suricata rules reloaded successfully")
	return nil
}

// GetStats retrieves Suricata's internal counters via the "dump-counters" command.
func (c *Client) GetStats(ctx context.Context) (*SuricataStats, error) {
	resp, err := c.Execute(ctx, Command{Command: "dump-counters"})
	if err != nil {
		return nil, err
	}

	// The message field contains the stats as a nested object.
	// Re-marshal and unmarshal into the typed struct.
	raw, err := json.Marshal(resp.Message)
	if err != nil {
		return nil, fmt.Errorf("marshal stats message: %w", err)
	}

	var stats SuricataStats
	if err := json.Unmarshal(raw, &stats); err != nil {
		return nil, fmt.Errorf("unmarshal stats: %w", err)
	}
	return &stats, nil
}

// ListInterfaces returns the list of capture interfaces that Suricata is
// currently listening on.
func (c *Client) ListInterfaces(ctx context.Context) ([]string, error) {
	resp, err := c.Execute(ctx, Command{Command: "iface-list"})
	if err != nil {
		return nil, err
	}

	// The message is expected to be a map with an "ifaces" key containing a
	// list of strings.
	raw, err := json.Marshal(resp.Message)
	if err != nil {
		return nil, fmt.Errorf("marshal iface-list message: %w", err)
	}

	var result struct {
		Ifaces []string `json:"ifaces"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("unmarshal iface-list: %w", err)
	}
	return result.Ifaces, nil
}

// ShutdownGraceful sends a graceful shutdown command to Suricata.
func (c *Client) ShutdownGraceful(ctx context.Context) error {
	_, err := c.Execute(ctx, Command{Command: "shutdown"})
	if err != nil {
		return err
	}
	klog.V(2).Info("Suricata graceful shutdown initiated")
	return nil
}

// IsRunning checks whether the Suricata control socket is connectable.
func (c *Client) IsRunning() bool {
	if c.config.Transport == TransportHTTPS || c.config.TLSEndpoint != "" {
		ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
		defer cancel()
		_, err := c.Version(ctx)
		return err == nil
	}
	conn, err := net.DialTimeout("unix", c.config.SocketPath, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
