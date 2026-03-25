package suricata

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/common/socket"
)

// Client communicates with a running Suricata instance through its Unix
// domain socket control interface.  It delegates the low-level socket
// I/O to the shared socket.JSONClient.
type Client struct {
	socket *socket.JSONClient
}

// NewClient creates a Suricata control socket client.
// socketPath is typically /var/run/suricata/suricata-command.socket.
func NewClient(socketPath string, timeout time.Duration) *Client {
	return &Client{
		socket: socket.NewJSONClient(socketPath, timeout),
	}
}

// Execute sends an arbitrary Command to Suricata and returns the parsed Response.
func (c *Client) Execute(ctx context.Context, cmd Command) (*Response, error) {
	var resp Response
	if err := c.socket.Execute(ctx, cmd, &resp); err != nil {
		return nil, fmt.Errorf("suricata execute %q: %w", cmd.Command, err)
	}
	if resp.Return != "OK" {
		return &resp, fmt.Errorf("suricata command %q failed: return=%s message=%v", cmd.Command, resp.Return, resp.Message)
	}
	return &resp, nil
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
	return c.socket.IsAvailable()
}
