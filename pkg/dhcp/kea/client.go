package kea

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/GizmoTickler/fos1/pkg/common/socket"
	"k8s.io/klog/v2"
)

// Client communicates with a Kea DHCP daemon via its Unix control socket.
type Client struct {
	socket  *socket.JSONClient
	service string // "dhcp4" or "dhcp6"
}

// NewClient creates a new Kea control socket client.
// socketPath is the path to the Kea Unix control socket.
// service is the target Kea service, typically "dhcp4" or "dhcp6".
func NewClient(socketPath string, service string) *Client {
	return &Client{
		socket:  socket.NewJSONClient(socketPath, 10*time.Second),
		service: service,
	}
}

// Execute sends a command to the Kea control socket and returns the response array.
// Kea always returns a JSON array of response objects, even for single responses.
func (c *Client) Execute(ctx context.Context, command string, args any) ([]KeaResponse, error) {
	cmd := KeaCommand{
		Command:   command,
		Service:   []string{c.service},
		Arguments: args,
	}

	klog.V(4).Infof("kea: sending command %q to service %s", command, c.service)

	var rawResp json.RawMessage
	if err := c.socket.Execute(ctx, cmd, &rawResp); err != nil {
		return nil, fmt.Errorf("kea execute %s: %w", command, err)
	}

	var responses []KeaResponse
	if err := json.Unmarshal(rawResp, &responses); err != nil {
		return nil, fmt.Errorf("kea unmarshal response for %s: %w", command, err)
	}

	if len(responses) == 0 {
		return nil, fmt.Errorf("kea %s: empty response array", command)
	}

	klog.V(4).Infof("kea: command %q returned result=%d text=%q", command, responses[0].Result, responses[0].Text)

	return responses, nil
}

// GetLease4 retrieves a single DHCPv4 lease by IP address.
func (c *Client) GetLease4(ctx context.Context, ip string) (*Lease4, error) {
	args := map[string]string{"ip-address": ip}

	responses, err := c.Execute(ctx, "lease4-get", args)
	if err != nil {
		return nil, err
	}

	resp := responses[0]
	if resp.Result != 0 {
		return nil, fmt.Errorf("lease4-get: result=%d: %s", resp.Result, resp.Text)
	}

	argBytes, err := json.Marshal(resp.Arguments)
	if err != nil {
		return nil, fmt.Errorf("lease4-get: marshal arguments: %w", err)
	}

	var lease Lease4
	if err := json.Unmarshal(argBytes, &lease); err != nil {
		return nil, fmt.Errorf("lease4-get: unmarshal lease: %w", err)
	}

	return &lease, nil
}

// GetAllLeases4 retrieves all DHCPv4 leases from the server.
func (c *Client) GetAllLeases4(ctx context.Context) ([]Lease4, error) {
	responses, err := c.Execute(ctx, "lease4-get-all", nil)
	if err != nil {
		return nil, err
	}

	resp := responses[0]
	if resp.Result != 0 {
		// Result 3 means empty — return nil slice, no error.
		if resp.Result == 3 {
			return nil, nil
		}
		return nil, fmt.Errorf("lease4-get-all: result=%d: %s", resp.Result, resp.Text)
	}

	argBytes, err := json.Marshal(resp.Arguments)
	if err != nil {
		return nil, fmt.Errorf("lease4-get-all: marshal arguments: %w", err)
	}

	// Kea returns {"leases": [...]}
	var wrapper struct {
		Leases []Lease4 `json:"leases"`
	}
	if err := json.Unmarshal(argBytes, &wrapper); err != nil {
		return nil, fmt.Errorf("lease4-get-all: unmarshal leases: %w", err)
	}

	return wrapper.Leases, nil
}

// AddReservation4 adds a DHCPv4 host reservation.
func (c *Client) AddReservation4(ctx context.Context, hwAddr, ip string, subnetID int) error {
	args := map[string]any{
		"reservation": map[string]any{
			"hw-address": hwAddr,
			"ip-address": ip,
			"subnet-id":  subnetID,
		},
	}

	responses, err := c.Execute(ctx, "reservation-add", args)
	if err != nil {
		return err
	}

	resp := responses[0]
	if resp.Result != 0 {
		return fmt.Errorf("reservation-add: result=%d: %s", resp.Result, resp.Text)
	}

	klog.V(2).Infof("kea: added reservation hw=%s ip=%s subnet=%d", hwAddr, ip, subnetID)
	return nil
}

// DeleteReservation4 deletes a DHCPv4 host reservation by IP address and subnet.
func (c *Client) DeleteReservation4(ctx context.Context, ip string, subnetID int) error {
	args := map[string]any{
		"ip-address": ip,
		"subnet-id":  subnetID,
	}

	responses, err := c.Execute(ctx, "reservation-del", args)
	if err != nil {
		return err
	}

	resp := responses[0]
	if resp.Result != 0 {
		return fmt.Errorf("reservation-del: result=%d: %s", resp.Result, resp.Text)
	}

	klog.V(2).Infof("kea: deleted reservation ip=%s subnet=%d", ip, subnetID)
	return nil
}

// ConfigGet retrieves the current running configuration from Kea.
func (c *Client) ConfigGet(ctx context.Context) (any, error) {
	responses, err := c.Execute(ctx, "config-get", nil)
	if err != nil {
		return nil, err
	}

	resp := responses[0]
	if resp.Result != 0 {
		return nil, fmt.Errorf("config-get: result=%d: %s", resp.Result, resp.Text)
	}

	return resp.Arguments, nil
}

// StatisticsGetAll retrieves all statistics from the Kea server.
func (c *Client) StatisticsGetAll(ctx context.Context) (map[string]any, error) {
	responses, err := c.Execute(ctx, "statistic-get-all", nil)
	if err != nil {
		return nil, err
	}

	resp := responses[0]
	if resp.Result != 0 {
		return nil, fmt.Errorf("statistic-get-all: result=%d: %s", resp.Result, resp.Text)
	}

	argBytes, err := json.Marshal(resp.Arguments)
	if err != nil {
		return nil, fmt.Errorf("statistic-get-all: marshal arguments: %w", err)
	}

	var stats map[string]any
	if err := json.Unmarshal(argBytes, &stats); err != nil {
		return nil, fmt.Errorf("statistic-get-all: unmarshal statistics: %w", err)
	}

	return stats, nil
}

// IsRunning checks whether the Kea daemon is reachable on its control socket.
func (c *Client) IsRunning() bool {
	return c.socket.IsAvailable()
}
