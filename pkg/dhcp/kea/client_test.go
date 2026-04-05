package kea

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKeaServer creates a Unix socket server that reads a JSON command,
// invokes the handler to produce a response, and writes it back.
// It returns the socket path and a cleanup function.
func mockKeaServer(t *testing.T, handler func(cmd KeaCommand) []KeaResponse) (string, func()) {
	t.Helper()

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "kea-test.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix socket listeners unavailable in this environment: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()

				// Use a JSON decoder so we don't block waiting for EOF.
				// The client sends exactly one JSON object per connection.
				dec := json.NewDecoder(c)
				var cmd KeaCommand
				if err := dec.Decode(&cmd); err != nil {
					resp := []KeaResponse{{Result: 1, Text: "bad request"}}
					out, _ := json.Marshal(resp)
					c.Write(out)
					return
				}

				responses := handler(cmd)
				out, _ := json.Marshal(responses)
				c.Write(out)
			}(conn)
		}
	}()

	cleanup := func() {
		listener.Close()
		<-done
	}

	return sockPath, cleanup
}

func TestGetLease4(t *testing.T) {
	sockPath, cleanup := mockKeaServer(t, func(cmd KeaCommand) []KeaResponse {
		assert.Equal(t, "lease4-get", cmd.Command)
		assert.Equal(t, []string{"dhcp4"}, cmd.Service)

		return []KeaResponse{{
			Result: 0,
			Text:   "IPv4 lease found.",
			Arguments: map[string]any{
				"ip-address": "192.168.1.100",
				"hw-address": "aa:bb:cc:dd:ee:ff",
				"subnet-id":  float64(1),
				"valid-lft":  float64(3600),
				"expire":     float64(1700000000),
				"hostname":   "myhost",
				"state":      float64(0),
				"client-id":  "01:aa:bb:cc:dd:ee:ff",
			},
		}}
	})
	defer cleanup()

	client := NewClient(sockPath, "dhcp4")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lease, err := client.GetLease4(ctx, "192.168.1.100")
	require.NoError(t, err)
	require.NotNil(t, lease)

	assert.Equal(t, "192.168.1.100", lease.Address)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", lease.HWAddress)
	assert.Equal(t, 1, lease.SubnetID)
	assert.Equal(t, 3600, lease.ValidLifetime)
	assert.Equal(t, int64(1700000000), lease.Expire)
	assert.Equal(t, "myhost", lease.Hostname)
	assert.Equal(t, 0, lease.State)
	assert.Equal(t, "01:aa:bb:cc:dd:ee:ff", lease.ClientID)
}

func TestGetAllLeases4(t *testing.T) {
	sockPath, cleanup := mockKeaServer(t, func(cmd KeaCommand) []KeaResponse {
		assert.Equal(t, "lease4-get-all", cmd.Command)

		return []KeaResponse{{
			Result: 0,
			Text:   "2 IPv4 lease(s) found.",
			Arguments: map[string]any{
				"leases": []any{
					map[string]any{
						"ip-address": "192.168.1.100",
						"hw-address": "aa:bb:cc:dd:ee:ff",
						"subnet-id":  float64(1),
						"valid-lft":  float64(3600),
						"expire":     float64(1700000000),
						"state":      float64(0),
					},
					map[string]any{
						"ip-address": "192.168.1.101",
						"hw-address": "11:22:33:44:55:66",
						"subnet-id":  float64(1),
						"valid-lft":  float64(7200),
						"expire":     float64(1700003600),
						"state":      float64(0),
					},
				},
			},
		}}
	})
	defer cleanup()

	client := NewClient(sockPath, "dhcp4")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	leases, err := client.GetAllLeases4(ctx)
	require.NoError(t, err)
	require.Len(t, leases, 2)

	assert.Equal(t, "192.168.1.100", leases[0].Address)
	assert.Equal(t, "192.168.1.101", leases[1].Address)
	assert.Equal(t, "11:22:33:44:55:66", leases[1].HWAddress)
}

func TestGetAllLeases4_Empty(t *testing.T) {
	sockPath, cleanup := mockKeaServer(t, func(cmd KeaCommand) []KeaResponse {
		return []KeaResponse{{
			Result: 3,
			Text:   "0 IPv4 lease(s) found.",
		}}
	})
	defer cleanup()

	client := NewClient(sockPath, "dhcp4")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	leases, err := client.GetAllLeases4(ctx)
	require.NoError(t, err)
	assert.Nil(t, leases)
}

func TestAddReservation4(t *testing.T) {
	sockPath, cleanup := mockKeaServer(t, func(cmd KeaCommand) []KeaResponse {
		assert.Equal(t, "reservation-add", cmd.Command)

		// Verify the arguments contain the reservation details.
		argBytes, _ := json.Marshal(cmd.Arguments)
		var args map[string]any
		json.Unmarshal(argBytes, &args)
		res := args["reservation"].(map[string]any)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", res["hw-address"])
		assert.Equal(t, "192.168.1.200", res["ip-address"])
		assert.Equal(t, float64(1), res["subnet-id"])

		return []KeaResponse{{
			Result: 0,
			Text:   "Host added.",
		}}
	})
	defer cleanup()

	client := NewClient(sockPath, "dhcp4")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.AddReservation4(ctx, "aa:bb:cc:dd:ee:ff", "192.168.1.200", 1)
	require.NoError(t, err)
}

func TestDeleteReservation4(t *testing.T) {
	sockPath, cleanup := mockKeaServer(t, func(cmd KeaCommand) []KeaResponse {
		assert.Equal(t, "reservation-del", cmd.Command)

		argBytes, _ := json.Marshal(cmd.Arguments)
		var args map[string]any
		json.Unmarshal(argBytes, &args)
		assert.Equal(t, "192.168.1.200", args["ip-address"])
		assert.Equal(t, float64(1), args["subnet-id"])

		return []KeaResponse{{
			Result: 0,
			Text:   "Host deleted.",
		}}
	})
	defer cleanup()

	client := NewClient(sockPath, "dhcp4")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.DeleteReservation4(ctx, "192.168.1.200", 1)
	require.NoError(t, err)
}

func TestErrorResponse(t *testing.T) {
	sockPath, cleanup := mockKeaServer(t, func(cmd KeaCommand) []KeaResponse {
		return []KeaResponse{{
			Result: 1,
			Text:   "IPv4 lease not found.",
		}}
	})
	defer cleanup()

	client := NewClient(sockPath, "dhcp4")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lease, err := client.GetLease4(ctx, "10.0.0.99")
	assert.Nil(t, lease)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "result=1")
	assert.Contains(t, err.Error(), "IPv4 lease not found")
}

func TestConfigGet(t *testing.T) {
	sockPath, cleanup := mockKeaServer(t, func(cmd KeaCommand) []KeaResponse {
		assert.Equal(t, "config-get", cmd.Command)

		return []KeaResponse{{
			Result: 0,
			Text:   "Configuration successful.",
			Arguments: map[string]any{
				"Dhcp4": map[string]any{
					"valid-lifetime": float64(4000),
				},
			},
		}}
	})
	defer cleanup()

	client := NewClient(sockPath, "dhcp4")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	config, err := client.ConfigGet(ctx)
	require.NoError(t, err)
	require.NotNil(t, config)

	configMap, ok := config.(map[string]any)
	require.True(t, ok)
	_, hasDhcp4 := configMap["Dhcp4"]
	assert.True(t, hasDhcp4)
}

func TestStatisticsGetAll(t *testing.T) {
	sockPath, cleanup := mockKeaServer(t, func(cmd KeaCommand) []KeaResponse {
		assert.Equal(t, "statistic-get-all", cmd.Command)

		return []KeaResponse{{
			Result: 0,
			Text:   "Statistics found.",
			Arguments: map[string]any{
				"pkt4-received":             []any{[]any{float64(1000), "2025-01-01 00:00:00.000"}},
				"pkt4-sent":                 []any{[]any{float64(950), "2025-01-01 00:00:00.000"}},
				"subnet[1].total-addresses": []any{[]any{float64(254), "2025-01-01 00:00:00.000"}},
			},
		}}
	})
	defer cleanup()

	client := NewClient(sockPath, "dhcp4")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := client.StatisticsGetAll(ctx)
	require.NoError(t, err)
	require.NotNil(t, stats)

	assert.Contains(t, stats, "pkt4-received")
	assert.Contains(t, stats, "pkt4-sent")
	assert.Contains(t, stats, "subnet[1].total-addresses")
}

func TestIsRunning(t *testing.T) {
	// Test with a socket that does not exist.
	client := NewClient("/tmp/nonexistent-kea-test.sock", "dhcp4")
	assert.False(t, client.IsRunning())

	// Test with a live mock socket.
	sockPath, cleanup := mockKeaServer(t, func(cmd KeaCommand) []KeaResponse {
		return []KeaResponse{{Result: 0, Text: "ok"}}
	})
	defer cleanup()

	client2 := NewClient(sockPath, "dhcp4")
	assert.True(t, client2.IsRunning())
}

func TestConnectionError(t *testing.T) {
	// Point at a socket that does not exist.
	badPath := filepath.Join(os.TempDir(), "kea-no-such-socket.sock")
	client := NewClient(badPath, "dhcp4")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.Execute(ctx, "config-get", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connect to")
}
