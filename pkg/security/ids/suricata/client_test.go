package suricata

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

// mockServer creates a temporary Unix socket that accepts one connection,
// reads a JSON Command, and writes back the given response bytes before
// closing the connection.  It returns the socket path and a cleanup func.
func mockServer(t *testing.T, handler func(cmd Command) Response) (string, func()) {
	t.Helper()

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix socket listeners unavailable in this environment: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()

				var cmd Command
				dec := json.NewDecoder(c)
				if err := dec.Decode(&cmd); err != nil {
					return
				}

				resp := handler(cmd)
				respBytes, _ := json.Marshal(resp)
				c.Write(respBytes)
			}(conn)
		}
	}()

	cleanup := func() {
		ln.Close()
		<-done
		os.RemoveAll(dir)
	}

	return sockPath, cleanup
}

func TestVersion(t *testing.T) {
	sockPath, cleanup := mockServer(t, func(cmd Command) Response {
		assert.Equal(t, "version", cmd.Command)
		return Response{
			Return:  "OK",
			Message: "7.0.3",
		}
	})
	defer cleanup()

	client := NewClient(sockPath, 5*time.Second)

	ctx := context.Background()
	version, err := client.Version(ctx)
	require.NoError(t, err)
	assert.Equal(t, "7.0.3", version)
}

func TestReloadRules(t *testing.T) {
	sockPath, cleanup := mockServer(t, func(cmd Command) Response {
		assert.Equal(t, "reload-rules", cmd.Command)
		return Response{
			Return:  "OK",
			Message: "done",
		}
	})
	defer cleanup()

	client := NewClient(sockPath, 5*time.Second)

	ctx := context.Background()
	err := client.ReloadRules(ctx)
	require.NoError(t, err)
}

func TestGetStats(t *testing.T) {
	sockPath, cleanup := mockServer(t, func(cmd Command) Response {
		assert.Equal(t, "dump-counters", cmd.Command)
		return Response{
			Return: "OK",
			Message: map[string]any{
				"uptime": float64(3600),
				"capture": map[string]any{
					"kernel_packets": float64(100000),
					"kernel_drops":   float64(5),
					"errors":         float64(0),
				},
				"decoder": map[string]any{
					"pkts":     float64(99000),
					"bytes":    float64(5000000),
					"invalid":  float64(10),
					"ipv4":     float64(80000),
					"ipv6":     float64(19000),
					"ethernet": float64(99000),
					"tcp":      float64(60000),
					"udp":      float64(30000),
					"icmp":     float64(1000),
				},
				"flow": map[string]any{
					"total":     float64(5000),
					"active":    float64(200),
					"tcp":       float64(3000),
					"udp":       float64(1800),
					"icmp":      float64(200),
					"timed_out": float64(50),
				},
				"detect": map[string]any{
					"alerts":        float64(42),
					"rules_loaded":  float64(30000),
					"rules_failed":  float64(3),
					"rules_skipped": float64(10),
				},
			},
		}
	})
	defer cleanup()

	client := NewClient(sockPath, 5*time.Second)

	ctx := context.Background()
	stats, err := client.GetStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3600), stats.Uptime)
	assert.Equal(t, int64(100000), stats.Capture.KernelPackets)
	assert.Equal(t, int64(5), stats.Capture.KernelDrops)
	assert.Equal(t, int64(42), stats.Detect.Alerts)
	assert.Equal(t, int64(30000), stats.Detect.RulesLoaded)
	assert.Equal(t, int64(200), stats.Flow.Active)
	assert.Equal(t, int64(99000), stats.Decoder.Pkts)
}

func TestListInterfaces(t *testing.T) {
	sockPath, cleanup := mockServer(t, func(cmd Command) Response {
		assert.Equal(t, "iface-list", cmd.Command)
		return Response{
			Return: "OK",
			Message: map[string]any{
				"ifaces": []any{"eth0", "eth1", "br0"},
			},
		}
	})
	defer cleanup()

	client := NewClient(sockPath, 5*time.Second)

	ctx := context.Background()
	ifaces, err := client.ListInterfaces(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"eth0", "eth1", "br0"}, ifaces)
}

func TestErrorResponse(t *testing.T) {
	sockPath, cleanup := mockServer(t, func(cmd Command) Response {
		return Response{
			Return:  "NOK",
			Message: "unknown command",
		}
	})
	defer cleanup()

	client := NewClient(sockPath, 5*time.Second)

	ctx := context.Background()
	_, err := client.Version(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOK")
}

func TestTimeout(t *testing.T) {
	// Create a socket that accepts but never responds, causing a timeout.
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "slow.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix socket listeners unavailable in this environment: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold connection open without responding.
			go func(c net.Conn) {
				time.Sleep(10 * time.Second)
				c.Close()
			}(conn)
		}
	}()

	client := NewClient(sockPath, 500*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err = client.Version(ctx)
	require.Error(t, err)
}

func TestIsRunning(t *testing.T) {
	t.Run("available", func(t *testing.T) {
		sockPath, cleanup := mockServer(t, func(cmd Command) Response {
			return Response{Return: "OK"}
		})
		defer cleanup()

		client := NewClient(sockPath, 5*time.Second)
		assert.True(t, client.IsRunning())
	})

	t.Run("unavailable", func(t *testing.T) {
		client := NewClient("/tmp/nonexistent-suricata-test.sock", 2*time.Second)
		assert.False(t, client.IsRunning())
	})
}

func TestShutdownGraceful(t *testing.T) {
	sockPath, cleanup := mockServer(t, func(cmd Command) Response {
		assert.Equal(t, "shutdown", cmd.Command)
		return Response{
			Return:  "OK",
			Message: "closing",
		}
	})
	defer cleanup()

	client := NewClient(sockPath, 5*time.Second)

	ctx := context.Background()
	err := client.ShutdownGraceful(ctx)
	require.NoError(t, err)
}
