// Package socket provides a shared JSON-over-Unix-socket client used by
// daemon integrations (Suricata, Kea DHCP, etc.).
package socket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// JSONClient communicates with a daemon via JSON messages over a Unix domain socket.
// Each call connects, sends, receives, and disconnects (short-lived connections),
// matching the protocol used by Suricata and Kea control sockets.
type JSONClient struct {
	SocketPath string
	Timeout    time.Duration
	mu         sync.Mutex
}

// NewJSONClient creates a new Unix socket JSON client.
func NewJSONClient(socketPath string, timeout time.Duration) *JSONClient {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &JSONClient{
		SocketPath: socketPath,
		Timeout:    timeout,
	}
}

// Execute sends a JSON request and decodes the JSON response.
// It holds a mutex to serialize concurrent calls.
func (c *JSONClient) Execute(ctx context.Context, request any, response any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.Timeout)
	}

	conn, err := net.DialTimeout("unix", c.SocketPath, c.Timeout)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", c.SocketPath, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	// Send request
	reqBytes, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	if _, err := conn.Write(reqBytes); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	// Read response
	respBytes, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if response != nil {
		if err := json.Unmarshal(respBytes, response); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}

// ExecuteRaw sends raw bytes and returns raw response bytes.
func (c *JSONClient) ExecuteRaw(ctx context.Context, request []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.Timeout)
	}

	conn, err := net.DialTimeout("unix", c.SocketPath, c.Timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", c.SocketPath, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	return io.ReadAll(conn)
}

// IsAvailable checks if the socket path exists and is connectable.
func (c *JSONClient) IsAvailable() bool {
	conn, err := net.DialTimeout("unix", c.SocketPath, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
