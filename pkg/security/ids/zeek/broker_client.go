// Package zeek provides integration with Zeek network analysis framework.
package zeek

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// BrokerEvent represents an event received from or sent to Zeek via the Broker API.
type BrokerEvent struct {
	Topic     string         `json:"topic"`
	Type      string         `json:"type"` // "event", "log", "error"
	Timestamp time.Time      `json:"timestamp"`
	Data      map[string]any `json:"data"`
}

// BrokerOptions configures the Broker client connection.
type BrokerOptions struct {
	Address       string        // host:port (default: "127.0.0.1:9753")
	Timeout       time.Duration // connection timeout
	RetryInterval time.Duration
	MaxRetries    int
}

// DefaultBrokerOptions returns sensible defaults.
func DefaultBrokerOptions() BrokerOptions {
	return BrokerOptions{
		Address:       "127.0.0.1:9753",
		Timeout:       10 * time.Second,
		RetryInterval: 5 * time.Second,
		MaxRetries:    3,
	}
}

// PeerInfo contains information about a Zeek Broker peer.
type PeerInfo struct {
	Address   string
	Connected bool
	Version   string
}

// BrokerClient communicates with Zeek via its Broker API.
type BrokerClient struct {
	opts       BrokerOptions
	conn       net.Conn
	mu         sync.Mutex
	connected  bool
	subscriptions map[string]chan BrokerEvent
	subMu      sync.RWMutex
}

// NewBrokerClient creates a new Zeek Broker client.
func NewBrokerClient(opts BrokerOptions) *BrokerClient {
	if opts.Address == "" {
		opts = DefaultBrokerOptions()
	}
	return &BrokerClient{
		opts:          opts,
		subscriptions: make(map[string]chan BrokerEvent),
	}
}

// Connect establishes a connection to the Zeek Broker.
func (c *BrokerClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	var lastErr error
	for attempt := 0; attempt <= c.opts.MaxRetries; attempt++ {
		conn, err := net.DialTimeout("tcp", c.opts.Address, c.opts.Timeout)
		if err != nil {
			lastErr = err
			if attempt < c.opts.MaxRetries {
				klog.V(4).Infof("Zeek Broker connect attempt %d failed: %v, retrying...", attempt+1, err)
				time.Sleep(c.opts.RetryInterval)
				continue
			}
		} else {
			c.conn = conn
			c.connected = true
			klog.Infof("Connected to Zeek Broker at %s", c.opts.Address)
			return nil
		}
	}

	return fmt.Errorf("failed to connect to Zeek Broker at %s after %d attempts: %w",
		c.opts.Address, c.opts.MaxRetries+1, lastErr)
}

// Disconnect closes the connection to Zeek Broker.
func (c *BrokerClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected || c.conn == nil {
		return nil
	}

	err := c.conn.Close()
	c.connected = false
	c.conn = nil

	// Close all subscription channels
	c.subMu.Lock()
	for topic, ch := range c.subscriptions {
		close(ch)
		delete(c.subscriptions, topic)
	}
	c.subMu.Unlock()

	klog.Info("Disconnected from Zeek Broker")
	return err
}

// IsConnected returns whether the client is connected.
func (c *BrokerClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// Subscribe registers interest in events on a topic and returns a channel.
func (c *BrokerClient) Subscribe(topic string) (<-chan BrokerEvent, error) {
	c.subMu.Lock()
	defer c.subMu.Unlock()

	if _, exists := c.subscriptions[topic]; exists {
		return nil, fmt.Errorf("already subscribed to topic %s", topic)
	}

	ch := make(chan BrokerEvent, 100)
	c.subscriptions[topic] = ch

	klog.V(4).Infof("Subscribed to Zeek Broker topic: %s", topic)
	return ch, nil
}

// Unsubscribe removes a topic subscription.
func (c *BrokerClient) Unsubscribe(topic string) error {
	c.subMu.Lock()
	defer c.subMu.Unlock()

	ch, exists := c.subscriptions[topic]
	if !exists {
		return fmt.Errorf("not subscribed to topic %s", topic)
	}

	close(ch)
	delete(c.subscriptions, topic)
	return nil
}

// Publish sends an event to a topic on the Zeek Broker.
func (c *BrokerClient) Publish(ctx context.Context, event BrokerEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected || c.conn == nil {
		return fmt.Errorf("not connected to Zeek Broker")
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.opts.Timeout)
	}
	c.conn.SetWriteDeadline(deadline)

	if _, err := c.conn.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write event: %w", err)
	}

	klog.V(5).Infof("Published event to Zeek Broker topic %s", event.Topic)
	return nil
}

// PeerInfo queries the Broker for peer information.
func (c *BrokerClient) PeerInfo() (*PeerInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return &PeerInfo{
		Address:   c.opts.Address,
		Connected: c.connected,
	}, nil
}

// dispatchEvent routes a received event to the appropriate subscription channel.
func (c *BrokerClient) dispatchEvent(event BrokerEvent) {
	c.subMu.RLock()
	defer c.subMu.RUnlock()

	if ch, ok := c.subscriptions[event.Topic]; ok {
		select {
		case ch <- event:
		default:
			klog.Warningf("Zeek Broker subscription buffer full for topic %s, dropping event", event.Topic)
		}
	}
}
