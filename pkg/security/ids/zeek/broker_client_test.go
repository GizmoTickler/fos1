package zeek

import (
	"context"
	"testing"
	"time"
)

func TestNewBrokerClient(t *testing.T) {
	client := NewBrokerClient(DefaultBrokerOptions())
	if client == nil {
		t.Fatal("NewBrokerClient returned nil")
	}
	if client.IsConnected() {
		t.Error("should not be connected initially")
	}
}

func TestSubscribeUnsubscribe(t *testing.T) {
	client := NewBrokerClient(DefaultBrokerOptions())

	ch, err := client.Subscribe("zeek/logs/conn")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if ch == nil {
		t.Fatal("channel should not be nil")
	}

	// Duplicate subscription should fail
	_, err = client.Subscribe("zeek/logs/conn")
	if err == nil {
		t.Error("duplicate subscription should fail")
	}

	// Unsubscribe
	if err := client.Unsubscribe("zeek/logs/conn"); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}

	// Unsubscribe non-existent
	if err := client.Unsubscribe("nonexistent"); err == nil {
		t.Error("unsubscribing non-existent topic should fail")
	}
}

func TestDispatchEvent(t *testing.T) {
	client := NewBrokerClient(DefaultBrokerOptions())

	ch, _ := client.Subscribe("test/topic")

	event := BrokerEvent{
		Topic:     "test/topic",
		Type:      "event",
		Timestamp: time.Now(),
		Data:      map[string]any{"key": "value"},
	}

	client.dispatchEvent(event)

	select {
	case received := <-ch:
		if received.Topic != "test/topic" {
			t.Errorf("expected topic test/topic, got %s", received.Topic)
		}
		if received.Data["key"] != "value" {
			t.Error("event data mismatch")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for dispatched event")
	}
}

func TestDispatchEventNoSubscriber(t *testing.T) {
	client := NewBrokerClient(DefaultBrokerOptions())

	// Should not panic when no subscriber
	event := BrokerEvent{
		Topic: "unsubscribed/topic",
		Type:  "event",
	}
	client.dispatchEvent(event)
}

func TestPublishNotConnected(t *testing.T) {
	client := NewBrokerClient(DefaultBrokerOptions())

	err := client.Publish(context.Background(), BrokerEvent{
		Topic: "test",
		Data:  map[string]any{},
	})
	if err == nil {
		t.Error("publish while disconnected should fail")
	}
}

func TestPeerInfo(t *testing.T) {
	client := NewBrokerClient(BrokerOptions{Address: "10.0.0.1:9753"})

	info, err := client.PeerInfo()
	if err != nil {
		t.Fatalf("PeerInfo: %v", err)
	}
	if info.Address != "10.0.0.1:9753" {
		t.Errorf("expected address 10.0.0.1:9753, got %s", info.Address)
	}
	if info.Connected {
		t.Error("should not be connected")
	}
}

func TestDisconnectIdempotent(t *testing.T) {
	client := NewBrokerClient(DefaultBrokerOptions())

	// Should not error when not connected
	if err := client.Disconnect(); err != nil {
		t.Errorf("disconnect when not connected should not error: %v", err)
	}
}
