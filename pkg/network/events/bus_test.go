package events

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewBus(t *testing.T) {
	bus := NewBus()
	if bus == nil {
		t.Fatal("NewBus returned nil")
	}
	if bus.SubscriberCount() != 0 {
		t.Errorf("expected 0 subscribers, got %d", bus.SubscriberCount())
	}
}

func TestSubscribeAndPublish(t *testing.T) {
	bus := NewBus()
	received := make(chan Event, 1)

	bus.Subscribe(InterfaceUp, func(e Event) {
		received <- e
	})

	event := Event{
		Type:   InterfaceUp,
		Source: "test",
		Data: InterfaceEventData{
			Name:  "eth0",
			State: "up",
		},
	}

	bus.Publish(event)

	select {
	case e := <-received:
		if e.Type != InterfaceUp {
			t.Errorf("expected type %s, got %s", InterfaceUp, e.Type)
		}
		data, ok := e.Data.(InterfaceEventData)
		if !ok {
			t.Fatal("expected InterfaceEventData")
		}
		if data.Name != "eth0" {
			t.Errorf("expected eth0, got %s", data.Name)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestSubscribeDoesNotReceiveOtherTypes(t *testing.T) {
	bus := NewBus()
	var called atomic.Bool

	bus.Subscribe(InterfaceUp, func(e Event) {
		called.Store(true)
	})

	bus.Publish(Event{Type: InterfaceDown, Source: "test"})

	time.Sleep(50 * time.Millisecond)
	if called.Load() {
		t.Error("handler was called for wrong event type")
	}
}

func TestSubscribeAll(t *testing.T) {
	bus := NewBus()
	var count atomic.Int32

	bus.SubscribeAll(func(e Event) {
		count.Add(1)
	})

	bus.Publish(Event{Type: InterfaceUp, Source: "test"})
	bus.Publish(Event{Type: RouteAdded, Source: "test"})
	bus.Publish(Event{Type: VLANCreated, Source: "test"})

	if count.Load() != 3 {
		t.Errorf("expected 3 events, got %d", count.Load())
	}
}

func TestUnsubscribe(t *testing.T) {
	bus := NewBus()
	var count atomic.Int32

	id := bus.Subscribe(InterfaceUp, func(e Event) {
		count.Add(1)
	})

	bus.Publish(Event{Type: InterfaceUp, Source: "test"})
	if count.Load() != 1 {
		t.Fatalf("expected 1, got %d", count.Load())
	}

	bus.Unsubscribe(id)

	bus.Publish(Event{Type: InterfaceUp, Source: "test"})
	if count.Load() != 1 {
		t.Errorf("expected still 1 after unsubscribe, got %d", count.Load())
	}
}

func TestUnsubscribeAll(t *testing.T) {
	bus := NewBus()
	var count atomic.Int32

	id := bus.SubscribeAll(func(e Event) {
		count.Add(1)
	})

	bus.Publish(Event{Type: InterfaceUp, Source: "test"})
	bus.Unsubscribe(id)
	bus.Publish(Event{Type: InterfaceUp, Source: "test"})

	if count.Load() != 1 {
		t.Errorf("expected 1, got %d", count.Load())
	}
}

func TestMultipleSubscribers(t *testing.T) {
	bus := NewBus()
	var count atomic.Int32

	for range 5 {
		bus.Subscribe(RouteAdded, func(e Event) {
			count.Add(1)
		})
	}

	bus.Publish(Event{Type: RouteAdded, Source: "test"})

	if count.Load() != 5 {
		t.Errorf("expected 5, got %d", count.Load())
	}
}

func TestPublishSetsTimestamp(t *testing.T) {
	bus := NewBus()
	received := make(chan Event, 1)

	bus.Subscribe(InterfaceUp, func(e Event) {
		received <- e
	})

	before := time.Now()
	bus.Publish(Event{Type: InterfaceUp, Source: "test"})

	e := <-received
	if e.Timestamp.Before(before) {
		t.Error("timestamp should be set to current time")
	}
}

func TestPublishPreservesExistingTimestamp(t *testing.T) {
	bus := NewBus()
	received := make(chan Event, 1)

	bus.Subscribe(InterfaceUp, func(e Event) {
		received <- e
	})

	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	bus.Publish(Event{Type: InterfaceUp, Source: "test", Timestamp: ts})

	e := <-received
	if !e.Timestamp.Equal(ts) {
		t.Errorf("expected preserved timestamp %v, got %v", ts, e.Timestamp)
	}
}

func TestClose(t *testing.T) {
	bus := NewBus()
	var count atomic.Int32

	bus.Subscribe(InterfaceUp, func(e Event) {
		count.Add(1)
	})

	bus.Publish(Event{Type: InterfaceUp, Source: "test"})
	bus.Close()
	bus.Publish(Event{Type: InterfaceUp, Source: "test"})

	if count.Load() != 1 {
		t.Errorf("expected 1 (no events after close), got %d", count.Load())
	}
}

func TestPublishAsyncConcurrency(t *testing.T) {
	bus := NewBus()
	var count atomic.Int32
	var wg sync.WaitGroup

	for range 10 {
		bus.Subscribe(InterfaceUp, func(e Event) {
			count.Add(1)
			wg.Done()
		})
	}

	wg.Add(10)
	bus.PublishAsync(Event{Type: InterfaceUp, Source: "test"})
	wg.Wait()

	if count.Load() != 10 {
		t.Errorf("expected 10, got %d", count.Load())
	}
}

func TestConcurrentPublishSubscribe(t *testing.T) {
	bus := NewBus()
	var count atomic.Int32
	done := make(chan struct{})

	// Concurrent subscribers
	go func() {
		for range 100 {
			id := bus.Subscribe(InterfaceUp, func(e Event) {
				count.Add(1)
			})
			bus.Unsubscribe(id)
		}
		close(done)
	}()

	// Concurrent publishers
	for range 100 {
		bus.Publish(Event{Type: InterfaceUp, Source: "test"})
	}

	<-done
}

func TestSubscriberCount(t *testing.T) {
	bus := NewBus()

	id1 := bus.Subscribe(InterfaceUp, func(e Event) {})
	bus.Subscribe(RouteAdded, func(e Event) {})
	bus.SubscribeAll(func(e Event) {})

	if bus.SubscriberCount() != 3 {
		t.Errorf("expected 3, got %d", bus.SubscriberCount())
	}

	bus.Unsubscribe(id1)
	if bus.SubscriberCount() != 2 {
		t.Errorf("expected 2 after unsubscribe, got %d", bus.SubscriberCount())
	}
}
