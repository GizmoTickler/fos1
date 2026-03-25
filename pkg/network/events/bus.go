package events

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Handler is a function that processes events.
type Handler func(Event)

// subscription tracks a single event handler registration.
type subscription struct {
	id        string
	eventType Type
	handler   Handler
}

// Bus is a thread-safe publish/subscribe event bus for network events.
type Bus struct {
	mu            sync.RWMutex
	subscriptions map[Type][]subscription
	allSubs       []subscription // subscribers that receive all events
	closed        bool
}

// NewBus creates a new event bus.
func NewBus() *Bus {
	return &Bus{
		subscriptions: make(map[Type][]subscription),
	}
}

// Subscribe registers a handler for a specific event type and returns
// a subscription ID that can be used to unsubscribe.
func (b *Bus) Subscribe(eventType Type, handler Handler) string {
	b.mu.Lock()
	defer b.mu.Unlock()

	id := uuid.New().String()
	sub := subscription{
		id:        id,
		eventType: eventType,
		handler:   handler,
	}

	b.subscriptions[eventType] = append(b.subscriptions[eventType], sub)
	return id
}

// SubscribeAll registers a handler that receives all events regardless of type.
func (b *Bus) SubscribeAll(handler Handler) string {
	b.mu.Lock()
	defer b.mu.Unlock()

	id := uuid.New().String()
	sub := subscription{
		id:      id,
		handler: handler,
	}

	b.allSubs = append(b.allSubs, sub)
	return id
}

// Unsubscribe removes a subscription by its ID.
func (b *Bus) Unsubscribe(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Search in type-specific subscriptions
	for eventType, subs := range b.subscriptions {
		for i, sub := range subs {
			if sub.id == id {
				b.subscriptions[eventType] = append(subs[:i], subs[i+1:]...)
				return
			}
		}
	}

	// Search in all-event subscriptions
	for i, sub := range b.allSubs {
		if sub.id == id {
			b.allSubs = append(b.allSubs[:i], b.allSubs[i+1:]...)
			return
		}
	}
}

// Publish sends an event to all matching subscribers. Handlers are called
// synchronously in the order they were registered.
func (b *Bus) Publish(event Event) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Collect handlers under read lock
	handlers := make([]Handler, 0)
	if subs, ok := b.subscriptions[event.Type]; ok {
		for _, sub := range subs {
			handlers = append(handlers, sub.handler)
		}
	}
	for _, sub := range b.allSubs {
		handlers = append(handlers, sub.handler)
	}
	b.mu.RUnlock()

	// Call handlers outside lock to avoid deadlocks
	for _, h := range handlers {
		h(event)
	}
}

// PublishAsync sends an event to all matching subscribers asynchronously.
// Each handler is called in its own goroutine.
func (b *Bus) PublishAsync(event Event) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	handlers := make([]Handler, 0)
	if subs, ok := b.subscriptions[event.Type]; ok {
		for _, sub := range subs {
			handlers = append(handlers, sub.handler)
		}
	}
	for _, sub := range b.allSubs {
		handlers = append(handlers, sub.handler)
	}
	b.mu.RUnlock()

	for _, h := range handlers {
		go h(event)
	}
}

// Close prevents further event publishing. Existing subscriptions are kept
// but will not receive any more events.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
}

// SubscriberCount returns the total number of active subscriptions.
func (b *Bus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	count := len(b.allSubs)
	for _, subs := range b.subscriptions {
		count += len(subs)
	}
	return count
}
