// Package ipset provides efficient IP list management using nftables named sets.
package ipset

import "time"

// SetType defines the type of elements in a set.
type SetType string

const (
	SetTypeIPv4Addr SetType = "ipv4_addr"
	SetTypeIPv6Addr SetType = "ipv6_addr"
	SetTypePort     SetType = "inet_service"
	SetTypeMixed    SetType = "ipv4_addr . inet_service" // concatenated type
)

// Config defines configuration for creating a new IP set.
type Config struct {
	// Name is the unique name of the set.
	Name string

	// Type defines what kind of elements the set contains.
	Type SetType

	// Timeout is the default auto-expiry for elements. Zero means no timeout.
	Timeout time.Duration

	// MaxElements is the maximum number of elements. Zero means unlimited.
	MaxElements uint32

	// Interval enables CIDR matching for address sets.
	Interval bool

	// Counter enables per-element match counting.
	Counter bool

	// Comment enables per-element comments.
	Comment bool

	// Table is the nftables table this set belongs to.
	Table string
}

// Element represents an element in an IP set.
type Element struct {
	// Value is the element value (IP address, CIDR, port number as string).
	Value string

	// Timeout overrides the set's default timeout for this element.
	Timeout time.Duration

	// Comment is an optional comment for this element.
	Comment string
}

// SetInfo contains information about an existing set.
type SetInfo struct {
	Name        string
	Type        SetType
	ElementCount int
	Table       string
	HasTimeout  bool
	HasInterval bool
	HasCounter  bool
}

// Manager manages nftables named sets for IP blocking, allowlisting,
// and threat intelligence feeds.
type Manager interface {
	// Set lifecycle
	CreateSet(config Config) error
	DeleteSet(name string) error
	SetExists(name string) bool

	// Element operations
	AddElements(setName string, elements []Element) error
	RemoveElements(setName string, elements []Element) error
	FlushSet(setName string) error
	ListElements(setName string) ([]Element, error)

	// Bulk operations (atomic replacement for threat feeds)
	ReplaceElements(setName string, elements []Element) error

	// Info
	GetSetInfo(setName string) (*SetInfo, error)
	ListSets() ([]SetInfo, error)
}
