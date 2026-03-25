// Package events provides a typed event bus for cross-component notifications
// in the network stack.
package events

import (
	"net"
	"time"
)

// Type represents the type of a network event.
type Type string

const (
	// Interface events
	InterfaceCreated Type = "interface.created"
	InterfaceDeleted Type = "interface.deleted"
	InterfaceUp      Type = "interface.up"
	InterfaceDown    Type = "interface.down"
	InterfaceMTU     Type = "interface.mtu_changed"
	InterfaceAddr    Type = "interface.address_changed"

	// VLAN events
	VLANCreated Type = "vlan.created"
	VLANDeleted Type = "vlan.deleted"
	VLANQoS     Type = "vlan.qos_changed"

	// Route events
	RouteAdded   Type = "route.added"
	RouteRemoved Type = "route.removed"
	RouteChanged Type = "route.changed"

	// Address/IPAM events
	AddressAssigned Type = "address.assigned"
	AddressReleased Type = "address.released"
	AddressConflict Type = "address.conflict"

	// Protocol events
	ProtocolUp   Type = "protocol.up"
	ProtocolDown Type = "protocol.down"
	NeighborUp   Type = "neighbor.up"
	NeighborDown Type = "neighbor.down"

	// Firewall events
	FirewallRuleAdded   Type = "firewall.rule_added"
	FirewallRuleRemoved Type = "firewall.rule_removed"
	FirewallCommit      Type = "firewall.commit"

	// NAT events
	NATRuleAdded   Type = "nat.rule_added"
	NATRuleRemoved Type = "nat.rule_removed"
)

// Event represents a network event with typed data.
type Event struct {
	Type      Type
	Timestamp time.Time
	Source    string // component that generated the event
	Data     any
}

// InterfaceEventData contains data for interface-related events.
type InterfaceEventData struct {
	Name      string
	Index     int
	Type      string // "physical", "vlan", "bridge", "bond"
	MTU       int
	State     string // "up", "down"
	HWAddr    net.HardwareAddr
	Addresses []string
}

// VLANEventData contains data for VLAN-related events.
type VLANEventData struct {
	Name     string
	Parent   string
	VLANID   int
	MTU      int
	QoSClass string
}

// RouteEventData contains data for route-related events.
type RouteEventData struct {
	Destination string
	Gateway     string
	Interface   string
	Metric      int
	Table       int
	Protocol    string
}

// AddressEventData contains data for address-related events.
type AddressEventData struct {
	Interface string
	Address   string
	Family    string // "ipv4", "ipv6"
	Action    string // "add", "delete"
}

// ProtocolEventData contains data for protocol-related events.
type ProtocolEventData struct {
	Protocol string // "bgp", "ospf"
	State    string
	Neighbor string
	VRF      string
}
