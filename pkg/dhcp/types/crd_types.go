package types

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DHCPv4Service defines the specification for a DHCPv4 service
type DHCPv4Service struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DHCPv4ServiceSpec   `json:"spec"`
	Status DHCPv4ServiceStatus `json:"status,omitempty"`
}

// DHCPv4ServiceSpec contains the specification for a DHCPv4 service
type DHCPv4ServiceSpec struct {
	// VLANRef is a reference to a VLAN CRD
	VLANRef string `json:"vlanRef"`

	// LeaseTime is the default lease time in seconds
	LeaseTime int `json:"leaseTime"`

	// MaxLeaseTime is the maximum lease time in seconds
	MaxLeaseTime int `json:"maxLeaseTime"`

	// Range is the range of addresses to allocate dynamically
	Range AddressRange `json:"range"`

	// Domain is the domain name to provide to clients
	Domain string `json:"domain"`

	// Options are additional DHCP options to provide
	Options []DHCPOption `json:"options,omitempty"`

	// Reservations are static IP reservations for specific devices
	Reservations []DHCPv4Reservation `json:"reservations,omitempty"`

	// DNSIntegration contains configuration for DNS integration
	DNSIntegration DNSIntegration `json:"dnsIntegration,omitempty"`
}

// DHCPv4ServiceStatus contains the status for a DHCPv4 service
type DHCPv4ServiceStatus struct {
	// Active indicates whether the DHCP service is active
	Active bool `json:"active"`

	// LeaseCount is the number of active leases
	LeaseCount int `json:"leaseCount"`

	// LastConfigured is the timestamp when the service was last configured
	LastConfigured metav1.Time `json:"lastConfigured,omitempty"`

	// Conditions represents the latest available observations of the DHCP service's state
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// DHCPv6Service defines the specification for a DHCPv6 service
type DHCPv6Service struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DHCPv6ServiceSpec   `json:"spec"`
	Status DHCPv6ServiceStatus `json:"status,omitempty"`
}

// DHCPv6ServiceSpec contains the specification for a DHCPv6 service
type DHCPv6ServiceSpec struct {
	// VLANRef is a reference to a VLAN CRD
	VLANRef string `json:"vlanRef"`

	// LeaseTime is the default lease time in seconds
	LeaseTime int `json:"leaseTime"`

	// MaxLeaseTime is the maximum lease time in seconds
	MaxLeaseTime int `json:"maxLeaseTime"`

	// Range is the range of addresses to allocate dynamically
	Range AddressRange `json:"range"`

	// Domain is the domain name to provide to clients
	Domain string `json:"domain"`

	// Options are additional DHCP options to provide
	Options []DHCPOption `json:"options,omitempty"`

	// Reservations are static IP reservations for specific devices
	Reservations []DHCPv6Reservation `json:"reservations,omitempty"`

	// DNSIntegration contains configuration for DNS integration
	DNSIntegration DNSIntegration `json:"dnsIntegration,omitempty"`
}

// DHCPv6ServiceStatus contains the status for a DHCPv6 service
type DHCPv6ServiceStatus struct {
	// Active indicates whether the DHCP service is active
	Active bool `json:"active"`

	// LeaseCount is the number of active leases
	LeaseCount int `json:"leaseCount"`

	// LastConfigured is the timestamp when the service was last configured
	LastConfigured metav1.Time `json:"lastConfigured,omitempty"`

	// Conditions represents the latest available observations of the DHCP service's state
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AddressRange defines a range of IP addresses
type AddressRange struct {
	// Start is the starting IP address
	Start string `json:"start"`

	// End is the ending IP address
	End string `json:"end"`
}

// DHCPOption defines a DHCP option to provide to clients
type DHCPOption struct {
	// Code is the DHCP option code
	Code int `json:"code"`

	// Value is the option value
	Value string `json:"value"`
}

// DHCPv4Reservation defines a static reservation for DHCPv4
type DHCPv4Reservation struct {
	// Hostname is the hostname for the reservation
	Hostname string `json:"hostname"`

	// MACAddress is the MAC address for the reservation (optional)
	MACAddress string `json:"macAddress,omitempty"`

	// ClientID is the client identifier for the reservation (optional)
	ClientID string `json:"clientId,omitempty"`

	// IPAddress is the reserved IP address
	IPAddress string `json:"ipAddress"`
}

// DHCPv6Reservation defines a static reservation for DHCPv6
type DHCPv6Reservation struct {
	// Hostname is the hostname for the reservation
	Hostname string `json:"hostname"`

	// DUID is the DHCP Unique Identifier for the reservation (optional)
	DUID string `json:"duid,omitempty"`

	// HWAddress is the hardware address for the reservation (optional)
	HWAddress string `json:"hwAddress,omitempty"`

	// IPAddress is the reserved IP address
	IPAddress string `json:"ipAddress"`
}

// DNSIntegration defines DNS integration settings
type DNSIntegration struct {
	// Enabled indicates whether DNS integration is enabled
	Enabled bool `json:"enabled"`

	// ForwardUpdates indicates whether forward DNS updates should be performed
	ForwardUpdates bool `json:"forwardUpdates"`

	// ReverseUpdates indicates whether reverse DNS updates should be performed
	ReverseUpdates bool `json:"reverseUpdates"`

	// TTL is the time-to-live for DNS records in seconds
	TTL int `json:"ttl"`
}

// Lease represents a DHCP lease
type Lease struct {
	// IP is the leased IP address
	IP string `json:"ip"`

	// Hostname is the client hostname (if provided)
	Hostname string `json:"hostname"`

	// MAC is the client MAC address (for IPv4)
	MAC string `json:"mac,omitempty"`

	// DUID is the client DUID (for IPv6)
	DUID string `json:"duid,omitempty"`

	// VLANRef is a reference to the VLAN
	VLANRef string `json:"vlanRef"`

	// ExpiresAt is the lease expiration time
	ExpiresAt time.Time `json:"expiresAt"`

	// IsReservation indicates whether this is a static reservation
	IsReservation bool `json:"isReservation"`
}
