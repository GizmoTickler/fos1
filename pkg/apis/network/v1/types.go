package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkInterface represents a network interface configuration
type NetworkInterface struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkInterfaceSpec   `json:"spec"`
	Status NetworkInterfaceStatus `json:"status,omitempty"`
}

// NetworkInterfaceSpec defines the desired state of NetworkInterface
type NetworkInterfaceSpec struct {
	// Name is the name of the interface
	Name string `json:"name"`

	// Type is the type of interface (physical, vlan, bridge, etc.)
	Type string `json:"type"`

	// Parent is the parent interface for VLAN interfaces
	Parent string `json:"parent,omitempty"`

	// VLANID is the VLAN ID for VLAN interfaces
	VLANID int `json:"vlanID,omitempty"`

	// Addresses is a list of IP addresses for the interface
	Addresses []string `json:"addresses,omitempty"`

	// MTU is the MTU for the interface
	MTU int `json:"mtu,omitempty"`

	// State is the desired state of the interface (up or down)
	State string `json:"state,omitempty"`
}

// NetworkInterfaceStatus defines the observed state of NetworkInterface
type NetworkInterfaceStatus struct {
	// OperationalState is the current state of the interface
	OperationalState string `json:"operationalState,omitempty"`

	// Addresses is a list of IP addresses currently assigned to the interface
	Addresses []string `json:"addresses,omitempty"`

	// LastUpdated is the timestamp of the last update
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`

	// Error is the error message if the interface is in an error state
	Error string `json:"error,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkInterfaceList contains a list of NetworkInterface
type NetworkInterfaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkInterface `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DHCPService represents a DHCP service configuration
type DHCPService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DHCPServiceSpec   `json:"spec"`
	Status DHCPServiceStatus `json:"status,omitempty"`
}

// DHCPServiceSpec defines the desired state of DHCPService
type DHCPServiceSpec struct {
	// Interface is the interface to serve DHCP on
	Interface string `json:"interface"`

	// Subnet is the subnet to serve
	Subnet string `json:"subnet"`

	// Range is the IP range to serve
	Range string `json:"range"`

	// Gateway is the gateway to advertise
	Gateway string `json:"gateway,omitempty"`

	// DNSServers is a list of DNS servers to advertise
	DNSServers []string `json:"dnsServers,omitempty"`

	// LeaseTime is the lease time in seconds
	LeaseTime int `json:"leaseTime,omitempty"`
}

// DHCPServiceStatus defines the observed state of DHCPService
type DHCPServiceStatus struct {
	// Active indicates whether the DHCP service is active
	Active bool `json:"active"`

	// LeaseCount is the number of active leases
	LeaseCount int `json:"leaseCount"`

	// LastUpdated is the timestamp of the last update
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DHCPServiceList contains a list of DHCPService
type DHCPServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DHCPService `json:"items"`
}
