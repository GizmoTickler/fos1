package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DHCPv4Service represents a DHCPv4 service configuration
type DHCPv4Service struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DHCPv4ServiceSpec   `json:"spec"`
	Status DHCPv4ServiceStatus `json:"status,omitempty"`
}

// DHCPv4ServiceSpec defines the desired state of DHCPv4Service
type DHCPv4ServiceSpec struct {
	// VLANRef is a reference to a VLAN CRD
	VLANRef string `json:"vlanRef"`

	// LeaseTime is the default lease time in seconds
	LeaseTime int `json:"leaseTime"`

	// Range is the range of addresses to allocate dynamically
	Range AddressRange `json:"range"`

	// Domain is the domain name to provide to clients
	Domain string `json:"domain,omitempty"`
}

// DHCPv4ServiceStatus defines the observed state of DHCPv4Service
type DHCPv4ServiceStatus struct {
	// Active indicates whether the DHCP service is active
	Active bool `json:"active"`

	// LastUpdated is the timestamp of the last update
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`

	// Phase represents the current lifecycle phase: Ready, Degraded, or Error
	Phase string `json:"phase,omitempty"`

	// Message is a human-readable description of the current status
	Message string `json:"message,omitempty"`

	// Conditions represents the latest available observations of the service state
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// DeepCopyObject implements runtime.Object
func (in *DHCPv4Service) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(DHCPv4Service)
	*out = *in
	return out
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DHCPv4ServiceList contains a list of DHCPv4Service
type DHCPv4ServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DHCPv4Service `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DHCPv6Service represents a DHCPv6 service configuration
type DHCPv6Service struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DHCPv6ServiceSpec   `json:"spec"`
	Status DHCPv6ServiceStatus `json:"status,omitempty"`
}

// DHCPv6ServiceSpec defines the desired state of DHCPv6Service
type DHCPv6ServiceSpec struct {
	// VLANRef is a reference to a VLAN CRD
	VLANRef string `json:"vlanRef"`

	// LeaseTime is the default lease time in seconds
	LeaseTime int `json:"leaseTime"`

	// Range is the range of addresses to allocate dynamically
	Range AddressRange `json:"range"`

	// Domain is the domain name to provide to clients
	Domain string `json:"domain,omitempty"`
}

// DHCPv6ServiceStatus defines the observed state of DHCPv6Service
type DHCPv6ServiceStatus struct {
	// Active indicates whether the DHCP service is active
	Active bool `json:"active"`

	// LastUpdated is the timestamp of the last update
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`

	// Phase represents the current lifecycle phase: Ready, Degraded, or Error
	Phase string `json:"phase,omitempty"`

	// Message is a human-readable description of the current status
	Message string `json:"message,omitempty"`

	// Conditions represents the latest available observations of the service state
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// DeepCopyObject implements runtime.Object
func (in *DHCPv6Service) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(DHCPv6Service)
	*out = *in
	return out
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DHCPv6ServiceList contains a list of DHCPv6Service
type DHCPv6ServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DHCPv6Service `json:"items"`
}

// AddressRange defines a range of IP addresses
type AddressRange struct {
	// Start is the starting IP address
	Start string `json:"start"`

	// End is the ending IP address
	End string `json:"end"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VLAN represents a VLAN configuration
type VLAN struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VLANSpec   `json:"spec"`
	Status VLANStatus `json:"status,omitempty"`
}

// VLANSpec defines the desired state of VLAN
type VLANSpec struct {
	// ID is the VLAN ID
	ID int `json:"id"`

	// Subnet is the IPv4 subnet for this VLAN
	Subnet string `json:"subnet"`

	// Subnet6 is the IPv6 subnet for this VLAN
	Subnet6 string `json:"subnet6,omitempty"`

	// Gateway is the IPv4 gateway address
	Gateway string `json:"gateway,omitempty"`

	// Gateway6 is the IPv6 gateway address
	Gateway6 string `json:"gateway6,omitempty"`
}

// VLANStatus defines the observed state of VLAN
type VLANStatus struct {
	// Active indicates whether the VLAN is active
	Active bool `json:"active"`

	// LastUpdated is the timestamp of the last update
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
}

// DeepCopyObject implements runtime.Object
func (in *VLAN) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(VLAN)
	*out = *in
	return out
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VLANList contains a list of VLAN
type VLANList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VLAN `json:"items"`
}
