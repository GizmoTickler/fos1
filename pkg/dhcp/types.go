// Package dhcp provides DHCP functionality for the system
// This file contains type aliases for backward compatibility with the new types package
package dhcp

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	
	"github.com/GizmoTickler/fos1/pkg/dhcp/types"
)

// DHCPv4Service defines the specification for a DHCPv4 service
// It's an alias to the same type in the types package for backward compatibility
type DHCPv4Service = types.DHCPv4Service

// DHCPv4ServiceSpec contains the specification for a DHCPv4 service
// It's an alias to the same type in the types package for backward compatibility
type DHCPv4ServiceSpec = types.DHCPv4ServiceSpec

// DHCPv4ServiceStatus contains the status for a DHCPv4 service
// It's an alias to the same type in the types package for backward compatibility
type DHCPv4ServiceStatus = types.DHCPv4ServiceStatus

// DHCPv6Service defines the specification for a DHCPv6 service
// It's an alias to the same type in the types package for backward compatibility
type DHCPv6Service = types.DHCPv6Service

// DHCPv6ServiceSpec contains the specification for a DHCPv6 service
// It's an alias to the same type in the types package for backward compatibility
type DHCPv6ServiceSpec = types.DHCPv6ServiceSpec

// DHCPv6ServiceStatus contains the status for a DHCPv6 service
// It's an alias to the same type in the types package for backward compatibility
type DHCPv6ServiceStatus = types.DHCPv6ServiceStatus

// AddressRange defines a range of IP addresses
// It's an alias to the same type in the types package for backward compatibility
type AddressRange = types.AddressRange

// DHCPOption defines a DHCP option to provide to clients
// It's an alias to the same type in the types package for backward compatibility
type DHCPOption = types.DHCPOption

// DHCPv4Reservation defines a static reservation for DHCPv4
// It's an alias to the same type in the types package for backward compatibility
type DHCPv4Reservation = types.DHCPv4Reservation

// DHCPv6Reservation defines a static reservation for DHCPv6
// It's an alias to the same type in the types package for backward compatibility
type DHCPv6Reservation = types.DHCPv6Reservation

// DNSIntegration defines DNS integration settings
// It's an alias to the same type in the types package for backward compatibility
type DNSIntegration = types.DNSIntegration

// Lease represents a DHCP lease
// It's an alias to the same type in the types package for backward compatibility
type Lease = types.Lease

// KeaConfig represents the configuration for a Kea DHCP server
// It's an alias to the same type in the types package for backward compatibility
type KeaConfig = types.KeaConfig

// Kea4Config contains the DHCPv4 configuration for Kea
// It's an alias to the same type in the types package for backward compatibility
type Kea4Config = types.Kea4Config

// Kea6Config contains the DHCPv6 configuration for Kea
// It's an alias to the same type in the types package for backward compatibility
type Kea6Config = types.Kea6Config

// KeaControlSocket defines the control socket configuration for Kea
// It's an alias to the same type in the types package for backward compatibility
type KeaControlSocket = types.KeaControlSocket

// KeaDatabase defines the database configuration for Kea
// It's an alias to the same type in the types package for backward compatibility
type KeaDatabase = types.KeaDatabase

// KeaSubnet4 defines an IPv4 subnet for Kea
// It's an alias to the same type in the types package for backward compatibility
type KeaSubnet4 = types.KeaSubnet4

// KeaSubnet6 defines an IPv6 subnet for Kea
// It's an alias to the same type in the types package for backward compatibility
type KeaSubnet6 = types.KeaSubnet6

// KeaPool defines an address pool
// It's an alias to the same type in the types package for backward compatibility
type KeaPool = types.KeaPool

// KeaReservation4 defines a DHCPv4 reservation
// It's an alias to the same type in the types package for backward compatibility
type KeaReservation4 = types.KeaReservation4

// KeaReservation6 defines a DHCPv6 reservation
// It's an alias to the same type in the types package for backward compatibility
type KeaReservation6 = types.KeaReservation6

// KeaOptionData defines a DHCP option
// It's an alias to the same type in the types package for backward compatibility
type KeaOptionData = types.KeaOptionData

// KeaLogger defines a logger configuration
// It's an alias to the same type in the types package for backward compatibility
type KeaLogger = types.KeaLogger

// KeaOutputOption defines a logger output option
// It's an alias to the same type in the types package for backward compatibility
type KeaOutputOption = types.KeaOutputOption

// KeaHookLibrary defines a hook library
// It's an alias to the same type in the types package for backward compatibility
type KeaHookLibrary = types.KeaHookLibrary
