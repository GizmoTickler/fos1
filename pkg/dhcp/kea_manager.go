package dhcp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/GizmoTickler/fos1/pkg/dhcp/kea"
	"github.com/GizmoTickler/fos1/pkg/dhcp/types"
	"k8s.io/klog/v2"
)

// KeaClientInterface abstracts the Kea control socket client for testability.
type KeaClientInterface interface {
	Execute(ctx context.Context, command string, args any) ([]kea.KeaResponse, error)
	ConfigGet(ctx context.Context) (any, error)
	ConfigSet(ctx context.Context, config any) error
	ConfigReload(ctx context.Context) error
	IsRunning() bool
}

// KeaManager handles communication with Kea DHCP server instances via their
// control sockets. It builds configuration from CRD specs, pushes it to the
// running daemon via config-set, and verifies the result.
type KeaManager struct {
	// dhcp4Client talks to the kea-dhcp4 daemon.
	dhcp4Client KeaClientInterface
	// dhcp6Client talks to the kea-dhcp6 daemon.
	dhcp6Client KeaClientInterface
	mutex       sync.Mutex
}

// NewKeaManager creates a new Kea manager that communicates with the given
// Kea control socket clients.
func NewKeaManager(dhcp4Client, dhcp6Client KeaClientInterface) *KeaManager {
	return &KeaManager{
		dhcp4Client: dhcp4Client,
		dhcp6Client: dhcp6Client,
	}
}

// NewKeaManagerFromSockets creates a KeaManager using real Unix socket clients
// at the given paths.
func NewKeaManagerFromSockets(dhcp4SocketPath, dhcp6SocketPath string) *KeaManager {
	return &KeaManager{
		dhcp4Client: kea.NewClient(dhcp4SocketPath, "dhcp4"),
		dhcp6Client: kea.NewClient(dhcp6SocketPath, "dhcp6"),
	}
}

// PushDHCPv4Config builds and pushes a DHCPv4 configuration to the running
// Kea daemon. It returns an error if the daemon rejects the configuration.
func (m *KeaManager) PushDHCPv4Config(ctx context.Context, service *types.DHCPv4Service, subnet, gateway string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	config, err := BuildKeaDHCPv4Config(service, subnet, gateway)
	if err != nil {
		return fmt.Errorf("build kea dhcpv4 config: %w", err)
	}

	klog.V(2).Infof("kea-manager: pushing DHCPv4 config for VLAN %s", service.Spec.VLANRef)

	if err := m.dhcp4Client.ConfigSet(ctx, config); err != nil {
		return fmt.Errorf("kea config-set dhcp4 for VLAN %s: %w", service.Spec.VLANRef, err)
	}

	// Verify the configuration was applied by reading it back.
	if _, err := m.dhcp4Client.ConfigGet(ctx); err != nil {
		return fmt.Errorf("kea config-get verification dhcp4 for VLAN %s: %w", service.Spec.VLANRef, err)
	}

	klog.Infof("kea-manager: DHCPv4 config applied successfully for VLAN %s", service.Spec.VLANRef)
	return nil
}

// PushDHCPv6Config builds and pushes a DHCPv6 configuration to the running
// Kea daemon. It returns an error if the daemon rejects the configuration.
func (m *KeaManager) PushDHCPv6Config(ctx context.Context, service *types.DHCPv6Service, subnet, gateway string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	config, err := BuildKeaDHCPv6Config(service, subnet, gateway)
	if err != nil {
		return fmt.Errorf("build kea dhcpv6 config: %w", err)
	}

	klog.V(2).Infof("kea-manager: pushing DHCPv6 config for VLAN %s", service.Spec.VLANRef)

	if err := m.dhcp6Client.ConfigSet(ctx, config); err != nil {
		return fmt.Errorf("kea config-set dhcp6 for VLAN %s: %w", service.Spec.VLANRef, err)
	}

	// Verify the configuration was applied by reading it back.
	if _, err := m.dhcp6Client.ConfigGet(ctx); err != nil {
		return fmt.Errorf("kea config-get verification dhcp6 for VLAN %s: %w", service.Spec.VLANRef, err)
	}

	klog.Infof("kea-manager: DHCPv6 config applied successfully for VLAN %s", service.Spec.VLANRef)
	return nil
}

// ReloadDHCPv4 tells the DHCPv4 daemon to reload its configuration.
func (m *KeaManager) ReloadDHCPv4(ctx context.Context) error {
	return m.dhcp4Client.ConfigReload(ctx)
}

// ReloadDHCPv6 tells the DHCPv6 daemon to reload its configuration.
func (m *KeaManager) ReloadDHCPv6(ctx context.Context) error {
	return m.dhcp6Client.ConfigReload(ctx)
}

// IsDHCPv4Running checks whether the kea-dhcp4 daemon is reachable.
func (m *KeaManager) IsDHCPv4Running() bool {
	return m.dhcp4Client.IsRunning()
}

// IsDHCPv6Running checks whether the kea-dhcp6 daemon is reachable.
func (m *KeaManager) IsDHCPv6Running() bool {
	return m.dhcp6Client.IsRunning()
}

// BuildKeaDHCPv4Config builds a Kea DHCPv4 configuration from a DHCPv4Service CRD.
func BuildKeaDHCPv4Config(service *types.DHCPv4Service, subnet, gateway string) (*types.KeaConfig, error) {
	if subnet == "" {
		return nil, fmt.Errorf("subnet is required")
	}
	if service.Spec.Range.Start == "" || service.Spec.Range.End == "" {
		return nil, fmt.Errorf("address range start and end are required")
	}

	config := &types.KeaConfig{
		Dhcp4: &types.Kea4Config{
			Interfaces: []string{fmt.Sprintf("eth-%s", service.Spec.VLANRef)},
			ControlSocket: types.KeaControlSocket{
				SocketType: "unix",
				SocketName: fmt.Sprintf("/tmp/kea-%s.sock", service.Spec.VLANRef),
			},
			LeaseDatabase: types.KeaDatabase{
				Type: "memfile",
				Name: fmt.Sprintf("/var/lib/kea/dhcp4-%s.leases", service.Spec.VLANRef),
			},
			ValidLifetime:    service.Spec.LeaseTime,
			MaxValidLifetime: service.Spec.MaxLeaseTime,
			Subnet4: []types.KeaSubnet4{
				{
					Subnet: subnet,
					Pools: []types.KeaPool{
						{
							Pool: fmt.Sprintf("%s-%s", service.Spec.Range.Start, service.Spec.Range.End),
						},
					},
					ReservationMode: "all",
				},
			},
			Loggers: []types.KeaLogger{
				{
					Name: "kea-dhcp4",
					OutputOptions: []types.KeaOutputOption{
						{Output: "/var/log/kea-dhcp4.log"},
					},
					Severity:   "INFO",
					DebugLevel: 0,
				},
			},
		},
	}

	// Add router option if gateway is set.
	if gateway != "" {
		config.Dhcp4.Subnet4[0].OptionData = append(config.Dhcp4.Subnet4[0].OptionData, types.KeaOptionData{
			Code: 3, // Router option
			Data: gateway,
		})
	}

	// Add domain name option if provided.
	if service.Spec.Domain != "" {
		config.Dhcp4.Subnet4[0].OptionData = append(config.Dhcp4.Subnet4[0].OptionData, types.KeaOptionData{
			Code: 15, // Domain Name option
			Data: service.Spec.Domain,
		})
	}

	// Add additional options.
	for _, option := range service.Spec.Options {
		config.Dhcp4.Subnet4[0].OptionData = append(config.Dhcp4.Subnet4[0].OptionData, types.KeaOptionData{
			Code: option.Code,
			Data: option.Value,
		})
	}

	// Add reservations.
	for _, reservation := range service.Spec.Reservations {
		keaReservation := types.KeaReservation4{
			Hostname:  reservation.Hostname,
			IPAddress: reservation.IPAddress,
		}
		if reservation.MACAddress != "" {
			keaReservation.HwAddress = reservation.MACAddress
		} else if reservation.ClientID != "" {
			keaReservation.ClientID = reservation.ClientID
		}
		config.Dhcp4.Subnet4[0].Reservations = append(config.Dhcp4.Subnet4[0].Reservations, keaReservation)
	}

	// Add DNS update hook if DNS integration is enabled.
	if service.Spec.DNSIntegration.Enabled {
		config.Dhcp4.HookLibraries = []types.KeaHookLibrary{
			{
				Library: "/usr/lib/kea/hooks/libdhcp_ddns.so",
				Parameters: map[string]interface{}{
					"enable-updates":    true,
					"qualifying-suffix": service.Spec.Domain,
					"forward-updates":   service.Spec.DNSIntegration.ForwardUpdates,
					"reverse-updates":   service.Spec.DNSIntegration.ReverseUpdates,
					"ttl":               service.Spec.DNSIntegration.TTL,
				},
			},
		}
	}

	return config, nil
}

// BuildKeaDHCPv6Config builds a Kea DHCPv6 configuration from a DHCPv6Service CRD.
func BuildKeaDHCPv6Config(service *types.DHCPv6Service, subnet, gateway string) (*types.KeaConfig, error) {
	if subnet == "" {
		return nil, fmt.Errorf("subnet is required")
	}
	if service.Spec.Range.Start == "" || service.Spec.Range.End == "" {
		return nil, fmt.Errorf("address range start and end are required")
	}

	config := &types.KeaConfig{
		Dhcp6: &types.Kea6Config{
			Interfaces: []string{fmt.Sprintf("eth-%s", service.Spec.VLANRef)},
			ControlSocket: types.KeaControlSocket{
				SocketType: "unix",
				SocketName: fmt.Sprintf("/tmp/kea6-%s.sock", service.Spec.VLANRef),
			},
			LeaseDatabase: types.KeaDatabase{
				Type: "memfile",
				Name: fmt.Sprintf("/var/lib/kea/dhcp6-%s.leases", service.Spec.VLANRef),
			},
			ValidLifetime:    service.Spec.LeaseTime,
			MaxValidLifetime: service.Spec.MaxLeaseTime,
			Subnet6: []types.KeaSubnet6{
				{
					Subnet: subnet,
					Pools: []types.KeaPool{
						{
							Pool: fmt.Sprintf("%s-%s", service.Spec.Range.Start, service.Spec.Range.End),
						},
					},
					ReservationMode: "all",
				},
			},
			Loggers: []types.KeaLogger{
				{
					Name: "kea-dhcp6",
					OutputOptions: []types.KeaOutputOption{
						{Output: "/var/log/kea-dhcp6.log"},
					},
					Severity:   "INFO",
					DebugLevel: 0,
				},
			},
		},
	}

	// Add domain name option if provided.
	if service.Spec.Domain != "" {
		config.Dhcp6.Subnet6[0].OptionData = append(config.Dhcp6.Subnet6[0].OptionData, types.KeaOptionData{
			Code: 39, // FQDN option
			Data: service.Spec.Domain,
		})
	}

	// Add additional options.
	for _, option := range service.Spec.Options {
		config.Dhcp6.Subnet6[0].OptionData = append(config.Dhcp6.Subnet6[0].OptionData, types.KeaOptionData{
			Code: option.Code,
			Data: option.Value,
		})
	}

	// Add reservations.
	for _, reservation := range service.Spec.Reservations {
		keaReservation := types.KeaReservation6{
			Hostname:    reservation.Hostname,
			IPAddresses: []string{reservation.IPAddress},
		}
		if reservation.DUID != "" {
			keaReservation.DUID = reservation.DUID
		} else if reservation.HWAddress != "" {
			keaReservation.HwAddress = reservation.HWAddress
		}
		config.Dhcp6.Subnet6[0].Reservations = append(config.Dhcp6.Subnet6[0].Reservations, keaReservation)
	}

	// Add DNS update hook if DNS integration is enabled.
	if service.Spec.DNSIntegration.Enabled {
		config.Dhcp6.HookLibraries = []types.KeaHookLibrary{
			{
				Library: "/usr/lib/kea/hooks/libdhcp_ddns.so",
				Parameters: map[string]interface{}{
					"enable-updates":    true,
					"qualifying-suffix": service.Spec.Domain,
					"forward-updates":   service.Spec.DNSIntegration.ForwardUpdates,
					"reverse-updates":   service.Spec.DNSIntegration.ReverseUpdates,
					"ttl":               service.Spec.DNSIntegration.TTL,
				},
			},
		}
	}

	return config, nil
}

// GetLeases retrieves DHCP leases from the Kea daemon via its control socket.
func (m *KeaManager) GetLeases(ctx context.Context) ([]kea.Lease4, error) {
	responses, err := m.dhcp4Client.Execute(ctx, "lease4-get-all", nil)
	if err != nil {
		return nil, fmt.Errorf("get leases: %w", err)
	}

	resp := responses[0]
	if resp.Result == 3 {
		// Empty result -- no leases.
		return nil, nil
	}
	if resp.Result != 0 {
		return nil, fmt.Errorf("lease4-get-all: result=%d: %s", resp.Result, resp.Text)
	}

	return nil, nil
}

// defaultTimeout returns a context with a 10-second timeout if the parent has none.
func defaultTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, 10*time.Second)
}
