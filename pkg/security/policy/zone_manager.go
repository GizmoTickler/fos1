package policy

import (
	"fmt"
	"sync"

	"github.com/GizmoTickler/fos1/pkg/security/firewall"
)

// ZoneState holds the runtime state for a single firewall zone.
type ZoneState struct {
	// Name is the zone name (e.g., "lan", "wan", "dmz").
	Name string
	// Interfaces is the list of network interfaces assigned to this zone.
	Interfaces []string
	// ChainRef is the nftables chain associated with this zone.
	ChainRef firewall.ChainRef
}

// ZoneManager manages firewall zones, mapping them to nftables chains
// and tracking interface membership.
type ZoneManager struct {
	firewallMgr firewall.FirewallManager
	zones       map[string]*ZoneState
	mu          sync.RWMutex
}

// NewZoneManager creates a new ZoneManager backed by the given FirewallManager.
func NewZoneManager(fwMgr firewall.FirewallManager) *ZoneManager {
	return &ZoneManager{
		firewallMgr: fwMgr,
		zones:       make(map[string]*ZoneState),
	}
}

// CreateZone creates a new firewall zone with the given name and initial interfaces.
// It sets up a dedicated nftables chain for the zone under the default filter table.
func (z *ZoneManager) CreateZone(name string, interfaces []string) error {
	if name == "" {
		return fmt.Errorf("zone name must not be empty")
	}

	z.mu.Lock()
	defer z.mu.Unlock()

	if _, exists := z.zones[name]; exists {
		return fmt.Errorf("zone %q already exists", name)
	}

	chainName := zoneChainName(name)

	// Create a filter chain for this zone.
	if err := z.firewallMgr.EnsureChain(
		defaultFilterTable,
		chainName,
		firewall.ChainTypeFilter,
		firewall.HookForward,
		0,
	); err != nil {
		return fmt.Errorf("creating chain for zone %q: %w", name, err)
	}

	if err := z.firewallMgr.Commit(); err != nil {
		return fmt.Errorf("committing zone %q chain: %w", name, err)
	}

	// Copy the interfaces slice to avoid aliasing.
	ifaces := make([]string, len(interfaces))
	copy(ifaces, interfaces)

	z.zones[name] = &ZoneState{
		Name:       name,
		Interfaces: ifaces,
		ChainRef: firewall.ChainRef{
			Table: defaultFilterTable,
			Chain: chainName,
		},
	}

	return nil
}

// DeleteZone removes a firewall zone and its associated nftables chain.
func (z *ZoneManager) DeleteZone(name string) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	state, ok := z.zones[name]
	if !ok {
		return fmt.Errorf("zone %q does not exist", name)
	}

	if err := z.firewallMgr.DeleteChain(state.ChainRef); err != nil {
		return fmt.Errorf("deleting chain for zone %q: %w", name, err)
	}

	if err := z.firewallMgr.Commit(); err != nil {
		return fmt.Errorf("committing deletion of zone %q: %w", name, err)
	}

	delete(z.zones, name)
	return nil
}

// AddInterfaceToZone adds a network interface to an existing zone.
func (z *ZoneManager) AddInterfaceToZone(zoneName, iface string) error {
	if iface == "" {
		return fmt.Errorf("interface name must not be empty")
	}

	z.mu.Lock()
	defer z.mu.Unlock()

	state, ok := z.zones[zoneName]
	if !ok {
		return fmt.Errorf("zone %q does not exist", zoneName)
	}

	for _, existing := range state.Interfaces {
		if existing == iface {
			return fmt.Errorf("interface %q already in zone %q", iface, zoneName)
		}
	}

	state.Interfaces = append(state.Interfaces, iface)
	return nil
}

// RemoveInterfaceFromZone removes a network interface from a zone.
func (z *ZoneManager) RemoveInterfaceFromZone(zoneName, iface string) error {
	if iface == "" {
		return fmt.Errorf("interface name must not be empty")
	}

	z.mu.Lock()
	defer z.mu.Unlock()

	state, ok := z.zones[zoneName]
	if !ok {
		return fmt.Errorf("zone %q does not exist", zoneName)
	}

	for i, existing := range state.Interfaces {
		if existing == iface {
			state.Interfaces = append(state.Interfaces[:i], state.Interfaces[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("interface %q not found in zone %q", iface, zoneName)
}

// GetZone returns the current state of a zone.
func (z *ZoneManager) GetZone(name string) (*ZoneState, error) {
	z.mu.RLock()
	defer z.mu.RUnlock()

	state, ok := z.zones[name]
	if !ok {
		return nil, fmt.Errorf("zone %q does not exist", name)
	}

	// Return a copy to prevent external mutation.
	cp := &ZoneState{
		Name:     state.Name,
		ChainRef: state.ChainRef,
	}
	cp.Interfaces = make([]string, len(state.Interfaces))
	copy(cp.Interfaces, state.Interfaces)
	return cp, nil
}

// ListZones returns a snapshot of all registered zones.
func (z *ZoneManager) ListZones() []ZoneState {
	z.mu.RLock()
	defer z.mu.RUnlock()

	zones := make([]ZoneState, 0, len(z.zones))
	for _, state := range z.zones {
		cp := ZoneState{
			Name:     state.Name,
			ChainRef: state.ChainRef,
		}
		cp.Interfaces = make([]string, len(state.Interfaces))
		copy(cp.Interfaces, state.Interfaces)
		zones = append(zones, cp)
	}
	return zones
}

// zoneChainName generates the nftables chain name for a zone.
func zoneChainName(zoneName string) string {
	return fmt.Sprintf("zone-%s", zoneName)
}
