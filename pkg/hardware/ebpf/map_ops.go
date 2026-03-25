//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	ciliumebpf "github.com/cilium/ebpf"
	"k8s.io/klog/v2"
)

// TypedMapOps provides typed operations on eBPF maps, ensuring Go structs
// match their BPF C counterparts for safe kernel interaction.
type TypedMapOps struct {
	maps map[string]*ciliumebpf.Map
	mu   sync.RWMutex
}

// NewTypedMapOps creates a new TypedMapOps from a map of loaded eBPF maps.
func NewTypedMapOps(maps map[string]*ciliumebpf.Map) *TypedMapOps {
	return &TypedMapOps{maps: maps}
}

// RegisterMap adds a map to the typed operations.
func (t *TypedMapOps) RegisterMap(name string, m *ciliumebpf.Map) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.maps[name] = m
}

// getMap retrieves a map by name.
func (t *TypedMapOps) getMap(name string) (*ciliumebpf.Map, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	m, ok := t.maps[name]
	if !ok {
		return nil, fmt.Errorf("map %s not found", name)
	}
	return m, nil
}

// --- XDP Config Operations ---

// UpdateXDPConfig writes the XDP program configuration.
func (t *TypedMapOps) UpdateXDPConfig(cfg XDPConfig) error {
	m, err := t.getMap("config_map")
	if err != nil {
		return err
	}
	var key uint32 = 0
	if err := m.Update(&key, &cfg, ciliumebpf.UpdateAny); err != nil {
		return fmt.Errorf("update XDP config: %w", err)
	}
	klog.V(4).Info("Updated XDP config map")
	return nil
}

// GetXDPConfig reads the current XDP program configuration.
func (t *TypedMapOps) GetXDPConfig() (*XDPConfig, error) {
	m, err := t.getMap("config_map")
	if err != nil {
		return nil, err
	}
	var key uint32 = 0
	var cfg XDPConfig
	if err := m.Lookup(&key, &cfg); err != nil {
		return nil, fmt.Errorf("lookup XDP config: %w", err)
	}
	return &cfg, nil
}

// --- IPv4 Blacklist Operations ---

// AddIPv4Blacklist adds an IPv4 address or CIDR to the blacklist.
func (t *TypedMapOps) AddIPv4Blacklist(cidr string) error {
	m, err := t.getMap("ipv4_blacklist")
	if err != nil {
		return err
	}
	key, err := NewIPv4BlacklistKey(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	var val uint32 = 1 // 1 = blocked
	if err := m.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
		return fmt.Errorf("add to blacklist %s: %w", cidr, err)
	}
	klog.V(4).Infof("Added %s to IPv4 blacklist", cidr)
	return nil
}

// RemoveIPv4Blacklist removes an IPv4 address or CIDR from the blacklist.
func (t *TypedMapOps) RemoveIPv4Blacklist(cidr string) error {
	m, err := t.getMap("ipv4_blacklist")
	if err != nil {
		return err
	}
	key, err := NewIPv4BlacklistKey(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	if err := m.Delete(&key); err != nil {
		return fmt.Errorf("remove from blacklist %s: %w", cidr, err)
	}
	klog.V(4).Infof("Removed %s from IPv4 blacklist", cidr)
	return nil
}

// AddIPv4BlacklistIP adds a single IP to the blacklist.
func (t *TypedMapOps) AddIPv4BlacklistIP(ip net.IP) error {
	m, err := t.getMap("ipv4_blacklist")
	if err != nil {
		return err
	}
	key := NewIPv4BlacklistKeyFromIP(ip)
	var val uint32 = 1
	if err := m.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
		return fmt.Errorf("add IP to blacklist: %w", err)
	}
	return nil
}

// --- IPv4 Rate Limit Operations ---

// GetRateLimitStats reads all rate limit entries.
// Map: "ipv4_rate_limit", key: uint32 (IP), value: uint64 (packet count)
func (t *TypedMapOps) GetRateLimitStats() (map[string]uint64, error) {
	m, err := t.getMap("ipv4_rate_limit")
	if err != nil {
		return nil, err
	}

	result := make(map[string]uint64)
	var key uint32
	var val uint64

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key)
		result[ip.String()] = val
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate rate limit map: %w", err)
	}

	return result, nil
}

// --- Flow State Operations ---

// GetFlowCount returns the number of tracked IPv4 flows.
func (t *TypedMapOps) GetFlowCount() (int, error) {
	m, err := t.getMap("ipv4_state_map")
	if err != nil {
		return 0, err
	}

	var key FlowKey4
	var val uint8
	count := 0

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		count++
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("iterate flow state map: %w", err)
	}

	return count, nil
}

// GetIPv6FlowCount returns the number of tracked IPv6 flows.
func (t *TypedMapOps) GetIPv6FlowCount() (int, error) {
	m, err := t.getMap("ipv6_state_map")
	if err != nil {
		return 0, err
	}

	var key FlowKey6
	var val uint8
	count := 0

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		count++
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("iterate ipv6 flow state map: %w", err)
	}

	return count, nil
}

// --- Batch Operations ---

// BatchAddIPv4Blacklist adds multiple CIDRs to the blacklist.
func (t *TypedMapOps) BatchAddIPv4Blacklist(cidrs []string) error {
	m, err := t.getMap("ipv4_blacklist")
	if err != nil {
		return err
	}

	var errs []error
	for _, cidr := range cidrs {
		key, err := NewIPv4BlacklistKey(cidr)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse %s: %w", cidr, err))
			continue
		}
		var val uint32 = 1
		if err := m.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
			errs = append(errs, fmt.Errorf("add %s: %w", cidr, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("batch add had %d errors, first: %w", len(errs), errs[0])
	}

	klog.V(4).Infof("Batch added %d entries to IPv4 blacklist", len(cidrs))
	return nil
}

// --- Cilium Integration Operations ---

// SetCiliumIdentity sets the Cilium identity for an IPv4 address.
func (t *TypedMapOps) SetCiliumIdentity(ip net.IP, identity CiliumIdentity) error {
	m, err := t.getMap("cilium_ipcache")
	if err != nil {
		return err
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("not an IPv4 address: %s", ip)
	}
	key := binary.BigEndian.Uint32(ipv4)
	if err := m.Update(&key, &identity, ciliumebpf.UpdateAny); err != nil {
		return fmt.Errorf("set cilium identity for %s: %w", ip, err)
	}
	return nil
}

// GetCiliumIdentity gets the Cilium identity for an IPv4 address.
func (t *TypedMapOps) GetCiliumIdentity(ip net.IP) (*CiliumIdentity, error) {
	m, err := t.getMap("cilium_ipcache")
	if err != nil {
		return nil, err
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("not an IPv4 address: %s", ip)
	}
	key := binary.BigEndian.Uint32(ipv4)
	var identity CiliumIdentity
	if err := m.Lookup(&key, &identity); err != nil {
		return nil, fmt.Errorf("lookup cilium identity for %s: %w", ip, err)
	}
	return &identity, nil
}

// --- Map Statistics ---

// MapStats holds basic statistics about an eBPF map.
type MapStats struct {
	Name       string
	EntryCount int
	MaxEntries uint32
	KeySize    uint32
	ValueSize  uint32
}

// GetMapStats returns statistics for a named map.
func (t *TypedMapOps) GetMapStats(name string) (*MapStats, error) {
	m, err := t.getMap(name)
	if err != nil {
		return nil, err
	}

	info, err := m.Info()
	if err != nil {
		return nil, fmt.Errorf("get map info for %s: %w", name, err)
	}

	return &MapStats{
		Name:       name,
		MaxEntries: info.MaxEntries,
		KeySize:    info.KeySize,
		ValueSize:  info.ValueSize,
	}, nil
}

// ListMaps returns the names of all registered maps.
func (t *TypedMapOps) ListMaps() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	names := make([]string, 0, len(t.maps))
	for name := range t.maps {
		names = append(names, name)
	}
	return names
}
