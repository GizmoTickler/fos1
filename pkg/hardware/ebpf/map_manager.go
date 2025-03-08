// Package ebpf provides functionality for managing eBPF programs and maps.
package ebpf

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

// MapType represents the type of eBPF map.
type MapType string

const (
	// MapTypeHash represents a hash table map.
	MapTypeHash MapType = "hash"
	// MapTypeArray represents an array map.
	MapTypeArray MapType = "array"
	// MapTypeLRUHash represents an LRU hash table map.
	MapTypeLRUHash MapType = "lru_hash"
	// MapTypeLPMTrie represents an LPM trie map.
	MapTypeLPMTrie MapType = "lpm_trie"
	// MapTypeRingBuffer represents a ring buffer map.
	MapTypeRingBuffer MapType = "ringbuf"
	// MapTypePerCPUHash represents a per-CPU hash table map.
	MapTypePerCPUHash MapType = "percpu_hash"
	// MapTypePerCPUArray represents a per-CPU array map.
	MapTypePerCPUArray MapType = "percpu_array"
	// MapTypeStackTrace represents a stack trace map.
	MapTypeStackTrace MapType = "stacktrace"
	// MapTypeCGroupArray represents a cgroup array map.
	MapTypeCGroupArray MapType = "cgroup_array"
	// MapTypeDevMap represents a device map.
	MapTypeDevMap MapType = "devmap"
)

// Map represents an eBPF map.
type Map struct {
	Name      string
	Type      MapType
	InnerMap  *ebpf.Map
	KeySize   int
	ValueSize int
	MaxEntries int
}

// MapManager handles the lifecycle of eBPF maps.
type MapManager struct {
	maps     map[string]*Map
	mapsMu   sync.RWMutex
}

// NewMapManager creates a new MapManager.
func NewMapManager() *MapManager {
	return &MapManager{
		maps: make(map[string]*Map),
	}
}

// CreateMap creates a new eBPF map.
func (m *MapManager) CreateMap(name string, mapType MapType, keySize, valueSize, maxEntries int) (*Map, error) {
	m.mapsMu.Lock()
	defer m.mapsMu.Unlock()

	// Check if map already exists
	if _, ok := m.maps[name]; ok {
		return nil, fmt.Errorf("map %s already exists", name)
	}

	// Convert MapType to ebpf.MapType
	var ebpfMapType ebpf.MapType
	switch mapType {
	case MapTypeHash:
		ebpfMapType = ebpf.Hash
	case MapTypeArray:
		ebpfMapType = ebpf.Array
	case MapTypeLRUHash:
		ebpfMapType = ebpf.LRUHash
	case MapTypeLPMTrie:
		ebpfMapType = ebpf.LPMTrie
	case MapTypeRingBuffer:
		ebpfMapType = ebpf.RingBuf
	case MapTypePerCPUHash:
		ebpfMapType = ebpf.PerCPUHash
	case MapTypePerCPUArray:
		ebpfMapType = ebpf.PerCPUArray
	case MapTypeStackTrace:
		ebpfMapType = ebpf.StackTrace
	case MapTypeCGroupArray:
		ebpfMapType = ebpf.CGroupArray
	case MapTypeDevMap:
		ebpfMapType = ebpf.DevMap
	default:
		return nil, fmt.Errorf("unsupported map type: %s", mapType)
	}

	// Create a new ebpf map specification
	mapSpec := &ebpf.MapSpec{
		Type:       ebpfMapType,
		KeySize:    uint32(keySize),
		ValueSize:  uint32(valueSize),
		MaxEntries: uint32(maxEntries),
		Name:       name,
	}

	// Create the map
	innerMap, err := ebpf.NewMap(mapSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF map: %w", err)
	}

	// Create the map wrapper
	newMap := &Map{
		Name:       name,
		Type:       mapType,
		InnerMap:   innerMap,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
	}

	// Store the map
	m.maps[name] = newMap

	return newMap, nil
}

// DeleteMap removes an eBPF map.
func (m *MapManager) DeleteMap(name string) error {
	m.mapsMu.Lock()
	defer m.mapsMu.Unlock()

	// Check if map exists
	mapObj, ok := m.maps[name]
	if !ok {
		return fmt.Errorf("map %s not found", name)
	}

	// Close the map
	if mapObj.InnerMap != nil {
		if err := mapObj.InnerMap.Close(); err != nil {
			return fmt.Errorf("failed to close eBPF map: %w", err)
		}
	}

	// Remove the map
	delete(m.maps, name)

	return nil
}

// GetMap retrieves an eBPF map.
func (m *MapManager) GetMap(name string) (*Map, error) {
	m.mapsMu.RLock()
	defer m.mapsMu.RUnlock()

	// Check if map exists
	mapObj, ok := m.maps[name]
	if !ok {
		return nil, fmt.Errorf("map %s not found", name)
	}

	return mapObj, nil
}

// ListMaps lists all eBPF maps.
func (m *MapManager) ListMaps() ([]*Map, error) {
	m.mapsMu.RLock()
	defer m.mapsMu.RUnlock()

	maps := make([]*Map, 0, len(m.maps))
	for _, mapObj := range m.maps {
		maps = append(maps, mapObj)
	}

	return maps, nil
}

// UpdateMap updates entries in an eBPF map.
func (m *MapManager) UpdateMap(name string, entries map[interface{}]interface{}) error {
	m.mapsMu.RLock()
	defer m.mapsMu.RUnlock()

	// Check if map exists
	mapObj, ok := m.maps[name]
	if !ok {
		return fmt.Errorf("map %s not found", name)
	}

	// Update the map
	for key, value := range entries {
		if err := mapObj.InnerMap.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to update eBPF map: %w", err)
		}
	}

	return nil
}

// DumpMap dumps the contents of an eBPF map.
func (m *MapManager) DumpMap(name string) (map[interface{}]interface{}, error) {
	m.mapsMu.RLock()
	defer m.mapsMu.RUnlock()

	// Check if map exists
	mapObj, ok := m.maps[name]
	if !ok {
		return nil, fmt.Errorf("map %s not found", name)
	}

	// Dump the map
	entries := make(map[interface{}]interface{})
	var key, value interface{}
	mapIterator := mapObj.InnerMap.Iterate()
	
	for mapIterator.Next(&key, &value) {
		entries[key] = value
	}
	
	if err := mapIterator.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over map: %w", err)
	}

	return entries, nil
}

// GetMapValue gets a value from an eBPF map.
func (m *MapManager) GetMapValue(name string, key interface{}) (interface{}, error) {
	m.mapsMu.RLock()
	defer m.mapsMu.RUnlock()

	// Check if map exists
	mapObj, ok := m.maps[name]
	if !ok {
		return nil, fmt.Errorf("map %s not found", name)
	}

	// Get the value
	var value interface{}
	if err := mapObj.InnerMap.Lookup(key, &value); err != nil {
		return nil, fmt.Errorf("failed to lookup key in eBPF map: %w", err)
	}

	return value, nil
}

// DeleteMapValue deletes a value from an eBPF map.
func (m *MapManager) DeleteMapValue(name string, key interface{}) error {
	m.mapsMu.RLock()
	defer m.mapsMu.RUnlock()

	// Check if map exists
	mapObj, ok := m.maps[name]
	if !ok {
		return fmt.Errorf("map %s not found", name)
	}

	// Delete the value
	if err := mapObj.InnerMap.Delete(key); err != nil {
		return fmt.Errorf("failed to delete key from eBPF map: %w", err)
	}

	return nil
}

// PinMap pins an eBPF map to the filesystem.
func (m *MapManager) PinMap(name string, path string) error {
	m.mapsMu.RLock()
	defer m.mapsMu.RUnlock()

	// Check if map exists
	mapObj, ok := m.maps[name]
	if !ok {
		return fmt.Errorf("map %s not found", name)
	}

	// Pin the map
	if err := mapObj.InnerMap.Pin(path); err != nil {
		return fmt.Errorf("failed to pin eBPF map: %w", err)
	}

	return nil
}

// UnpinMap unpins an eBPF map from the filesystem.
func (m *MapManager) UnpinMap(name string) error {
	m.mapsMu.RLock()
	defer m.mapsMu.RUnlock()

	// Check if map exists
	mapObj, ok := m.maps[name]
	if !ok {
		return fmt.Errorf("map %s not found", name)
	}

	// Unpin the map
	if err := mapObj.InnerMap.Unpin(); err != nil {
		return fmt.Errorf("failed to unpin eBPF map: %w", err)
	}

	return nil
}
