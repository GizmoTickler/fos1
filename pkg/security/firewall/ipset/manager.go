package ipset

import (
	"fmt"
	"sync"
)

// DefaultManager implements the Manager interface with in-memory tracking.
// The actual nftables operations are delegated to the kernel layer.
type DefaultManager struct {
	mu       sync.RWMutex
	sets     map[string]*managedSet
	table    string // default nftables table for sets
	kernel   KernelOperations
}

// managedSet tracks a set and its configuration.
type managedSet struct {
	config   Config
	elements map[string]Element // key: Element.Value
}

// KernelOperations defines the kernel-level operations for set management.
// This interface enables testing with mocks.
type KernelOperations interface {
	CreateSet(config Config) error
	DeleteSet(table, name string) error
	AddElements(table, setName string, elements []Element) error
	RemoveElements(table, setName string, elements []Element) error
	FlushSet(table, setName string) error
	Flush() error // atomic commit
}

// NewManager creates a new IPSet manager.
func NewManager(table string, kernel KernelOperations) *DefaultManager {
	return &DefaultManager{
		sets:   make(map[string]*managedSet),
		table:  table,
		kernel: kernel,
	}
}

// CreateSet creates a new named set.
func (m *DefaultManager) CreateSet(config Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sets[config.Name]; exists {
		return fmt.Errorf("set %s already exists", config.Name)
	}

	if config.Table == "" {
		config.Table = m.table
	}

	if err := m.kernel.CreateSet(config); err != nil {
		return fmt.Errorf("kernel create set %s: %w", config.Name, err)
	}
	if err := m.kernel.Flush(); err != nil {
		return fmt.Errorf("kernel flush after create set %s: %w", config.Name, err)
	}

	m.sets[config.Name] = &managedSet{
		config:   config,
		elements: make(map[string]Element),
	}
	return nil
}

// DeleteSet removes a set.
func (m *DefaultManager) DeleteSet(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	set, exists := m.sets[name]
	if !exists {
		return fmt.Errorf("set %s does not exist", name)
	}

	table := set.config.Table
	if table == "" {
		table = m.table
	}

	if err := m.kernel.DeleteSet(table, name); err != nil {
		return fmt.Errorf("kernel delete set %s: %w", name, err)
	}
	if err := m.kernel.Flush(); err != nil {
		return fmt.Errorf("kernel flush after delete set %s: %w", name, err)
	}

	delete(m.sets, name)
	return nil
}

// SetExists returns true if a set with the given name exists.
func (m *DefaultManager) SetExists(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.sets[name]
	return exists
}

// AddElements adds elements to a set.
func (m *DefaultManager) AddElements(setName string, elements []Element) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	set, exists := m.sets[setName]
	if !exists {
		return fmt.Errorf("set %s does not exist", setName)
	}

	table := set.config.Table
	if table == "" {
		table = m.table
	}

	if err := m.kernel.AddElements(table, setName, elements); err != nil {
		return fmt.Errorf("kernel add elements to %s: %w", setName, err)
	}
	if err := m.kernel.Flush(); err != nil {
		return fmt.Errorf("kernel flush after add elements to %s: %w", setName, err)
	}

	for _, elem := range elements {
		set.elements[elem.Value] = elem
	}
	return nil
}

// RemoveElements removes elements from a set.
func (m *DefaultManager) RemoveElements(setName string, elements []Element) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	set, exists := m.sets[setName]
	if !exists {
		return fmt.Errorf("set %s does not exist", setName)
	}

	table := set.config.Table
	if table == "" {
		table = m.table
	}

	if err := m.kernel.RemoveElements(table, setName, elements); err != nil {
		return fmt.Errorf("kernel remove elements from %s: %w", setName, err)
	}
	if err := m.kernel.Flush(); err != nil {
		return fmt.Errorf("kernel flush after remove elements from %s: %w", setName, err)
	}

	for _, elem := range elements {
		delete(set.elements, elem.Value)
	}
	return nil
}

// FlushSet removes all elements from a set.
func (m *DefaultManager) FlushSet(setName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	set, exists := m.sets[setName]
	if !exists {
		return fmt.Errorf("set %s does not exist", setName)
	}

	table := set.config.Table
	if table == "" {
		table = m.table
	}

	if err := m.kernel.FlushSet(table, setName); err != nil {
		return fmt.Errorf("kernel flush set %s: %w", setName, err)
	}
	if err := m.kernel.Flush(); err != nil {
		return fmt.Errorf("kernel flush after flush set %s: %w", setName, err)
	}

	set.elements = make(map[string]Element)
	return nil
}

// ListElements returns all elements in a set.
func (m *DefaultManager) ListElements(setName string) ([]Element, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	set, exists := m.sets[setName]
	if !exists {
		return nil, fmt.Errorf("set %s does not exist", setName)
	}

	result := make([]Element, 0, len(set.elements))
	for _, elem := range set.elements {
		result = append(result, elem)
	}
	return result, nil
}

// ReplaceElements atomically replaces all elements in a set.
// This is useful for threat intelligence feed updates where the
// entire set should be refreshed without a window where it's empty.
func (m *DefaultManager) ReplaceElements(setName string, elements []Element) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	set, exists := m.sets[setName]
	if !exists {
		return fmt.Errorf("set %s does not exist", setName)
	}

	table := set.config.Table
	if table == "" {
		table = m.table
	}

	// Flush existing elements and add new ones in a single atomic commit
	if err := m.kernel.FlushSet(table, setName); err != nil {
		return fmt.Errorf("kernel flush set %s: %w", setName, err)
	}
	if len(elements) > 0 {
		if err := m.kernel.AddElements(table, setName, elements); err != nil {
			return fmt.Errorf("kernel add elements to %s: %w", setName, err)
		}
	}
	if err := m.kernel.Flush(); err != nil {
		return fmt.Errorf("kernel atomic flush for replace on %s: %w", setName, err)
	}

	// Update tracking
	set.elements = make(map[string]Element, len(elements))
	for _, elem := range elements {
		set.elements[elem.Value] = elem
	}
	return nil
}

// GetSetInfo returns information about a set.
func (m *DefaultManager) GetSetInfo(setName string) (*SetInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	set, exists := m.sets[setName]
	if !exists {
		return nil, fmt.Errorf("set %s does not exist", setName)
	}

	return &SetInfo{
		Name:         setName,
		Type:         set.config.Type,
		ElementCount: len(set.elements),
		Table:        set.config.Table,
		HasTimeout:   set.config.Timeout > 0,
		HasInterval:  set.config.Interval,
		HasCounter:   set.config.Counter,
	}, nil
}

// ListSets returns info about all managed sets.
func (m *DefaultManager) ListSets() ([]SetInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]SetInfo, 0, len(m.sets))
	for name, set := range m.sets {
		result = append(result, SetInfo{
			Name:         name,
			Type:         set.config.Type,
			ElementCount: len(set.elements),
			Table:        set.config.Table,
			HasTimeout:   set.config.Timeout > 0,
			HasInterval:  set.config.Interval,
			HasCounter:   set.config.Counter,
		})
	}
	return result, nil
}
