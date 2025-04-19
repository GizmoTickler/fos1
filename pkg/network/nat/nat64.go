package nat

import (
	"fmt"
	"sync"

	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/cilium"
)

// NAT64Manager manages NAT64 (IPv6 to IPv4) translations
type NAT64Manager struct {
	mutex         sync.RWMutex
	translations  map[string]NAT64Translation // key: sourcePrefix
	ciliumClient  cilium.Client
}

// NAT64Translation represents a NAT64 translation
type NAT64Translation struct {
	// SourcePrefix is the source IPv6 prefix
	SourcePrefix string
	
	// DestinationPrefix is the destination IPv4 prefix
	DestinationPrefix string
	
	// Interface is the outgoing interface
	Interface string
	
	// Stateful indicates whether the translation is stateful
	Stateful bool
	
	// Enabled indicates whether the translation is enabled
	Enabled bool
}

// NewNAT64Manager creates a new NAT64 manager
func NewNAT64Manager(ciliumClient cilium.Client) *NAT64Manager {
	return &NAT64Manager{
		translations: make(map[string]NAT64Translation),
		ciliumClient: ciliumClient,
	}
}

// AddTranslation adds a NAT64 translation
func (m *NAT64Manager) AddTranslation(translation NAT64Translation) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the translation already exists
	if _, exists := m.translations[translation.SourcePrefix]; exists {
		return fmt.Errorf("NAT64 translation already exists for source prefix: %s", translation.SourcePrefix)
	}
	
	// Store the translation
	m.translations[translation.SourcePrefix] = translation
	
	// Apply the translation if it's enabled
	if translation.Enabled {
		if err := m.applyTranslation(translation); err != nil {
			delete(m.translations, translation.SourcePrefix)
			return fmt.Errorf("failed to apply NAT64 translation: %w", err)
		}
	}
	
	klog.Infof("Added NAT64 translation: %s -> %s", translation.SourcePrefix, translation.DestinationPrefix)
	return nil
}

// UpdateTranslation updates a NAT64 translation
func (m *NAT64Manager) UpdateTranslation(translation NAT64Translation) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the translation exists
	oldTranslation, exists := m.translations[translation.SourcePrefix]
	if !exists {
		return fmt.Errorf("NAT64 translation does not exist for source prefix: %s", translation.SourcePrefix)
	}
	
	// Remove the old translation if it was enabled
	if oldTranslation.Enabled {
		if err := m.removeTranslation(oldTranslation); err != nil {
			return fmt.Errorf("failed to remove old NAT64 translation: %w", err)
		}
	}
	
	// Store the new translation
	m.translations[translation.SourcePrefix] = translation
	
	// Apply the new translation if it's enabled
	if translation.Enabled {
		if err := m.applyTranslation(translation); err != nil {
			// Restore the old translation
			m.translations[translation.SourcePrefix] = oldTranslation
			if oldTranslation.Enabled {
				_ = m.applyTranslation(oldTranslation)
			}
			return fmt.Errorf("failed to apply NAT64 translation: %w", err)
		}
	}
	
	klog.Infof("Updated NAT64 translation: %s -> %s", translation.SourcePrefix, translation.DestinationPrefix)
	return nil
}

// RemoveTranslation removes a NAT64 translation
func (m *NAT64Manager) RemoveTranslation(sourcePrefix string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the translation exists
	translation, exists := m.translations[sourcePrefix]
	if !exists {
		return fmt.Errorf("NAT64 translation does not exist for source prefix: %s", sourcePrefix)
	}
	
	// Remove the translation if it was enabled
	if translation.Enabled {
		if err := m.removeTranslation(translation); err != nil {
			return fmt.Errorf("failed to remove NAT64 translation: %w", err)
		}
	}
	
	// Remove the translation from the map
	delete(m.translations, sourcePrefix)
	
	klog.Infof("Removed NAT64 translation for source prefix: %s", sourcePrefix)
	return nil
}

// GetTranslation gets a NAT64 translation
func (m *NAT64Manager) GetTranslation(sourcePrefix string) (*NAT64Translation, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Check if the translation exists
	translation, exists := m.translations[sourcePrefix]
	if !exists {
		return nil, fmt.Errorf("NAT64 translation does not exist for source prefix: %s", sourcePrefix)
	}
	
	// Return a copy of the translation
	translationCopy := translation
	return &translationCopy, nil
}

// ListTranslations lists all NAT64 translations
func (m *NAT64Manager) ListTranslations() []NAT64Translation {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Create a list of translations
	translations := make([]NAT64Translation, 0, len(m.translations))
	for _, translation := range m.translations {
		translations = append(translations, translation)
	}
	
	return translations
}

// EnableTranslation enables a NAT64 translation
func (m *NAT64Manager) EnableTranslation(sourcePrefix string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the translation exists
	translation, exists := m.translations[sourcePrefix]
	if !exists {
		return fmt.Errorf("NAT64 translation does not exist for source prefix: %s", sourcePrefix)
	}
	
	// Check if the translation is already enabled
	if translation.Enabled {
		return nil
	}
	
	// Enable the translation
	translation.Enabled = true
	
	// Apply the translation
	if err := m.applyTranslation(translation); err != nil {
		translation.Enabled = false
		m.translations[sourcePrefix] = translation
		return fmt.Errorf("failed to apply NAT64 translation: %w", err)
	}
	
	// Store the updated translation
	m.translations[sourcePrefix] = translation
	
	klog.Infof("Enabled NAT64 translation for source prefix: %s", sourcePrefix)
	return nil
}

// DisableTranslation disables a NAT64 translation
func (m *NAT64Manager) DisableTranslation(sourcePrefix string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the translation exists
	translation, exists := m.translations[sourcePrefix]
	if !exists {
		return fmt.Errorf("NAT64 translation does not exist for source prefix: %s", sourcePrefix)
	}
	
	// Check if the translation is already disabled
	if !translation.Enabled {
		return nil
	}
	
	// Disable the translation
	translation.Enabled = false
	
	// Remove the translation
	if err := m.removeTranslation(translation); err != nil {
		translation.Enabled = true
		m.translations[sourcePrefix] = translation
		return fmt.Errorf("failed to remove NAT64 translation: %w", err)
	}
	
	// Store the updated translation
	m.translations[sourcePrefix] = translation
	
	klog.Infof("Disabled NAT64 translation for source prefix: %s", sourcePrefix)
	return nil
}

// applyTranslation applies a NAT64 translation
func (m *NAT64Manager) applyTranslation(translation NAT64Translation) error {
	// Create a Cilium NAT64 configuration
	nat64Config := &cilium.NAT64Config{
		SourceNetwork:    translation.SourcePrefix,
		DestinationIface: translation.Interface,
	}
	
	// Apply the NAT64 configuration using Cilium
	return m.ciliumClient.CreateNAT64(nil, nat64Config)
}

// removeTranslation removes a NAT64 translation
func (m *NAT64Manager) removeTranslation(translation NAT64Translation) error {
	// Create a Cilium NAT64 configuration
	nat64Config := &cilium.NAT64Config{
		SourceNetwork:    translation.SourcePrefix,
		DestinationIface: translation.Interface,
	}
	
	// Remove the NAT64 configuration using Cilium
	return m.ciliumClient.RemoveNAT64(nil, nat64Config)
}
