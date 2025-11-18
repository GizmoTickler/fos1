package nat

import (
	"fmt"
	"sync"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// NAT66Manager2 manages NAT66 (IPv6 to IPv6) translations
type NAT66Manager2 struct {
	mutex         sync.RWMutex
	translations  map[string]NAT66Translation // key: sourcePrefix
	ciliumClient  cilium.Client
}

// NAT66Translation represents a NAT66 translation
type NAT66Translation struct {
	// SourcePrefix is the source IPv6 prefix
	SourcePrefix string
	
	// TranslatedPrefix is the translated IPv6 prefix
	TranslatedPrefix string
	
	// Interface is the outgoing interface
	Interface string
	
	// Stateful indicates whether the translation is stateful
	Stateful bool
	
	// Enabled indicates whether the translation is enabled
	Enabled bool
}

// NewNAT66Manager2 creates a new NAT66 manager
func NewNAT66Manager2(ciliumClient cilium.Client) *NAT66Manager2 {
	return &NAT66Manager2{
		translations: make(map[string]NAT66Translation),
		ciliumClient: ciliumClient,
	}
}

// AddTranslation adds a NAT66 translation
func (m *NAT66Manager2) AddTranslation(translation NAT66Translation) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the translation already exists
	if _, exists := m.translations[translation.SourcePrefix]; exists {
		return fmt.Errorf("NAT66 translation already exists for source prefix: %s", translation.SourcePrefix)
	}
	
	// Store the translation
	m.translations[translation.SourcePrefix] = translation
	
	// Apply the translation if it's enabled
	if translation.Enabled {
		if err := m.applyTranslation(translation); err != nil {
			delete(m.translations, translation.SourcePrefix)
			return fmt.Errorf("failed to apply NAT66 translation: %w", err)
		}
	}
	
	klog.Infof("Added NAT66 translation: %s -> %s", translation.SourcePrefix, translation.TranslatedPrefix)
	return nil
}

// UpdateTranslation updates a NAT66 translation
func (m *NAT66Manager2) UpdateTranslation(translation NAT66Translation) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the translation exists
	oldTranslation, exists := m.translations[translation.SourcePrefix]
	if !exists {
		return fmt.Errorf("NAT66 translation does not exist for source prefix: %s", translation.SourcePrefix)
	}
	
	// Remove the old translation if it was enabled
	if oldTranslation.Enabled {
		if err := m.removeTranslation(oldTranslation); err != nil {
			return fmt.Errorf("failed to remove old NAT66 translation: %w", err)
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
			return fmt.Errorf("failed to apply NAT66 translation: %w", err)
		}
	}
	
	klog.Infof("Updated NAT66 translation: %s -> %s", translation.SourcePrefix, translation.TranslatedPrefix)
	return nil
}

// RemoveTranslation removes a NAT66 translation
func (m *NAT66Manager2) RemoveTranslation(sourcePrefix string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the translation exists
	translation, exists := m.translations[sourcePrefix]
	if !exists {
		return fmt.Errorf("NAT66 translation does not exist for source prefix: %s", sourcePrefix)
	}
	
	// Remove the translation if it was enabled
	if translation.Enabled {
		if err := m.removeTranslation(translation); err != nil {
			return fmt.Errorf("failed to remove NAT66 translation: %w", err)
		}
	}
	
	// Remove the translation from the map
	delete(m.translations, sourcePrefix)
	
	klog.Infof("Removed NAT66 translation for source prefix: %s", sourcePrefix)
	return nil
}

// GetTranslation gets a NAT66 translation
func (m *NAT66Manager2) GetTranslation(sourcePrefix string) (*NAT66Translation, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Check if the translation exists
	translation, exists := m.translations[sourcePrefix]
	if !exists {
		return nil, fmt.Errorf("NAT66 translation does not exist for source prefix: %s", sourcePrefix)
	}
	
	// Return a copy of the translation
	translationCopy := translation
	return &translationCopy, nil
}

// ListTranslations lists all NAT66 translations
func (m *NAT66Manager2) ListTranslations() []NAT66Translation {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Create a list of translations
	translations := make([]NAT66Translation, 0, len(m.translations))
	for _, translation := range m.translations {
		translations = append(translations, translation)
	}
	
	return translations
}

// EnableTranslation enables a NAT66 translation
func (m *NAT66Manager2) EnableTranslation(sourcePrefix string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the translation exists
	translation, exists := m.translations[sourcePrefix]
	if !exists {
		return fmt.Errorf("NAT66 translation does not exist for source prefix: %s", sourcePrefix)
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
		return fmt.Errorf("failed to apply NAT66 translation: %w", err)
	}
	
	// Store the updated translation
	m.translations[sourcePrefix] = translation
	
	klog.Infof("Enabled NAT66 translation for source prefix: %s", sourcePrefix)
	return nil
}

// DisableTranslation disables a NAT66 translation
func (m *NAT66Manager2) DisableTranslation(sourcePrefix string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the translation exists
	translation, exists := m.translations[sourcePrefix]
	if !exists {
		return fmt.Errorf("NAT66 translation does not exist for source prefix: %s", sourcePrefix)
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
		return fmt.Errorf("failed to remove NAT66 translation: %w", err)
	}
	
	// Store the updated translation
	m.translations[sourcePrefix] = translation
	
	klog.Infof("Disabled NAT66 translation for source prefix: %s", sourcePrefix)
	return nil
}

// applyTranslation applies a NAT66 translation
func (m *NAT66Manager2) applyTranslation(translation NAT66Translation) error {
	// Create a Cilium NAT configuration with IPv6
	natConfig := &cilium.NATConfig{
		SourceNetwork:    translation.SourcePrefix,
		DestinationIface: translation.Interface,
		IPv6:             true,
	}
	
	// Apply the NAT configuration using Cilium
	return m.ciliumClient.CreateNAT(nil, natConfig)
}

// removeTranslation removes a NAT66 translation
func (m *NAT66Manager2) removeTranslation(translation NAT66Translation) error {
	// Create a Cilium NAT configuration with IPv6
	natConfig := &cilium.NATConfig{
		SourceNetwork:    translation.SourcePrefix,
		DestinationIface: translation.Interface,
		IPv6:             true,
	}
	
	// Remove the NAT configuration using Cilium
	return m.ciliumClient.RemoveNAT(nil, natConfig)
}
