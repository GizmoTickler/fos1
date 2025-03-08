package coredns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewController tests the NewController function
func TestNewController(t *testing.T) {
	// Test with empty config path
	controller, err := NewController("", "")
	assert.Error(t, err)
	assert.Nil(t, controller)

	// Test with valid parameters
	controller, err = NewController("/tmp/coredns", "/tmp/zones")
	assert.NoError(t, err)
	assert.NotNil(t, controller)
	assert.Equal(t, "/tmp/coredns", controller.configPath)
	assert.Equal(t, "/tmp/zones", controller.zonesPath)

	// Test with only config path (zones path should default to config path)
	controller, err = NewController("/tmp/coredns", "")
	assert.NoError(t, err)
	assert.NotNil(t, controller)
	assert.Equal(t, "/tmp/coredns", controller.configPath)
	assert.Equal(t, "/tmp/coredns", controller.zonesPath)
}

// TestAddRecord tests the AddRecord function
func TestAddRecord(t *testing.T) {
	// Create a controller
	controller, err := NewController("/tmp/coredns", "/tmp/zones")
	assert.NoError(t, err)

	// Mock the saveConfiguration method to prevent actual file writes
	originalSaveConfig := controller.saveConfiguration
	controller.saveConfiguration = func() error { return nil }
	defer func() { controller.saveConfiguration = originalSaveConfig }()

	// Test adding a record to a new zone
	record := &DNSRecord{
		Name:  "www",
		Type:  "A",
		Value: "192.168.1.1",
		TTL:   3600,
	}

	err = controller.AddRecord("example.com", record)
	assert.NoError(t, err)

	// Verify the zone and record were created
	assert.Len(t, controller.zones, 1)
	zone, exists := controller.zones["example.com"]
	assert.True(t, exists)
	assert.Len(t, zone.Records, 1)
	assert.Equal(t, "www", zone.Records[0].Name)
	assert.Equal(t, "A", zone.Records[0].Type)
	assert.Equal(t, "192.168.1.1", zone.Records[0].Value)

	// Test updating an existing record
	updatedRecord := &DNSRecord{
		Name:  "www",
		Type:  "A",
		Value: "192.168.1.2",
		TTL:   7200,
	}

	err = controller.AddRecord("example.com", updatedRecord)
	assert.NoError(t, err)

	// Verify the record was updated
	assert.Len(t, controller.zones, 1)
	zone, exists = controller.zones["example.com"]
	assert.True(t, exists)
	assert.Len(t, zone.Records, 1)
	assert.Equal(t, "www", zone.Records[0].Name)
	assert.Equal(t, "A", zone.Records[0].Type)
	assert.Equal(t, "192.168.1.2", zone.Records[0].Value)
	assert.Equal(t, int32(7200), zone.Records[0].TTL)

	// Test adding a different record to the same zone
	anotherRecord := &DNSRecord{
		Name:  "mail",
		Type:  "A",
		Value: "192.168.1.3",
		TTL:   3600,
	}

	err = controller.AddRecord("example.com", anotherRecord)
	assert.NoError(t, err)

	// Verify both records exist
	assert.Len(t, controller.zones, 1)
	zone, exists = controller.zones["example.com"]
	assert.True(t, exists)
	assert.Len(t, zone.Records, 2)
}

// TestRemoveRecord tests the RemoveRecord function
func TestRemoveRecord(t *testing.T) {
	// Create a controller
	controller, err := NewController("/tmp/coredns", "/tmp/zones")
	assert.NoError(t, err)

	// Mock the saveConfiguration method to prevent actual file writes
	originalSaveConfig := controller.saveConfiguration
	controller.saveConfiguration = func() error { return nil }
	defer func() { controller.saveConfiguration = originalSaveConfig }()

	// Add a record first
	record := &DNSRecord{
		Name:  "www",
		Type:  "A",
		Value: "192.168.1.1",
		TTL:   3600,
	}

	err = controller.AddRecord("example.com", record)
	assert.NoError(t, err)

	// Add another record
	anotherRecord := &DNSRecord{
		Name:  "mail",
		Type:  "A",
		Value: "192.168.1.2",
		TTL:   3600,
	}

	err = controller.AddRecord("example.com", anotherRecord)
	assert.NoError(t, err)

	// Verify both records exist
	assert.Len(t, controller.zones["example.com"].Records, 2)

	// Test removing a record
	err = controller.RemoveRecord("example.com", "www", "A", "192.168.1.1")
	assert.NoError(t, err)

	// Verify only one record remains
	assert.Len(t, controller.zones, 1)
	zone, exists := controller.zones["example.com"]
	assert.True(t, exists)
	assert.Len(t, zone.Records, 1)
	assert.Equal(t, "mail", zone.Records[0].Name)

	// Test removing a non-existent record
	err = controller.RemoveRecord("example.com", "nonexistent", "A", "")
	assert.Error(t, err)

	// Test removing a record from a non-existent zone
	err = controller.RemoveRecord("nonexistent.com", "www", "A", "")
	assert.Error(t, err)
}

// TestAddPTRRecord tests the AddPTRRecord function
func TestAddPTRRecord(t *testing.T) {
	// Create a controller
	controller, err := NewController("/tmp/coredns", "/tmp/zones")
	assert.NoError(t, err)

	// Mock the saveConfiguration method to prevent actual file writes
	originalSaveConfig := controller.saveConfiguration
	controller.saveConfiguration = func() error { return nil }
	defer func() { controller.saveConfiguration = originalSaveConfig }()

	// Test adding a PTR record to a new zone
	record := &DNSRecord{
		Name:  "1",
		Type:  "PTR",
		Value: "www.example.com.",
		TTL:   3600,
	}

	err = controller.AddPTRRecord("1.168.192.in-addr.arpa", record)
	assert.NoError(t, err)

	// Verify the zone and record were created
	assert.Len(t, controller.ptrZones, 1)
	zone, exists := controller.ptrZones["1.168.192.in-addr.arpa"]
	assert.True(t, exists)
	assert.Len(t, zone.Records, 1)
	assert.Equal(t, "1", zone.Records[0].Name)
	assert.Equal(t, "PTR", zone.Records[0].Type)
	assert.Equal(t, "www.example.com.", zone.Records[0].Value)

	// Test updating an existing PTR record
	updatedRecord := &DNSRecord{
		Name:  "1",
		Type:  "PTR",
		Value: "mail.example.com.",
		TTL:   7200,
	}

	err = controller.AddPTRRecord("1.168.192.in-addr.arpa", updatedRecord)
	assert.NoError(t, err)

	// Verify the record was updated
	assert.Len(t, controller.ptrZones, 1)
	zone, exists = controller.ptrZones["1.168.192.in-addr.arpa"]
	assert.True(t, exists)
	assert.Len(t, zone.Records, 1)
	assert.Equal(t, "1", zone.Records[0].Name)
	assert.Equal(t, "PTR", zone.Records[0].Type)
	assert.Equal(t, "mail.example.com.", zone.Records[0].Value)
	assert.Equal(t, int32(7200), zone.Records[0].TTL)
}

// TestRemovePTRRecord tests the RemovePTRRecord function
func TestRemovePTRRecord(t *testing.T) {
	// Create a controller
	controller, err := NewController("/tmp/coredns", "/tmp/zones")
	assert.NoError(t, err)

	// Mock the saveConfiguration method to prevent actual file writes
	originalSaveConfig := controller.saveConfiguration
	controller.saveConfiguration = func() error { return nil }
	defer func() { controller.saveConfiguration = originalSaveConfig }()

	// Add a PTR record first
	record := &DNSRecord{
		Name:  "1",
		Type:  "PTR",
		Value: "www.example.com.",
		TTL:   3600,
	}

	err = controller.AddPTRRecord("1.168.192.in-addr.arpa", record)
	assert.NoError(t, err)

	// Add another PTR record
	anotherRecord := &DNSRecord{
		Name:  "2",
		Type:  "PTR",
		Value: "mail.example.com.",
		TTL:   3600,
	}

	err = controller.AddPTRRecord("1.168.192.in-addr.arpa", anotherRecord)
	assert.NoError(t, err)

	// Verify both records exist
	assert.Len(t, controller.ptrZones["1.168.192.in-addr.arpa"].Records, 2)

	// Test removing a PTR record
	err = controller.RemovePTRRecord("1.168.192.in-addr.arpa", "1")
	assert.NoError(t, err)

	// Verify only one record remains
	assert.Len(t, controller.ptrZones, 1)
	zone, exists := controller.ptrZones["1.168.192.in-addr.arpa"]
	assert.True(t, exists)
	assert.Len(t, zone.Records, 1)
	assert.Equal(t, "2", zone.Records[0].Name)

	// Test removing a non-existent record
	err = controller.RemovePTRRecord("1.168.192.in-addr.arpa", "nonexistent")
	assert.Error(t, err)

	// Test removing a record from a non-existent zone
	err = controller.RemovePTRRecord("nonexistent.arpa", "1")
	assert.Error(t, err)
}

// TestStatus tests the Status function
func TestStatus(t *testing.T) {
	// Create a controller
	controller, err := NewController("/tmp/coredns", "/tmp/zones")
	assert.NoError(t, err)

	// Mock the saveConfiguration method to prevent actual file writes
	originalSaveConfig := controller.saveConfiguration
	controller.saveConfiguration = func() error { return nil }
	defer func() { controller.saveConfiguration = originalSaveConfig }()

	// Add some records
	for i := 0; i < 3; i++ {
		record := &DNSRecord{
			Name:  "www",
			Type:  "A",
			Value: "192.168.1.1",
			TTL:   3600,
		}

		err = controller.AddRecord("example"+string(rune('0'+i))+".com", record)
		assert.NoError(t, err)
	}

	// Get status
	status, err := controller.Status()
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.True(t, status.Running)
	assert.Equal(t, 3, status.Zones)
	assert.Equal(t, 3, status.RecordsServed)
}
