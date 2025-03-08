package test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/varuntirumala1/fos1/pkg/dhcp/controller"
	"github.com/varuntirumala1/fos1/pkg/dhcp/types"
)

// MockDNSManager is a mock for the DNS manager
type MockDNSManager struct {
	mock.Mock
}

// AddRecord mocks the AddRecord method
func (m *MockDNSManager) AddRecord(name, recordType, value string, ttl uint32) error {
	args := m.Called(name, recordType, value, ttl)
	return args.Error(0)
}

// RemoveRecord mocks the RemoveRecord method
func (m *MockDNSManager) RemoveRecord(name, recordType, value string) error {
	args := m.Called(name, recordType, value)
	return args.Error(0)
}

// AddReverseRecord mocks the AddReverseRecord method
func (m *MockDNSManager) AddReverseRecord(ip, target string, ttl uint32) error {
	args := m.Called(ip, target, ttl)
	return args.Error(0)
}

// RemoveReverseRecord mocks the RemoveReverseRecord method
func (m *MockDNSManager) RemoveReverseRecord(ip string) error {
	args := m.Called(ip)
	return args.Error(0)
}

// TestUpdateLease tests that UpdateLease correctly adds DNS records
func TestUpdateLease(t *testing.T) {
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// Setup the mock expectations
	mockDNSManager.On("AddRecord", "test-host.example.com", "A", "192.168.1.100", uint32(3600)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "192.168.1.100", "test-host.example.com", uint32(3600)).Return(nil)
	
	// Create a DNS connector with the mock
	dnsConnector := controller.NewDNSConnector(mockDNSManager)
	
	// Create a test lease
	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "test-host",
		Domain:   "example.com",
		TTL:      3600,
	}
	
	// Call UpdateLease
	err := dnsConnector.UpdateLease(lease)
	
	// Verify results
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestUpdateLeaseNoHostname tests that UpdateLease skips DNS records when no hostname is provided
func TestUpdateLeaseNoHostname(t *testing.T) {
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// No expectations, as no methods should be called
	
	// Create a DNS connector with the mock
	dnsConnector := controller.NewDNSConnector(mockDNSManager)
	
	// Create a test lease with no hostname
	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "",
		Domain:   "example.com",
		TTL:      3600,
	}
	
	// Call UpdateLease
	err := dnsConnector.UpdateLease(lease)
	
	// Verify results
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestUpdateLeaseDefaultDomain tests that UpdateLease uses a default domain when none is provided
func TestUpdateLeaseDefaultDomain(t *testing.T) {
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// Setup the mock expectations (note the default "local" domain)
	mockDNSManager.On("AddRecord", "test-host.local", "A", "192.168.1.100", uint32(3600)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "192.168.1.100", "test-host.local", uint32(3600)).Return(nil)
	
	// Create a DNS connector with the mock
	dnsConnector := controller.NewDNSConnector(mockDNSManager)
	
	// Create a test lease with no domain
	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "test-host",
		Domain:   "", // No domain provided
		TTL:      3600,
	}
	
	// Call UpdateLease
	err := dnsConnector.UpdateLease(lease)
	
	// Verify results
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestUpdateLeaseDefaultTTL tests that UpdateLease uses a default TTL when none is provided
func TestUpdateLeaseDefaultTTL(t *testing.T) {
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// Setup the mock expectations with default TTL of 3600
	mockDNSManager.On("AddRecord", "test-host.example.com", "A", "192.168.1.100", uint32(3600)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "192.168.1.100", "test-host.example.com", uint32(3600)).Return(nil)
	
	// Create a DNS connector with the mock
	dnsConnector := controller.NewDNSConnector(mockDNSManager)
	
	// Create a test lease with no TTL
	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "test-host",
		Domain:   "example.com",
		TTL:      0, // No TTL provided
	}
	
	// Call UpdateLease
	err := dnsConnector.UpdateLease(lease)
	
	// Verify results
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestRemoveLease tests that RemoveLease correctly removes DNS records
func TestRemoveLease(t *testing.T) {
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// Setup the mock expectations
	mockDNSManager.On("RemoveRecord", "test-host.example.com", "A", "192.168.1.100").Return(nil)
	mockDNSManager.On("RemoveReverseRecord", "192.168.1.100").Return(nil)
	
	// Create a DNS connector with the mock
	dnsConnector := controller.NewDNSConnector(mockDNSManager)
	
	// Create a test lease
	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "test-host",
		Domain:   "example.com",
	}
	
	// Call RemoveLease
	err := dnsConnector.RemoveLease(lease)
	
	// Verify results
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestRemoveLeaseNoHostname tests that RemoveLease skips DNS records when no hostname is provided
func TestRemoveLeaseNoHostname(t *testing.T) {
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// No expectations, as no methods should be called
	
	// Create a DNS connector with the mock
	dnsConnector := controller.NewDNSConnector(mockDNSManager)
	
	// Create a test lease with no hostname
	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "",
		Domain:   "example.com",
	}
	
	// Call RemoveLease
	err := dnsConnector.RemoveLease(lease)
	
	// Verify results
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestScheduleLeaseRemoval tests that ScheduleLeaseRemoval correctly schedules a lease removal
func TestScheduleLeaseRemoval(t *testing.T) {
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// Setup expectations for expired lease
	mockDNSManager.On("RemoveRecord", "test-host.example.com", "A", "192.168.1.100").Return(nil)
	mockDNSManager.On("RemoveReverseRecord", "192.168.1.100").Return(nil)
	
	// Create a DNS connector with the mock
	dnsConnector := controller.NewDNSConnector(mockDNSManager)
	
	// Create a test lease that has already expired
	expiredLease := &types.Lease{
		IP:        "192.168.1.100",
		Hostname:  "test-host",
		Domain:    "example.com",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}
	
	// Call ScheduleLeaseRemoval
	dnsConnector.ScheduleLeaseRemoval(expiredLease)
	
	// Give a moment for the goroutine to execute
	time.Sleep(100 * time.Millisecond)
	
	// Verify the mock expectations
	mockDNSManager.AssertExpectations(t)
}

// TestScheduleLeaseRemovalFuture tests that ScheduleLeaseRemoval correctly schedules a future lease removal
func TestScheduleLeaseRemovalFuture(t *testing.T) {
	// Skip this test in CI environments or when time is a constraint
	t.Skip("Skipping long-running test")
	
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// Setup expectations for future lease removal
	mockDNSManager.On("RemoveRecord", "test-host.example.com", "A", "192.168.1.100").Return(nil)
	mockDNSManager.On("RemoveReverseRecord", "192.168.1.100").Return(nil)
	
	// Create a DNS connector with the mock
	dnsConnector := controller.NewDNSConnector(mockDNSManager)
	
	// Create a test lease that expires in 1 second
	futureLease := &types.Lease{
		IP:        "192.168.1.100",
		Hostname:  "test-host",
		Domain:    "example.com",
		ExpiresAt: time.Now().Add(1 * time.Second), // Expires in 1 second
	}
	
	// Call ScheduleLeaseRemoval
	dnsConnector.ScheduleLeaseRemoval(futureLease)
	
	// Wait for more than the lease expiration time
	time.Sleep(1500 * time.Millisecond)
	
	// Verify the mock expectations
	mockDNSManager.AssertExpectations(t)
}
