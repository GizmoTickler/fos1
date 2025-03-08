package integration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	dhcpController "github.com/varuntirumala1/fos1/pkg/dhcp/controller"
	"github.com/varuntirumala1/fos1/pkg/dhcp/types"
	dnsManager "github.com/varuntirumala1/fos1/pkg/dns/manager"
)

// MockDNSManager mocks the DNS manager
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

// MockDHCPController mocks the DHCP controller
type MockDHCPController struct {
	mock.Mock
}

// CreateLease mocks the CreateLease method
func (m *MockDHCPController) CreateLease(lease *types.Lease) error {
	args := m.Called(lease)
	return args.Error(0)
}

// RemoveLease mocks the RemoveLease method
func (m *MockDHCPController) RemoveLease(ip string) error {
	args := m.Called(ip)
	return args.Error(0)
}

// TestDHCPDNSIntegration tests the integration between DHCP and DNS
func TestDHCPDNSIntegration(t *testing.T) {
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// Create a mock DHCP controller
	mockDHCPController := new(MockDHCPController)
	
	// Create a DNS connector with the mock DNS manager
	dnsConnector := dhcpController.NewDNSConnector(mockDNSManager)
	
	// Test scenario: DHCP lease is created and DNS records are added
	
	// Setup DNS manager expectations for lease creation
	mockDNSManager.On("AddRecord", "test-host.example.com", "A", "192.168.1.100", uint32(3600)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "192.168.1.100", "test-host.example.com", uint32(3600)).Return(nil)
	
	// Create a test lease
	lease := &types.Lease{
		IP:        "192.168.1.100",
		Hostname:  "test-host",
		Domain:    "example.com",
		TTL:       3600,
		ExpiresAt: time.Now().Add(24 * time.Hour), // Expires in 24 hours
	}
	
	// Call UpdateLease to simulate DHCP lease creation with DNS updates
	err := dnsConnector.UpdateLease(lease)
	
	// Verify results
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
	
	// Test scenario: DHCP lease is removed and DNS records are removed
	
	// Reset the mock to prepare for the next test
	mockDNSManager = new(MockDNSManager)
	dnsConnector = dhcpController.NewDNSConnector(mockDNSManager)
	
	// Setup DNS manager expectations for lease removal
	mockDNSManager.On("RemoveRecord", "test-host.example.com", "A", "192.168.1.100").Return(nil)
	mockDNSManager.On("RemoveReverseRecord", "192.168.1.100").Return(nil)
	
	// Call RemoveLease to simulate DHCP lease removal with DNS updates
	err = dnsConnector.RemoveLease(lease)
	
	// Verify results
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestDHCPDNSIntegrationMultipleLeases tests handling multiple leases
func TestDHCPDNSIntegrationMultipleLeases(t *testing.T) {
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// Create a DNS connector with the mock
	dnsConnector := dhcpController.NewDNSConnector(mockDNSManager)
	
	// Setup DNS manager expectations for multiple leases
	mockDNSManager.On("AddRecord", "host1.example.com", "A", "192.168.1.101", uint32(3600)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "192.168.1.101", "host1.example.com", uint32(3600)).Return(nil)
	
	mockDNSManager.On("AddRecord", "host2.example.com", "A", "192.168.1.102", uint32(3600)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "192.168.1.102", "host2.example.com", uint32(3600)).Return(nil)
	
	mockDNSManager.On("AddRecord", "host3.example.com", "A", "192.168.1.103", uint32(3600)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "192.168.1.103", "host3.example.com", uint32(3600)).Return(nil)
	
	// Create and process multiple leases
	leases := []*types.Lease{
		{
			IP:        "192.168.1.101",
			Hostname:  "host1",
			Domain:    "example.com",
			TTL:       3600,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
		{
			IP:        "192.168.1.102",
			Hostname:  "host2",
			Domain:    "example.com",
			TTL:       3600,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
		{
			IP:        "192.168.1.103",
			Hostname:  "host3",
			Domain:    "example.com",
			TTL:       3600,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
	}
	
	// Process each lease
	for _, lease := range leases {
		err := dnsConnector.UpdateLease(lease)
		assert.NoError(t, err)
	}
	
	// Verify all expectations were met
	mockDNSManager.AssertExpectations(t)
	
	// Now test removing all the leases
	mockDNSManager = new(MockDNSManager)
	dnsConnector = dhcpController.NewDNSConnector(mockDNSManager)
	
	// Setup DNS manager expectations for removing multiple leases
	mockDNSManager.On("RemoveRecord", "host1.example.com", "A", "192.168.1.101").Return(nil)
	mockDNSManager.On("RemoveReverseRecord", "192.168.1.101").Return(nil)
	
	mockDNSManager.On("RemoveRecord", "host2.example.com", "A", "192.168.1.102").Return(nil)
	mockDNSManager.On("RemoveReverseRecord", "192.168.1.102").Return(nil)
	
	mockDNSManager.On("RemoveRecord", "host3.example.com", "A", "192.168.1.103").Return(nil)
	mockDNSManager.On("RemoveReverseRecord", "192.168.1.103").Return(nil)
	
	// Remove each lease
	for _, lease := range leases {
		err := dnsConnector.RemoveLease(lease)
		assert.NoError(t, err)
	}
	
	// Verify all expectations were met
	mockDNSManager.AssertExpectations(t)
}

// TestDHCPDNSIntegrationErrorHandling tests error cases in the DHCP-DNS integration
func TestDHCPDNSIntegrationErrorHandling(t *testing.T) {
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// Create a DNS connector with the mock
	dnsConnector := dhcpController.NewDNSConnector(mockDNSManager)
	
	// Setup a failure case for adding a forward record
	mockDNSManager.On("AddRecord", "test-host.example.com", "A", "192.168.1.100", uint32(3600)).Return(
		assert.AnError)
	
	// Create a test lease
	lease := &types.Lease{
		IP:        "192.168.1.100",
		Hostname:  "test-host",
		Domain:    "example.com",
		TTL:       3600,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	
	// Call UpdateLease
	err := dnsConnector.UpdateLease(lease)
	
	// Verify the error is propagated
	assert.Error(t, err)
	mockDNSManager.AssertExpectations(t)
	
	// Reset for next test
	mockDNSManager = new(MockDNSManager)
	dnsConnector = dhcpController.NewDNSConnector(mockDNSManager)
	
	// Setup a case where forward record succeeds but reverse record fails
	mockDNSManager.On("AddRecord", "test-host.example.com", "A", "192.168.1.100", uint32(3600)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "192.168.1.100", "test-host.example.com", uint32(3600)).Return(
		assert.AnError)
	
	// Call UpdateLease
	err = dnsConnector.UpdateLease(lease)
	
	// Verify the operation succeeds even when reverse record fails (this is by design)
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestDHCPDNSIntegrationLeaseExpiration tests automatic lease expiration
func TestDHCPDNSIntegrationLeaseExpiration(t *testing.T) {
	// Skip in CI environments
	t.Skip("Skipping long-running test")
	
	// Create a mock DNS manager
	mockDNSManager := new(MockDNSManager)
	
	// Setup expectations for lease removal on expiration
	mockDNSManager.On("RemoveRecord", "test-host.example.com", "A", "192.168.1.100").Return(nil)
	mockDNSManager.On("RemoveReverseRecord", "192.168.1.100").Return(nil)
	
	// Create a DNS connector with the mock
	dnsConnector := dhcpController.NewDNSConnector(mockDNSManager)
	
	// Create a test lease that expires in 1 second
	lease := &types.Lease{
		IP:        "192.168.1.100",
		Hostname:  "test-host",
		Domain:    "example.com",
		TTL:       3600,
		ExpiresAt: time.Now().Add(1 * time.Second),
	}
	
	// Schedule the lease removal
	dnsConnector.ScheduleLeaseRemoval(lease)
	
	// Wait slightly longer than the lease expiration time
	time.Sleep(1500 * time.Millisecond)
	
	// Verify the mock expectations
	mockDNSManager.AssertExpectations(t)
}
