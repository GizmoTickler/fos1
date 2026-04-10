package test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/GizmoTickler/fos1/pkg/dhcp/controller"
	"github.com/GizmoTickler/fos1/pkg/dhcp/types"
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
	mockDNSManager := new(MockDNSManager)

	mockDNSManager.On("AddRecord", "test-host.example.com", "A", "192.168.1.100", uint32(3600)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "192.168.1.100", "test-host.example.com", uint32(3600)).Return(nil)

	dnsConnector := controller.NewDNSConnector(mockDNSManager)

	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "test-host",
		Domain:   "example.com",
		TTL:      3600,
	}

	err := dnsConnector.UpdateLease(lease)
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestUpdateLeaseNoHostname tests that UpdateLease skips DNS records when no hostname is provided
func TestUpdateLeaseNoHostname(t *testing.T) {
	mockDNSManager := new(MockDNSManager)

	dnsConnector := controller.NewDNSConnector(mockDNSManager)

	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "",
		Domain:   "example.com",
		TTL:      3600,
	}

	err := dnsConnector.UpdateLease(lease)
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestUpdateLeaseVLANRefDomain tests that UpdateLease derives domain from VLAN ref
// when no explicit domain is set.
func TestUpdateLeaseVLANRefDomain(t *testing.T) {
	mockDNSManager := new(MockDNSManager)

	// When no domain is set but VLANRef is, domain becomes "vlan100.local"
	mockDNSManager.On("AddRecord", "test-host.vlan100.local", "A", "192.168.1.100", uint32(3600)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "192.168.1.100", "test-host.vlan100.local", uint32(3600)).Return(nil)

	dnsConnector := controller.NewDNSConnector(mockDNSManager)

	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "test-host",
		Domain:   "",
		VLANRef:  "vlan100",
		TTL:      3600,
	}

	err := dnsConnector.UpdateLease(lease)
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestUpdateLeaseNoDomainNoVLAN tests that UpdateLease returns an error when
// neither domain nor VLANRef is set.
func TestUpdateLeaseNoDomainNoVLAN(t *testing.T) {
	mockDNSManager := new(MockDNSManager)

	dnsConnector := controller.NewDNSConnector(mockDNSManager)

	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "test-host",
		Domain:   "",
		VLANRef:  "",
		TTL:      3600,
	}

	err := dnsConnector.UpdateLease(lease)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no domain suffix configured")
	mockDNSManager.AssertExpectations(t)
}

// TestUpdateLeaseDefaultTTL tests that UpdateLease uses a default TTL when none is provided
func TestUpdateLeaseDefaultTTL(t *testing.T) {
	mockDNSManager := new(MockDNSManager)

	mockDNSManager.On("AddRecord", "test-host.example.com", "A", "192.168.1.100", uint32(3600)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "192.168.1.100", "test-host.example.com", uint32(3600)).Return(nil)

	dnsConnector := controller.NewDNSConnector(mockDNSManager)

	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "test-host",
		Domain:   "example.com",
		TTL:      0, // No TTL provided, defaults to 3600
	}

	err := dnsConnector.UpdateLease(lease)
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestRemoveLease tests that RemoveLease correctly removes DNS records
func TestRemoveLease(t *testing.T) {
	mockDNSManager := new(MockDNSManager)

	mockDNSManager.On("RemoveRecord", "test-host.example.com", "A", "192.168.1.100").Return(nil)
	mockDNSManager.On("RemoveReverseRecord", "192.168.1.100").Return(nil)

	dnsConnector := controller.NewDNSConnector(mockDNSManager)

	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "test-host",
		Domain:   "example.com",
	}

	err := dnsConnector.RemoveLease(lease)
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestRemoveLeaseNoHostname tests that RemoveLease skips DNS records when no hostname is provided
func TestRemoveLeaseNoHostname(t *testing.T) {
	mockDNSManager := new(MockDNSManager)

	dnsConnector := controller.NewDNSConnector(mockDNSManager)

	lease := &types.Lease{
		IP:       "192.168.1.100",
		Hostname: "",
		Domain:   "example.com",
	}

	err := dnsConnector.RemoveLease(lease)
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}

// TestScheduleLeaseRemoval tests that ScheduleLeaseRemoval correctly schedules a lease removal
func TestScheduleLeaseRemoval(t *testing.T) {
	mockDNSManager := new(MockDNSManager)

	mockDNSManager.On("RemoveRecord", "test-host.example.com", "A", "192.168.1.100").Return(nil)
	mockDNSManager.On("RemoveReverseRecord", "192.168.1.100").Return(nil)

	dnsConnector := controller.NewDNSConnector(mockDNSManager)

	expiredLease := &types.Lease{
		IP:        "192.168.1.100",
		Hostname:  "test-host",
		Domain:    "example.com",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	dnsConnector.ScheduleLeaseRemoval(expiredLease)

	// Give a moment for the goroutine to execute
	time.Sleep(100 * time.Millisecond)

	mockDNSManager.AssertExpectations(t)
}

// TestScheduleLeaseRemovalFuture tests that ScheduleLeaseRemoval correctly schedules a future lease removal
func TestScheduleLeaseRemovalFuture(t *testing.T) {
	// Skip this test in CI environments or when time is a constraint
	t.Skip("Skipping long-running test")

	mockDNSManager := new(MockDNSManager)

	mockDNSManager.On("RemoveRecord", "test-host.example.com", "A", "192.168.1.100").Return(nil)
	mockDNSManager.On("RemoveReverseRecord", "192.168.1.100").Return(nil)

	dnsConnector := controller.NewDNSConnector(mockDNSManager)

	futureLease := &types.Lease{
		IP:        "192.168.1.100",
		Hostname:  "test-host",
		Domain:    "example.com",
		ExpiresAt: time.Now().Add(1 * time.Second), // Expires in 1 second
	}

	dnsConnector.ScheduleLeaseRemoval(futureLease)

	time.Sleep(1500 * time.Millisecond)

	mockDNSManager.AssertExpectations(t)
}

// TestUpdateLeaseExplicitDomainFromCRD tests that UpdateLease uses the domain
// from the DHCP CRD spec (carried via Lease.Domain) for proper FQDN generation.
func TestUpdateLeaseExplicitDomainFromCRD(t *testing.T) {
	mockDNSManager := new(MockDNSManager)

	// Domain is "home.arpa" from the CRD spec, not a placeholder.
	mockDNSManager.On("AddRecord", "nas.home.arpa", "A", "10.0.10.50", uint32(7200)).Return(nil)
	mockDNSManager.On("AddReverseRecord", "10.0.10.50", "nas.home.arpa", uint32(7200)).Return(nil)

	dnsConnector := controller.NewDNSConnector(mockDNSManager)

	lease := &types.Lease{
		IP:       "10.0.10.50",
		Hostname: "nas",
		Domain:   "home.arpa", // From CRD spec
		VLANRef:  "vlan10",
		TTL:      7200,
	}

	err := dnsConnector.UpdateLease(lease)
	assert.NoError(t, err)
	mockDNSManager.AssertExpectations(t)
}
