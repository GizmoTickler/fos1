package manager

import (
	"fmt"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/dns/adguard"
	"github.com/GizmoTickler/fos1/pkg/dns/coredns"
	"github.com/GizmoTickler/fos1/pkg/dns/mdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// Mock controllers
type MockCoreDNSController struct {
	mock.Mock
}

func (m *MockCoreDNSController) Start() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockCoreDNSController) Stop() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockCoreDNSController) Sync() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockCoreDNSController) Status() (*coredns.CoreDNSStatus, error) {
	args := m.Called()
	return args.Get(0).(*coredns.CoreDNSStatus), args.Error(1)
}

func (m *MockCoreDNSController) AddRecord(zone string, record *coredns.DNSRecord) error {
	args := m.Called(zone, record)
	return args.Error(0)
}

func (m *MockCoreDNSController) RemoveRecord(zone, name, recordType, value string) error {
	args := m.Called(zone, name, recordType, value)
	return args.Error(0)
}

func (m *MockCoreDNSController) AddPTRRecord(zone string, record *coredns.DNSRecord) error {
	args := m.Called(zone, record)
	return args.Error(0)
}

func (m *MockCoreDNSController) RemovePTRRecord(zone, name string) error {
	args := m.Called(zone, name)
	return args.Error(0)
}

func (m *MockCoreDNSController) UpdateZone(zone *coredns.Zone) error {
	args := m.Called(zone)
	return args.Error(0)
}

func (m *MockCoreDNSController) UpdatePTRZone(ptrZone *coredns.PTRZone) error {
	args := m.Called(ptrZone)
	return args.Error(0)
}

func (m *MockCoreDNSController) GetZone(name string) *coredns.Zone {
	args := m.Called(name)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*coredns.Zone)
}

func (m *MockCoreDNSController) ListZones() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

// Mock AdGuard controller
type MockAdGuardController struct {
	mock.Mock
}

func (m *MockAdGuardController) Start() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockAdGuardController) Stop() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockAdGuardController) Sync() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockAdGuardController) Status() (*adguard.AdGuardStatus, error) {
	args := m.Called()
	return args.Get(0).(*adguard.AdGuardStatus), args.Error(1)
}

func (m *MockAdGuardController) UpdateFilterList(name, url string, enabled bool) error {
	args := m.Called(name, url, enabled)
	return args.Error(0)
}

func (m *MockAdGuardController) RemoveFilterList(name string) error {
	args := m.Called(name)
	return args.Error(0)
}

func (m *MockAdGuardController) UpdateClientRule(clientID, clientName string, addresses []string, enabled bool, blockLists, allowLists []string) error {
	args := m.Called(clientID, clientName, addresses, enabled, blockLists, allowLists)
	return args.Error(0)
}

func (m *MockAdGuardController) RemoveClientRule(clientID string) error {
	args := m.Called(clientID)
	return args.Error(0)
}

// Mock mDNS controller
type MockMDNSController struct {
	mock.Mock
}

func (m *MockMDNSController) Start() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockMDNSController) Stop() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockMDNSController) Sync() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockMDNSController) Status() (*mdns.MDNSStatus, error) {
	args := m.Called()
	return args.Get(0).(*mdns.MDNSStatus), args.Error(1)
}

func (m *MockMDNSController) UpdateReflectionRule(name string, sourceVLANs, destinationVLANs []int, serviceTypes []string, enabled bool) error {
	args := m.Called(name, sourceVLANs, destinationVLANs, serviceTypes, enabled)
	return args.Error(0)
}

func (m *MockMDNSController) RemoveReflectionRule(name string) error {
	args := m.Called(name)
	return args.Error(0)
}

func (m *MockMDNSController) EnableReflection(enabled bool) error {
	args := m.Called(enabled)
	return args.Error(0)
}

// Setup helper function
func setupTestManager(t *testing.T) (*Manager, *MockCoreDNSController, *MockAdGuardController, *MockMDNSController, kubernetes.Interface) {
	mockCoreDNS := new(MockCoreDNSController)
	mockAdGuard := new(MockAdGuardController)
	mockMDNS := new(MockMDNSController)

	// Create a fake k8s client
	fakeClient := fake.NewSimpleClientset()

	// Create test config that disables most features to simplify testing
	config := &Config{
		EnableDHCPIntegration: false,
		MetricsEnabled:        false,
		APIEnabled:            false,
		ResyncPeriod:          time.Second * 5,
	}

	// Create manager with mocks
	manager, err := NewManager(fakeClient, mockCoreDNS, mockAdGuard, mockMDNS, config)
	assert.NoError(t, err)
	assert.NotNil(t, manager)

	return manager, mockCoreDNS, mockAdGuard, mockMDNS, fakeClient
}

// TestNewManager tests the NewManager function
func TestNewManager(t *testing.T) {
	// Test with nil client
	manager, err := NewManager(nil, nil, nil, nil, nil)
	assert.Error(t, err)
	assert.Nil(t, manager)

	// Test with valid client
	fakeClient := fake.NewSimpleClientset()
	manager, err = NewManager(fakeClient, nil, nil, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, manager)

	// Test with nil config (should use defaults)
	manager, err = NewManager(fakeClient, nil, nil, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, manager)

	// Test with config
	config := &Config{
		EnableDHCPIntegration: true,
		MetricsEnabled:        true,
		APIEnabled:            true,
		ResyncPeriod:          time.Minute * 10,
	}
	manager, err = NewManager(fakeClient, nil, nil, nil, config)
	assert.NoError(t, err)
	assert.NotNil(t, manager)
}

// TestManagerStart tests the Start function
func TestManagerStart(t *testing.T) {
	manager, mockCoreDNS, mockAdGuard, mockMDNS, _ := setupTestManager(t)

	// Setup expectations for Start methods
	mockCoreDNS.On("Start").Return(nil)
	mockAdGuard.On("Start").Return(nil)
	mockMDNS.On("Start").Return(nil)

	// Start the manager
	err := manager.Start()
	assert.NoError(t, err)

	// Verify mock expectations
	mockCoreDNS.AssertExpectations(t)
	mockAdGuard.AssertExpectations(t)
	mockMDNS.AssertExpectations(t)
}

// TestManagerStop tests the Stop function
func TestManagerStop(t *testing.T) {
	manager, mockCoreDNS, mockAdGuard, mockMDNS, _ := setupTestManager(t)

	// Setup expectations for Stop methods
	mockCoreDNS.On("Stop").Return(nil)
	mockAdGuard.On("Stop").Return(nil)
	mockMDNS.On("Stop").Return(nil)

	// Stop the manager
	manager.Stop()

	// Verify mock expectations
	mockCoreDNS.AssertExpectations(t)
	mockAdGuard.AssertExpectations(t)
	mockMDNS.AssertExpectations(t)
}

// TestAddRecord tests the AddRecord function
func TestAddRecord(t *testing.T) {
	manager, mockCoreDNS, _, _, _ := setupTestManager(t)

	// findZoneForRecord calls ListZones; "www.example.com" doesn't match "local"
	// so it falls back to the default "local" zone.
	mockCoreDNS.On("ListZones").Return([]string{"local"})

	// Setup expectations for AddRecord
	mockCoreDNS.On("AddRecord", "local", &coredns.DNSRecord{
		Name: "www.example.com", Type: "A", Value: "192.168.1.1", TTL: 3600, Dynamic: true,
	}).Return(nil)

	// Test adding a record
	err := manager.AddRecord("www.example.com", "A", "192.168.1.1", 3600)
	assert.NoError(t, err)

	// Verify mock expectations
	mockCoreDNS.AssertExpectations(t)
}

// TestRemoveRecord tests the RemoveRecord function
func TestRemoveRecord(t *testing.T) {
	manager, mockCoreDNS, _, _, _ := setupTestManager(t)

	// findZoneForRecord calls ListZones; no match so default "local" zone.
	mockCoreDNS.On("ListZones").Return([]string{"local"})

	// Setup expectations for RemoveRecord
	mockCoreDNS.On("RemoveRecord", "local", "www.example.com", "A", "192.168.1.1").Return(nil)

	// Test removing a record
	err := manager.RemoveRecord("www.example.com", "A", "192.168.1.1")
	assert.NoError(t, err)

	// Verify mock expectations
	mockCoreDNS.AssertExpectations(t)
}

// TestAddReverseRecord tests the AddReverseRecord function
func TestAddReverseRecord(t *testing.T) {
	manager, mockCoreDNS, _, _, _ := setupTestManager(t)

	// Setup expectations for AddRecord for reverse lookup
	mockCoreDNS.On("AddPTRRecord", "in-addr.arpa", &coredns.DNSRecord{
		Name: "1.1.168.192", Type: "PTR", Value: "www.example.com", TTL: 3600, Dynamic: true,
	}).Return(nil)

	// Test adding a reverse record
	err := manager.AddReverseRecord("192.168.1.1", "www.example.com", 3600)
	assert.NoError(t, err)

	// Verify mock expectations
	mockCoreDNS.AssertExpectations(t)
}

// TestRemoveReverseRecord tests the RemoveReverseRecord function
func TestRemoveReverseRecord(t *testing.T) {
	manager, mockCoreDNS, _, _, _ := setupTestManager(t)

	// Setup expectations for RemoveRecord for reverse lookup
	mockCoreDNS.On("RemovePTRRecord", "in-addr.arpa", "1.1.168.192").Return(nil)

	// Test removing a reverse record
	err := manager.RemoveReverseRecord("192.168.1.1")
	assert.NoError(t, err)

	// Verify mock expectations
	mockCoreDNS.AssertExpectations(t)
}

// TestConvertToReverseLookup tests the convertToReverseLookup function
func TestConvertToReverseLookup(t *testing.T) {
	manager, _, _, _, _ := setupTestManager(t)

	// Test IPv4 conversion
	name, zone, err := manager.convertToReverseLookup("192.168.1.1")
	assert.NoError(t, err)
	assert.Equal(t, "1.1.168.192", name)
	assert.Equal(t, "in-addr.arpa", zone)

	// Test invalid IP
	_, _, err = manager.convertToReverseLookup("not-an-ip")
	assert.Error(t, err)

	// Test IPv6 conversion
	name, zone, err = manager.convertToReverseLookup("2001:db8::1")
	assert.NoError(t, err)
	assert.Contains(t, name, "ip6.arpa")
	assert.Contains(t, zone, "ip6.arpa")
}

// TestSync tests the Sync function
func TestSync(t *testing.T) {
	manager, mockCoreDNS, mockAdGuard, mockMDNS, _ := setupTestManager(t)

	// Setup expectations for Sync methods
	mockCoreDNS.On("Sync").Return(nil)
	mockAdGuard.On("Sync").Return(nil)
	mockMDNS.On("Sync").Return(nil)

	// Test syncing
	err := manager.Sync()
	assert.NoError(t, err)

	// Verify mock expectations
	mockCoreDNS.AssertExpectations(t)
	mockAdGuard.AssertExpectations(t)
	mockMDNS.AssertExpectations(t)
}

// TestUpdateDNSZone verifies that UpdateDNSZone converts the manager zone to
// a CoreDNS zone and delegates to the CoreDNS controller.
func TestUpdateDNSZone(t *testing.T) {
	manager, mockCoreDNS, _, _, _ := setupTestManager(t)

	zone := &DNSZone{
		Name:   "example.com",
		Domain: "example.com",
		TTL:    3600,
		SOA: &SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2025010101,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minimum: 3600,
		},
		Records: []*DNSRecord{
			{Name: "www", Type: "A", Value: "10.0.0.1", TTL: 300},
			{Name: "mail", Type: "A", Value: "10.0.0.2", TTL: 300},
		},
	}

	// Expect the CoreDNS controller to receive an UpdateZone call with a matching zone
	mockCoreDNS.On("UpdateZone", mock.MatchedBy(func(z *coredns.Zone) bool {
		return z.Domain == "example.com" &&
			len(z.Records) == 2 &&
			z.SOA != nil &&
			z.SOA.Serial == 2025010101
	})).Return(nil)

	err := manager.UpdateDNSZone(zone)
	assert.NoError(t, err)

	mockCoreDNS.AssertExpectations(t)

	// Verify zone is cached locally
	manager.mutex.RLock()
	cached, ok := manager.zones["example.com"]
	manager.mutex.RUnlock()
	assert.True(t, ok)
	assert.Equal(t, "example.com", cached.Domain)
}

// TestUpdateDNSZone_NilController verifies the error when CoreDNS controller is nil.
func TestUpdateDNSZone_NilController(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	config := &Config{EnableDHCPIntegration: false, MetricsEnabled: false, APIEnabled: false}
	manager, err := NewManager(fakeClient, nil, nil, nil, config)
	assert.NoError(t, err)

	err = manager.UpdateDNSZone(&DNSZone{Name: "test", Domain: "test"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CoreDNS controller not initialized")
}

// TestUpdateDNSZone_NilZone verifies the error when zone is nil.
func TestUpdateDNSZone_NilZone(t *testing.T) {
	manager, _, _, _, _ := setupTestManager(t)
	err := manager.UpdateDNSZone(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "zone is nil")
}

// TestUpdatePTRZone verifies that UpdatePTRZone converts and delegates to
// the CoreDNS controller.
func TestUpdatePTRZone(t *testing.T) {
	manager, mockCoreDNS, _, _, _ := setupTestManager(t)

	ptrZone := &PTRZone{
		Name:    "1.168.192.in-addr.arpa",
		Network: "192.168.1.0/24",
		TTL:     3600,
		Records: []*DNSRecord{
			{Name: "10", Type: "PTR", Value: "host10.example.com.", TTL: 3600},
		},
	}

	mockCoreDNS.On("UpdatePTRZone", mock.MatchedBy(func(z *coredns.PTRZone) bool {
		return z.Name == "1.168.192.in-addr.arpa" &&
			z.Network == "192.168.1.0/24" &&
			len(z.Records) == 1
	})).Return(nil)

	err := manager.UpdatePTRZone(ptrZone)
	assert.NoError(t, err)
	mockCoreDNS.AssertExpectations(t)
}

// TestUpdatePTRZone_NilZone verifies the error when PTR zone is nil.
func TestUpdatePTRZone_NilZone(t *testing.T) {
	manager, _, _, _, _ := setupTestManager(t)
	err := manager.UpdatePTRZone(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PTR zone is nil")
}

// TestUpdateDNSFilters verifies that UpdateDNSFilters calls the AdGuard
// controller's UpdateFilterList for each custom list.
func TestUpdateDNSFilters(t *testing.T) {
	manager, _, mockAdGuard, _, _ := setupTestManager(t)

	filters := &DNSFilterList{
		Name:    "test-filters",
		Enabled: true,
		CustomLists: []CustomFilterList{
			{Name: "blocklist-1", URL: "https://example.com/list1.txt", Enabled: true},
			{Name: "blocklist-2", URL: "https://example.com/list2.txt", Enabled: false},
		},
	}

	mockAdGuard.On("UpdateFilterList", "blocklist-1", "https://example.com/list1.txt", true).Return(nil)
	mockAdGuard.On("UpdateFilterList", "blocklist-2", "https://example.com/list2.txt", false).Return(nil)

	err := manager.UpdateDNSFilters(filters)
	assert.NoError(t, err)
	mockAdGuard.AssertExpectations(t)
}

// TestUpdateDNSFilters_NilFilters verifies the error when filters is nil.
func TestUpdateDNSFilters_NilFilters(t *testing.T) {
	manager, _, _, _, _ := setupTestManager(t)
	err := manager.UpdateDNSFilters(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "filters is nil")
}

// TestUpdateDNSFilters_ControllerError verifies error propagation from the
// AdGuard controller.
func TestUpdateDNSFilters_ControllerError(t *testing.T) {
	manager, _, mockAdGuard, _, _ := setupTestManager(t)

	filters := &DNSFilterList{
		Name: "test",
		CustomLists: []CustomFilterList{
			{Name: "bad-list", URL: "https://example.com/bad.txt", Enabled: true},
		},
	}

	mockAdGuard.On("UpdateFilterList", "bad-list", "https://example.com/bad.txt", true).Return(fmt.Errorf("connection refused"))

	err := manager.UpdateDNSFilters(filters)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

// TestUpdateDNSClient verifies that UpdateDNSClient calls the AdGuard
// controller's UpdateClientRule with the correct parameters.
func TestUpdateDNSClient(t *testing.T) {
	manager, _, mockAdGuard, _, _ := setupTestManager(t)

	client := &DNSClient{
		Name:        "test-client",
		Description: "Test device",
		Identifiers: []ClientIdentifier{
			{Type: "ip", Value: "192.168.1.100"},
			{Type: "mac", Value: "aa:bb:cc:dd:ee:ff"},
		},
		Filtering: FilteringOptions{
			Enabled:    true,
			BlockLists: []string{"ads", "malware"},
			Exceptions: []string{"example.com"},
		},
	}

	mockAdGuard.On("UpdateClientRule",
		"test-client",
		"Test device",
		[]string{"192.168.1.100", "aa:bb:cc:dd:ee:ff"},
		true,
		[]string{"ads", "malware"},
		[]string{"example.com"},
	).Return(nil)

	err := manager.UpdateDNSClient(client)
	assert.NoError(t, err)
	mockAdGuard.AssertExpectations(t)
}

// TestUpdateDNSClient_NilClient verifies the error when client is nil.
func TestUpdateDNSClient_NilClient(t *testing.T) {
	manager, _, _, _, _ := setupTestManager(t)
	err := manager.UpdateDNSClient(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client is nil")
}

// TestUpdateMDNSReflection verifies that UpdateMDNSReflection calls
// EnableReflection and UpdateReflectionRule on the mDNS controller.
func TestUpdateMDNSReflection(t *testing.T) {
	manager, _, _, mockMDNS, _ := setupTestManager(t)

	reflection := &MDNSReflection{
		Name:    "test-reflection",
		Enabled: true,
		ReflectionRules: []ReflectionRule{
			{
				Name:             "iot-to-main",
				SourceVLANs:      []int{10},
				DestinationVLANs: []int{20, 30},
				ServiceTypes:     []string{"_airplay._tcp"},
			},
			{
				Name:             "guest-to-main",
				SourceVLANs:      []int{40},
				DestinationVLANs: []int{20},
				ServiceTypes:     []string{"_googlecast._tcp"},
			},
		},
	}

	mockMDNS.On("EnableReflection", true).Return(nil)
	mockMDNS.On("UpdateReflectionRule",
		"iot-to-main", []int{10}, []int{20, 30}, []string{"_airplay._tcp"}, true,
	).Return(nil)
	mockMDNS.On("UpdateReflectionRule",
		"guest-to-main", []int{40}, []int{20}, []string{"_googlecast._tcp"}, true,
	).Return(nil)

	err := manager.UpdateMDNSReflection(reflection)
	assert.NoError(t, err)
	mockMDNS.AssertExpectations(t)
}

// TestUpdateMDNSReflection_NilReflection verifies the error when reflection is nil.
func TestUpdateMDNSReflection_NilReflection(t *testing.T) {
	manager, _, _, _, _ := setupTestManager(t)
	err := manager.UpdateMDNSReflection(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reflection is nil")
}

// TestUpdateMDNSReflection_EnableError verifies error propagation from
// EnableReflection.
func TestUpdateMDNSReflection_EnableError(t *testing.T) {
	manager, _, _, mockMDNS, _ := setupTestManager(t)

	reflection := &MDNSReflection{
		Name:    "test",
		Enabled: true,
	}

	mockMDNS.On("EnableReflection", true).Return(fmt.Errorf("permission denied"))

	err := manager.UpdateMDNSReflection(reflection)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

// TestFindZoneForRecord_MatchesCachedZone verifies that findZoneForRecord
// returns a cached zone when the record name matches.
func TestFindZoneForRecord_MatchesCachedZone(t *testing.T) {
	manager, mockCoreDNS, _, _, _ := setupTestManager(t)

	// Pre-populate the zone cache
	manager.zones["example.com"] = &DNSZone{
		Name:   "example.com",
		Domain: "example.com",
		TTL:    3600,
	}

	mockCoreDNS.On("ListZones").Return([]string{})

	zone, err := manager.findZoneForRecord("www.example.com")
	assert.NoError(t, err)
	assert.Equal(t, "example.com", zone.Domain)
}

// TestFindZoneForRecord_QueriesCoreDNS verifies that findZoneForRecord
// falls back to the CoreDNS controller when no cache hit.
func TestFindZoneForRecord_QueriesCoreDNS(t *testing.T) {
	manager, mockCoreDNS, _, _, _ := setupTestManager(t)

	mockCoreDNS.On("ListZones").Return([]string{"myzone.local"})
	mockCoreDNS.On("GetZone", "myzone.local").Return(&coredns.Zone{
		Name:   "myzone.local",
		Domain: "myzone.local",
		Records: []*coredns.DNSRecord{
			{Name: "host1", Type: "A", Value: "10.0.0.1", TTL: 300},
		},
	})

	zone, err := manager.findZoneForRecord("host1.myzone.local")
	assert.NoError(t, err)
	assert.Equal(t, "myzone.local", zone.Domain)
	assert.Len(t, zone.Records, 1)
	mockCoreDNS.AssertExpectations(t)
}

// TestFindZoneForRecord_LongestMatch verifies that the longest matching zone
// is selected when multiple zones could match.
func TestFindZoneForRecord_LongestMatch(t *testing.T) {
	manager, mockCoreDNS, _, _, _ := setupTestManager(t)

	manager.zones["local"] = &DNSZone{Name: "local", Domain: "local"}
	manager.zones["home.local"] = &DNSZone{Name: "home.local", Domain: "home.local"}

	mockCoreDNS.On("ListZones").Return([]string{})

	zone, err := manager.findZoneForRecord("host.home.local")
	assert.NoError(t, err)
	assert.Equal(t, "home.local", zone.Domain)
}

// TestFindZoneForRecord_DefaultFallback verifies that findZoneForRecord
// returns the default "local" zone when no zone matches.
func TestFindZoneForRecord_DefaultFallback(t *testing.T) {
	manager, mockCoreDNS, _, _, _ := setupTestManager(t)

	mockCoreDNS.On("ListZones").Return([]string{})

	zone, err := manager.findZoneForRecord("unknown.domain.org")
	assert.NoError(t, err)
	assert.Equal(t, "local", zone.Domain)
}
