package manager

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/GizmoTickler/fos1/pkg/dns/adguard"
	"github.com/GizmoTickler/fos1/pkg/dns/coredns"
	"github.com/GizmoTickler/fos1/pkg/dns/mdns"
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

func (m *MockCoreDNSController) AddRecord(zone, name, recordType, value string, ttl uint32) error {
	args := m.Called(zone, name, recordType, value, ttl)
	return args.Error(0)
}

func (m *MockCoreDNSController) RemoveRecord(zone, name, recordType, value string) error {
	args := m.Called(zone, name, recordType, value)
	return args.Error(0)
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

// Setup helper function
func setupTestManager(t *testing.T) (*Manager, *MockCoreDNSController, *MockAdGuardController, *MockMDNSController, kubernetes.Interface) {
	mockCoreDNS := new(MockCoreDNSController)
	mockAdGuard := new(MockAdGuardController)
	mockMDNS := new(MockMDNSController)
	
	// Setup mock expectations for Start()
	mockCoreDNS.On("Start").Return(nil)
	mockAdGuard.On("Start").Return(nil)
	mockMDNS.On("Start").Return(nil)
	
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
	
	// Setup expectations for AddRecord
	mockCoreDNS.On("AddRecord", "example.com", "www", "A", "192.168.1.1", uint32(3600)).Return(nil)
	
	// Test adding a record
	err := manager.AddRecord("www.example.com", "A", "192.168.1.1", 3600)
	assert.NoError(t, err)
	
	// Verify mock expectations
	mockCoreDNS.AssertExpectations(t)
}

// TestRemoveRecord tests the RemoveRecord function
func TestRemoveRecord(t *testing.T) {
	manager, mockCoreDNS, _, _, _ := setupTestManager(t)
	
	// Setup expectations for RemoveRecord
	mockCoreDNS.On("RemoveRecord", "example.com", "www", "A", "192.168.1.1").Return(nil)
	
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
	mockCoreDNS.On("AddRecord", "1.168.192.in-addr.arpa", "1", "PTR", "www.example.com", uint32(3600)).Return(nil)
	
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
	mockCoreDNS.On("RemoveRecord", "1.168.192.in-addr.arpa", "1", "PTR", mock.Anything).Return(nil)
	
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
	zone, name, err := manager.convertToReverseLookup("192.168.1.1")
	assert.NoError(t, err)
	assert.Equal(t, "1.168.192.in-addr.arpa", zone)
	assert.Equal(t, "1", name)
	
	// Test invalid IP
	_, _, err = manager.convertToReverseLookup("not-an-ip")
	assert.Error(t, err)
	
	// Test IPv6 conversion
	zone, name, err = manager.convertToReverseLookup("2001:db8::1")
	assert.NoError(t, err)
	assert.Contains(t, zone, "ip6.arpa")
	assert.Equal(t, "1", name)
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
