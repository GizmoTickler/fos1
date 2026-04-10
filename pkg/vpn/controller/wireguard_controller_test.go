package controller

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"

	"github.com/GizmoTickler/fos1/pkg/vpn"
)

// ---------------------------------------------------------------------------
// Mock WireGuardManager
// ---------------------------------------------------------------------------

type mockWireGuardManager struct {
	vpns      map[string]*vpn.WireGuardVPN
	createErr error
	updateErr error
	deleteErr error
	statusErr error

	createdVPNs []string
	updatedVPNs []string
	deletedVPNs []string
}

func newMockWireGuardManager() *mockWireGuardManager {
	return &mockWireGuardManager{
		vpns: make(map[string]*vpn.WireGuardVPN),
	}
}

func (m *mockWireGuardManager) CreateVPN(v *vpn.WireGuardVPN) error {
	if m.createErr != nil {
		return m.createErr
	}
	if _, exists := m.vpns[v.Name]; exists {
		return fmt.Errorf("VPN %s already exists", v.Name)
	}
	m.vpns[v.Name] = v
	m.createdVPNs = append(m.createdVPNs, v.Name)
	return nil
}

func (m *mockWireGuardManager) UpdateVPN(v *vpn.WireGuardVPN) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, exists := m.vpns[v.Name]; !exists {
		return fmt.Errorf("VPN %s does not exist", v.Name)
	}
	m.vpns[v.Name] = v
	m.updatedVPNs = append(m.updatedVPNs, v.Name)
	return nil
}

func (m *mockWireGuardManager) DeleteVPN(name string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deletedVPNs = append(m.deletedVPNs, name)
	delete(m.vpns, name)
	return nil
}

func (m *mockWireGuardManager) GetVPNStatus(name string) (*vpn.Status, error) {
	if m.statusErr != nil {
		return nil, m.statusErr
	}
	v, exists := m.vpns[name]
	if !exists {
		return nil, fmt.Errorf("VPN %s does not exist", name)
	}
	return &vpn.Status{
		Phase:          "Running",
		PublicKey:      "test-public-key",
		ConnectedPeers: len(v.Peers),
		LastHandshake:  time.Now().Add(-10 * time.Second),
		TransferRx:     1024,
		TransferTx:     2048,
		Conditions: []vpn.Condition{
			{
				Type:               "Peer",
				Status:             "True",
				Reason:             "peer-pub-key",
				Message:            "Endpoint: 10.0.0.1:51820",
				LastTransitionTime: time.Now().Add(-10 * time.Second),
			},
		},
	}, nil
}

func (m *mockWireGuardManager) GetPeerStatus(vpnName, peerPublicKey string) (*vpn.PeerStatus, error) {
	return &vpn.PeerStatus{
		PublicKey: peerPublicKey,
		Connected: true,
	}, nil
}

func (m *mockWireGuardManager) RotateKeys(name string) error {
	return nil
}

// ---------------------------------------------------------------------------
// Helper: build unstructured CRD objects
// ---------------------------------------------------------------------------

func makeWireGuardCRD(name, namespace string, spec map[string]interface{}) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "vpn.fos1.io/v1alpha1",
			"kind":       "WireGuardInterface",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": spec,
		},
	}
	return obj
}

func minimalSpec() map[string]interface{} {
	return map[string]interface{}{
		"interfaceName": "wg0",
		"address":       "10.10.10.1/24",
		"listenPort":    float64(51820),
		"privateKey":    "test-private-key",
	}
}

func fullSpec() map[string]interface{} {
	return map[string]interface{}{
		"interfaceName": "wg0",
		"address":       "10.10.10.1/24",
		"listenPort":    float64(51820),
		"privateKey":    "test-private-key",
		"mtu":           float64(1420),
		"enabled":       true,
		"postUp": []interface{}{
			"iptables -A FORWARD -i %i -j ACCEPT",
		},
		"postDown": []interface{}{
			"iptables -D FORWARD -i %i -j ACCEPT",
		},
		"peers": []interface{}{
			map[string]interface{}{
				"publicKey":           "peer-pub-key-1",
				"endpoint":            "10.0.0.1:51820",
				"persistentKeepalive": float64(25),
				"allowedIPs":          []interface{}{"10.0.0.0/24", "192.168.1.0/24"},
				"description":         "Remote Office 1",
			},
			map[string]interface{}{
				"publicKey":  "peer-pub-key-2",
				"allowedIPs": []interface{}{"10.0.1.0/24"},
				"presharedKey": "test-psk",
			},
		},
		"routing": map[string]interface{}{
			"defaultRoute": false,
			"allowedIPs":   []interface{}{"192.168.0.0/16"},
			"metric":       float64(100),
		},
		"monitoring": map[string]interface{}{
			"enabled":  true,
			"metrics":  true,
			"logging":  true,
			"logLevel": "info",
		},
	}
}

// ---------------------------------------------------------------------------
// Tests: convertToInternalWireGuardVPN
// ---------------------------------------------------------------------------

func TestConvertToInternalWireGuardVPN_MinimalSpec(t *testing.T) {
	crd := makeWireGuardCRD("test-vpn", "default", minimalSpec())

	wgVPN, err := convertToInternalWireGuardVPN(crd)
	require.NoError(t, err)

	assert.Equal(t, "test-vpn", wgVPN.Name)
	assert.True(t, wgVPN.Enabled) // defaults to true
	assert.Equal(t, "wg0", wgVPN.Interface.Name)
	assert.Equal(t, "test-private-key", wgVPN.Interface.PrivateKey)
	assert.Equal(t, 51820, wgVPN.Interface.ListenPort)
	assert.Equal(t, []string{"10.10.10.1/24"}, wgVPN.Interface.Addresses)
	assert.Empty(t, wgVPN.Peers)
}

func TestConvertToInternalWireGuardVPN_FullSpec(t *testing.T) {
	crd := makeWireGuardCRD("full-vpn", "vpn-ns", fullSpec())

	wgVPN, err := convertToInternalWireGuardVPN(crd)
	require.NoError(t, err)

	assert.Equal(t, "full-vpn", wgVPN.Name)
	assert.True(t, wgVPN.Enabled)
	assert.Equal(t, "wg0", wgVPN.Interface.Name)
	assert.Equal(t, 51820, wgVPN.Interface.ListenPort)
	assert.Equal(t, 1420, wgVPN.Interface.MTU)
	assert.Equal(t, []string{"10.10.10.1/24"}, wgVPN.Interface.Addresses)

	// PostUp/PostDown
	require.Len(t, wgVPN.Interface.PostUp, 1)
	assert.Equal(t, "iptables -A FORWARD -i %i -j ACCEPT", wgVPN.Interface.PostUp[0])
	require.Len(t, wgVPN.Interface.PostDown, 1)
	assert.Equal(t, "iptables -D FORWARD -i %i -j ACCEPT", wgVPN.Interface.PostDown[0])

	// Peers
	require.Len(t, wgVPN.Peers, 2)

	assert.Equal(t, "peer-pub-key-1", wgVPN.Peers[0].PublicKey)
	assert.Equal(t, "10.0.0.1:51820", wgVPN.Peers[0].Endpoint)
	assert.Equal(t, 25, wgVPN.Peers[0].PersistentKeepalive)
	assert.Equal(t, []string{"10.0.0.0/24", "192.168.1.0/24"}, wgVPN.Peers[0].AllowedIPs)
	assert.Equal(t, "Remote Office 1", wgVPN.Peers[0].Description)

	assert.Equal(t, "peer-pub-key-2", wgVPN.Peers[1].PublicKey)
	assert.Equal(t, "test-psk", wgVPN.Peers[1].PresharedKey)
	assert.Equal(t, []string{"10.0.1.0/24"}, wgVPN.Peers[1].AllowedIPs)

	// Routing
	assert.False(t, wgVPN.Routing.DefaultRoute)
	assert.Equal(t, []string{"192.168.0.0/16"}, wgVPN.Routing.AllowedIPs)
	assert.Equal(t, 100, wgVPN.Routing.Metric)

	// Monitoring
	assert.True(t, wgVPN.Monitoring.Enabled)
	assert.True(t, wgVPN.Monitoring.Metrics)
	assert.True(t, wgVPN.Monitoring.Logging)
	assert.Equal(t, "info", wgVPN.Monitoring.LogLevel)
}

func TestConvertToInternalWireGuardVPN_DisabledVPN(t *testing.T) {
	spec := minimalSpec()
	spec["enabled"] = false
	crd := makeWireGuardCRD("disabled-vpn", "default", spec)

	wgVPN, err := convertToInternalWireGuardVPN(crd)
	require.NoError(t, err)
	assert.False(t, wgVPN.Enabled)
}

func TestConvertToInternalWireGuardVPN_MissingInterfaceName(t *testing.T) {
	spec := map[string]interface{}{
		"address":    "10.10.10.1/24",
		"privateKey": "key",
	}
	crd := makeWireGuardCRD("bad-vpn", "default", spec)

	_, err := convertToInternalWireGuardVPN(crd)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "interfaceName is required")
}

func TestConvertToInternalWireGuardVPN_MissingAddress(t *testing.T) {
	spec := map[string]interface{}{
		"interfaceName": "wg0",
		"privateKey":    "key",
	}
	crd := makeWireGuardCRD("bad-vpn", "default", spec)

	_, err := convertToInternalWireGuardVPN(crd)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address is required")
}

func TestConvertToInternalWireGuardVPN_MissingSpec(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "vpn.fos1.io/v1alpha1",
			"kind":       "WireGuardInterface",
			"metadata": map[string]interface{}{
				"name":      "bad-vpn",
				"namespace": "default",
			},
		},
	}

	_, err := convertToInternalWireGuardVPN(obj)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "spec not found")
}

func TestConvertToInternalWireGuardVPN_NotUnstructured(t *testing.T) {
	_, err := convertToInternalWireGuardVPN("not an unstructured object")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an Unstructured type")
}

func TestConvertToInternalWireGuardVPN_PrivateKeyFromSecret(t *testing.T) {
	spec := map[string]interface{}{
		"interfaceName": "wg0",
		"address":       "10.10.10.1/24",
		"privateKeySecret": map[string]interface{}{
			"name": "wg-secret",
			"key":  "privateKey",
		},
	}
	crd := makeWireGuardCRD("secret-vpn", "default", spec)

	wgVPN, err := convertToInternalWireGuardVPN(crd)
	require.NoError(t, err)
	assert.Equal(t, "secret:wg-secret/privateKey", wgVPN.Interface.PrivateKey)
}

func TestConvertToInternalWireGuardVPN_DirectPrivateKeyOverridesSecret(t *testing.T) {
	spec := map[string]interface{}{
		"interfaceName": "wg0",
		"address":       "10.10.10.1/24",
		"privateKeySecret": map[string]interface{}{
			"name": "wg-secret",
			"key":  "privateKey",
		},
		"privateKey": "direct-key",
	}
	crd := makeWireGuardCRD("override-vpn", "default", spec)

	wgVPN, err := convertToInternalWireGuardVPN(crd)
	require.NoError(t, err)
	assert.Equal(t, "direct-key", wgVPN.Interface.PrivateKey)
}

func TestConvertToInternalWireGuardVPN_InvalidPeerSkipped(t *testing.T) {
	spec := minimalSpec()
	spec["peers"] = []interface{}{
		map[string]interface{}{
			// Missing publicKey -- should be skipped
			"endpoint": "10.0.0.1:51820",
		},
		map[string]interface{}{
			"publicKey":  "valid-key",
			"allowedIPs": []interface{}{"10.0.0.0/24"},
		},
	}
	crd := makeWireGuardCRD("partial-peers", "default", spec)

	wgVPN, err := convertToInternalWireGuardVPN(crd)
	require.NoError(t, err)
	// Only the valid peer should be present
	require.Len(t, wgVPN.Peers, 1)
	assert.Equal(t, "valid-key", wgVPN.Peers[0].PublicKey)
}

func TestConvertToInternalWireGuardVPN_IntegerListenPort(t *testing.T) {
	// Some JSON decoders might produce int64 instead of float64
	spec := map[string]interface{}{
		"interfaceName": "wg0",
		"address":       "10.10.10.1/24",
		"listenPort":    int64(51820),
		"privateKey":    "key",
		"mtu":           int64(1400),
	}
	crd := makeWireGuardCRD("int-port", "default", spec)

	wgVPN, err := convertToInternalWireGuardVPN(crd)
	require.NoError(t, err)
	assert.Equal(t, 51820, wgVPN.Interface.ListenPort)
	assert.Equal(t, 1400, wgVPN.Interface.MTU)
}

// ---------------------------------------------------------------------------
// Tests: parsePeerConfig
// ---------------------------------------------------------------------------

func TestParsePeerConfig_Valid(t *testing.T) {
	peerMap := map[string]interface{}{
		"publicKey":           "pub-key",
		"endpoint":            "10.0.0.1:51820",
		"persistentKeepalive": float64(25),
		"allowedIPs":          []interface{}{"10.0.0.0/24"},
		"description":         "test peer",
		"presharedKey":        "psk-value",
	}

	peer, err := parsePeerConfig(peerMap)
	require.NoError(t, err)
	assert.Equal(t, "pub-key", peer.PublicKey)
	assert.Equal(t, "10.0.0.1:51820", peer.Endpoint)
	assert.Equal(t, 25, peer.PersistentKeepalive)
	assert.Equal(t, []string{"10.0.0.0/24"}, peer.AllowedIPs)
	assert.Equal(t, "test peer", peer.Description)
	assert.Equal(t, "psk-value", peer.PresharedKey)
}

func TestParsePeerConfig_MissingPublicKey(t *testing.T) {
	peerMap := map[string]interface{}{
		"endpoint": "10.0.0.1:51820",
	}

	_, err := parsePeerConfig(peerMap)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "publicKey is required")
}

func TestParsePeerConfig_PresharedKeyFromSecret(t *testing.T) {
	peerMap := map[string]interface{}{
		"publicKey": "pub-key",
		"presharedKeySecret": map[string]interface{}{
			"name": "psk-secret",
			"key":  "psk",
		},
	}

	peer, err := parsePeerConfig(peerMap)
	require.NoError(t, err)
	assert.Equal(t, "secret:psk-secret/psk", peer.PresharedKey)
}

func TestParsePeerConfig_IntegerKeepalive(t *testing.T) {
	peerMap := map[string]interface{}{
		"publicKey":           "pub-key",
		"persistentKeepalive": int64(30),
	}

	peer, err := parsePeerConfig(peerMap)
	require.NoError(t, err)
	assert.Equal(t, 30, peer.PersistentKeepalive)
}

// ---------------------------------------------------------------------------
// Tests: extractStringSlice
// ---------------------------------------------------------------------------

func TestExtractStringSlice(t *testing.T) {
	m := map[string]interface{}{
		"items":   []interface{}{"a", "b", "c"},
		"empty":   []interface{}{},
		"mixed":   []interface{}{"a", float64(1), "b"},
		"notList": "single",
	}

	assert.Equal(t, []string{"a", "b", "c"}, extractStringSlice(m, "items"))
	assert.Equal(t, []string{}, extractStringSlice(m, "empty"))
	assert.Equal(t, []string{"a", "b"}, extractStringSlice(m, "mixed"))
	assert.Nil(t, extractStringSlice(m, "notList"))
	assert.Nil(t, extractStringSlice(m, "missing"))
}

// ---------------------------------------------------------------------------
// Tests: controller reconciliation via syncWireGuardVPN
// ---------------------------------------------------------------------------

// fakeInformer is a minimal implementation for indexer-based lookup in tests.
type fakeIndexer struct {
	objects map[string]interface{}
}

func newFakeIndexer() *fakeIndexer {
	return &fakeIndexer{objects: make(map[string]interface{})}
}

func (f *fakeIndexer) Add(obj interface{}) error { return nil }
func (f *fakeIndexer) Update(obj interface{}) error { return nil }
func (f *fakeIndexer) Delete(obj interface{}) error { return nil }
func (f *fakeIndexer) List() []interface{} {
	result := make([]interface{}, 0, len(f.objects))
	for _, v := range f.objects {
		result = append(result, v)
	}
	return result
}
func (f *fakeIndexer) ListKeys() []string {
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	return keys
}
func (f *fakeIndexer) Get(obj interface{}) (interface{}, bool, error)                    { return nil, false, nil }
func (f *fakeIndexer) GetByKey(key string) (interface{}, bool, error) {
	obj, ok := f.objects[key]
	return obj, ok, nil
}
func (f *fakeIndexer) Replace(list []interface{}, resourceVersion string) error { return nil }
func (f *fakeIndexer) Resync() error                                            { return nil }
func (f *fakeIndexer) ListIndexFuncValues(indexName string) []string             { return nil }
func (f *fakeIndexer) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	return nil, nil
}
func (f *fakeIndexer) GetIndexers() cache.Indexers                                { return nil }
func (f *fakeIndexer) AddIndexers(newIndexers cache.Indexers) error               { return nil }
func (f *fakeIndexer) IndexKeys(indexName, indexedValue string) ([]string, error)  { return nil, nil }
func (f *fakeIndexer) Index(indexName string, obj interface{}) ([]interface{}, error) { return nil, nil }

// fakeInformerWithIndexer wraps a fakeIndexer to satisfy cache.SharedIndexInformer
// for the subset of methods used by the controller.
type fakeInformerWithIndexer struct {
	cache.SharedIndexInformer // embed to get method signatures
	indexer                   *fakeIndexer
}

func (fi *fakeInformerWithIndexer) GetIndexer() cache.Indexer {
	return fi.indexer
}

func (fi *fakeInformerWithIndexer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	return nil, nil
}

func (fi *fakeInformerWithIndexer) HasSynced() bool {
	return true
}

func newTestController(mgr *mockWireGuardManager, indexer *fakeIndexer) *WireGuardController {
	inf := &fakeInformerWithIndexer{indexer: indexer}
	return &WireGuardController{
		wgManager: mgr,
		informer:  inf,
		workers:   1,
	}
}

func TestSyncWireGuardVPN_CreateNew(t *testing.T) {
	mgr := newMockWireGuardManager()
	idx := newFakeIndexer()
	ctrl := newTestController(mgr, idx)

	crd := makeWireGuardCRD("my-vpn", "default", minimalSpec())
	idx.objects["default/my-vpn"] = crd

	err := ctrl.syncWireGuardVPN(t.Context(), "default/my-vpn")
	require.NoError(t, err)

	// Should have created the VPN
	require.Contains(t, mgr.createdVPNs, "my-vpn")
	assert.NotNil(t, mgr.vpns["my-vpn"])
	assert.Equal(t, "wg0", mgr.vpns["my-vpn"].Interface.Name)
}

func TestSyncWireGuardVPN_UpdateExisting(t *testing.T) {
	mgr := newMockWireGuardManager()
	idx := newFakeIndexer()
	ctrl := newTestController(mgr, idx)

	// Pre-populate the manager with an existing VPN
	mgr.vpns["my-vpn"] = &vpn.WireGuardVPN{
		Name:    "my-vpn",
		Enabled: true,
		Interface: vpn.InterfaceConfig{
			Name: "wg0",
		},
	}

	// Put a CRD with updated spec
	spec := minimalSpec()
	spec["listenPort"] = float64(51821) // changed port
	crd := makeWireGuardCRD("my-vpn", "default", spec)
	idx.objects["default/my-vpn"] = crd

	err := ctrl.syncWireGuardVPN(t.Context(), "default/my-vpn")
	require.NoError(t, err)

	// Create would fail (already exists), so it should have updated
	require.Contains(t, mgr.updatedVPNs, "my-vpn")
	assert.Equal(t, 51821, mgr.vpns["my-vpn"].Interface.ListenPort)
}

func TestSyncWireGuardVPN_Delete(t *testing.T) {
	mgr := newMockWireGuardManager()
	idx := newFakeIndexer()
	ctrl := newTestController(mgr, idx)

	// Object not in indexer = deleted
	err := ctrl.syncWireGuardVPN(t.Context(), "default/deleted-vpn")
	require.NoError(t, err)

	require.Contains(t, mgr.deletedVPNs, "deleted-vpn")
}

func TestSyncWireGuardVPN_DisabledVPN(t *testing.T) {
	mgr := newMockWireGuardManager()
	idx := newFakeIndexer()
	ctrl := newTestController(mgr, idx)

	spec := minimalSpec()
	spec["enabled"] = false
	crd := makeWireGuardCRD("disabled-vpn", "default", spec)
	idx.objects["default/disabled-vpn"] = crd

	err := ctrl.syncWireGuardVPN(t.Context(), "default/disabled-vpn")
	require.NoError(t, err)

	// Should attempt delete for disabled VPNs
	require.Contains(t, mgr.deletedVPNs, "disabled-vpn")
}

func TestSyncWireGuardVPN_InvalidSpec(t *testing.T) {
	mgr := newMockWireGuardManager()
	idx := newFakeIndexer()
	ctrl := newTestController(mgr, idx)

	// CRD with missing required fields
	badSpec := map[string]interface{}{
		// Missing interfaceName and address
	}
	crd := makeWireGuardCRD("bad-vpn", "default", badSpec)
	idx.objects["default/bad-vpn"] = crd

	err := ctrl.syncWireGuardVPN(t.Context(), "default/bad-vpn")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to convert object")
}

func TestSyncWireGuardVPN_ManagerUpdateError(t *testing.T) {
	mgr := newMockWireGuardManager()
	mgr.createErr = fmt.Errorf("create failed")
	mgr.updateErr = fmt.Errorf("update failed")
	idx := newFakeIndexer()
	ctrl := newTestController(mgr, idx)

	crd := makeWireGuardCRD("error-vpn", "default", minimalSpec())
	idx.objects["default/error-vpn"] = crd

	err := ctrl.syncWireGuardVPN(t.Context(), "default/error-vpn")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create or update VPN")
}

func TestSyncWireGuardVPN_FullSpec_CreateAndStatus(t *testing.T) {
	mgr := newMockWireGuardManager()
	idx := newFakeIndexer()
	ctrl := newTestController(mgr, idx)

	crd := makeWireGuardCRD("full-vpn", "vpn-ns", fullSpec())
	idx.objects["vpn-ns/full-vpn"] = crd

	err := ctrl.syncWireGuardVPN(t.Context(), "vpn-ns/full-vpn")
	require.NoError(t, err)

	require.Contains(t, mgr.createdVPNs, "full-vpn")
	created := mgr.vpns["full-vpn"]
	require.NotNil(t, created)
	assert.Equal(t, "wg0", created.Interface.Name)
	assert.Len(t, created.Peers, 2)
	assert.Equal(t, 1420, created.Interface.MTU)
}
