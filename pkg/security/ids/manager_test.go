package ids

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GizmoTickler/fos1/pkg/security/ids/suricata"
	"github.com/GizmoTickler/fos1/pkg/security/ids/zeek"
)

// --- Mock implementations ---

type mockSuricataClient struct {
	running    bool
	stats      *suricata.SuricataStats
	statsErr   error
	interfaces []string
	ifaceErr   error
	reloadErr  error
}

func (m *mockSuricataClient) IsRunning() bool { return m.running }
func (m *mockSuricataClient) GetStats(_ context.Context) (*suricata.SuricataStats, error) {
	return m.stats, m.statsErr
}
func (m *mockSuricataClient) ListInterfaces(_ context.Context) ([]string, error) {
	return m.interfaces, m.ifaceErr
}
func (m *mockSuricataClient) ReloadRules(_ context.Context) error { return m.reloadErr }

type mockRuleManager struct {
	rules       []*suricata.Rule
	addErr      error
	disableErr  error
	enableErr   error
	reloadErr   error
	disabledSIDs []int
	addedRules   []*suricata.Rule
	reloaded     bool
}

func (m *mockRuleManager) ListRules() ([]*suricata.Rule, error) {
	return m.rules, nil
}
func (m *mockRuleManager) AddRule(rule *suricata.Rule) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.addedRules = append(m.addedRules, rule)
	return nil
}
func (m *mockRuleManager) DisableRule(sid int) error {
	if m.disableErr != nil {
		return m.disableErr
	}
	m.disabledSIDs = append(m.disabledSIDs, sid)
	return nil
}
func (m *mockRuleManager) EnableRule(sid int) error {
	return m.enableErr
}
func (m *mockRuleManager) ReloadRules(_ context.Context) error {
	if m.reloadErr != nil {
		return m.reloadErr
	}
	m.reloaded = true
	return nil
}

type mockEveReader struct {
	alerts []suricata.EveEvent
	err    error
}

func (m *mockEveReader) ReadAlerts(_ time.Time, _ int) ([]suricata.EveEvent, error) {
	return m.alerts, m.err
}

type mockZeekClient struct {
	connected   bool
	connectErr  error
	publishErr  error
	published   []zeek.BrokerEvent
	peerInfo    *zeek.PeerInfo
}

func (m *mockZeekClient) IsConnected() bool { return m.connected }
func (m *mockZeekClient) Connect(_ context.Context) error { return m.connectErr }
func (m *mockZeekClient) Publish(_ context.Context, event zeek.BrokerEvent) error {
	if m.publishErr != nil {
		return m.publishErr
	}
	m.published = append(m.published, event)
	return nil
}
func (m *mockZeekClient) PeerInfo() (*zeek.PeerInfo, error) {
	return m.peerInfo, nil
}

// --- GetStatus tests ---

func TestGetStatus_BothEnginesRunning(t *testing.T) {
	sc := &mockSuricataClient{
		running: true,
		stats: &suricata.SuricataStats{
			Uptime: 3600,
			Detect: suricata.DetectStats{
				RulesLoaded: 25000,
			},
		},
		interfaces: []string{"eth0", "eth1"},
	}
	zc := &mockZeekClient{connected: true}

	mgr := newIDSManagerForTest(sc, nil, nil, zc)
	status, err := mgr.GetStatus()
	require.NoError(t, err)

	assert.True(t, status.Running)
	assert.Equal(t, "IDS", status.Mode)
	assert.Equal(t, time.Duration(3600)*time.Second, status.Uptime)
	assert.Equal(t, 25000, status.RulesCount)
	assert.Equal(t, []string{"eth0", "eth1"}, status.Interfaces)
	assert.Empty(t, status.Errors)
}

func TestGetStatus_SuricataOnlyRunning(t *testing.T) {
	sc := &mockSuricataClient{
		running: true,
		stats: &suricata.SuricataStats{
			Uptime: 120,
			Detect: suricata.DetectStats{RulesLoaded: 5000},
		},
		interfaces: []string{"br0"},
	}
	zc := &mockZeekClient{connected: false}

	mgr := newIDSManagerForTest(sc, nil, nil, zc)
	status, err := mgr.GetStatus()
	require.NoError(t, err)

	assert.True(t, status.Running)
	assert.Equal(t, 5000, status.RulesCount)
	assert.Contains(t, status.Errors, "zeek broker is not connected")
}

func TestGetStatus_NeitherRunning(t *testing.T) {
	sc := &mockSuricataClient{running: false}
	zc := &mockZeekClient{connected: false}

	mgr := newIDSManagerForTest(sc, nil, nil, zc)
	status, err := mgr.GetStatus()
	require.NoError(t, err)

	assert.False(t, status.Running)
	assert.Len(t, status.Errors, 2)
}

func TestGetStatus_NoClientsConfigured(t *testing.T) {
	mgr := newIDSManagerForTest(nil, nil, nil, nil)
	status, err := mgr.GetStatus()
	require.NoError(t, err)

	assert.False(t, status.Running)
	assert.Contains(t, status.Errors, "suricata client not configured")
	assert.Contains(t, status.Errors, "zeek client not configured")
}

func TestGetStatus_IPSMode(t *testing.T) {
	sc := &mockSuricataClient{
		running: true,
		stats:   &suricata.SuricataStats{Uptime: 10, Detect: suricata.DetectStats{RulesLoaded: 100}},
		interfaces: []string{"eth0"},
	}
	mgr := newIDSManagerForTest(sc, nil, nil, nil)
	mgr.ipsEnabled = true

	status, err := mgr.GetStatus()
	require.NoError(t, err)
	assert.Equal(t, "IPS", status.Mode)
}

func TestGetStatus_SuricataStatsError(t *testing.T) {
	sc := &mockSuricataClient{
		running:  true,
		statsErr: fmt.Errorf("socket timeout"),
		interfaces: []string{"eth0"},
	}
	mgr := newIDSManagerForTest(sc, nil, nil, nil)

	status, err := mgr.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.Running)
	assert.Contains(t, status.Errors[0], "suricata stats: socket timeout")
}

// --- UpdateRules tests ---

func TestUpdateRules_Success(t *testing.T) {
	rm := &mockRuleManager{}
	zc := &mockZeekClient{connected: true}
	mgr := newIDSManagerForTest(nil, rm, nil, zc)

	config := &RulesConfig{
		CustomRules:   []string{`alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Test"; sid:1000001; rev:1;)`},
		DisabledRules: []string{"2000001"},
	}

	err := mgr.UpdateRules(config)
	require.NoError(t, err)

	assert.Len(t, rm.addedRules, 1)
	assert.Equal(t, 1000001, rm.addedRules[0].SID)
	assert.Equal(t, []int{2000001}, rm.disabledSIDs)
	assert.True(t, rm.reloaded)
	assert.Len(t, zc.published, 1)
	assert.Equal(t, "zeek/control", zc.published[0].Topic)
}

func TestUpdateRules_SuricataReloadError(t *testing.T) {
	rm := &mockRuleManager{reloadErr: fmt.Errorf("reload failed")}
	zc := &mockZeekClient{connected: true}
	mgr := newIDSManagerForTest(nil, rm, nil, zc)

	config := &RulesConfig{}
	err := mgr.UpdateRules(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suricata rule reload: reload failed")
}

func TestUpdateRules_InvalidCustomRule(t *testing.T) {
	rm := &mockRuleManager{}
	zc := &mockZeekClient{connected: true}
	mgr := newIDSManagerForTest(nil, rm, nil, zc)

	config := &RulesConfig{
		CustomRules: []string{"not a valid rule"},
	}

	err := mgr.UpdateRules(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse custom rule")
}

func TestUpdateRules_ZeekNotConnected(t *testing.T) {
	rm := &mockRuleManager{}
	zc := &mockZeekClient{connected: false}
	mgr := newIDSManagerForTest(nil, rm, nil, zc)

	config := &RulesConfig{}
	err := mgr.UpdateRules(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zeek broker not connected")
}

func TestUpdateRules_NoRuleManager(t *testing.T) {
	zc := &mockZeekClient{connected: true}
	mgr := newIDSManagerForTest(nil, nil, nil, zc)

	config := &RulesConfig{}
	err := mgr.UpdateRules(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suricata rule manager not configured")
}

// --- GetAlerts tests ---

func TestGetAlerts_ReturnsRealAlerts(t *testing.T) {
	reader := &mockEveReader{
		alerts: []suricata.EveEvent{
			{
				Timestamp: "2025-01-15T10:30:00.000000+0000",
				EventType: "alert",
				SrcIP:     "192.168.1.100",
				SrcPort:   12345,
				DestIP:    "10.0.0.1",
				DestPort:  22,
				Proto:     "TCP",
				InIface:   "eth0",
				Alert: &suricata.EveAlert{
					Action:      "allowed",
					SignatureID: 2001219,
					Signature:   "ET SCAN Potential SSH Scan",
					Category:    "Attempted Information Leak",
					Severity:    2,
				},
			},
			{
				Timestamp: "2025-01-15T10:35:00.000000+0000",
				EventType: "alert",
				SrcIP:     "10.0.0.50",
				SrcPort:   54321,
				DestIP:    "10.0.0.1",
				DestPort:  445,
				Proto:     "TCP",
				InIface:   "eth1",
				Alert: &suricata.EveAlert{
					Action:      "allowed",
					SignatureID: 2000419,
					Signature:   "ET POLICY SMB Outbound 445",
					Category:    "Policy Violation",
					Severity:    3,
				},
			},
		},
	}

	mgr := newIDSManagerForTest(nil, nil, reader, nil)

	alerts, err := mgr.GetAlerts(nil)
	require.NoError(t, err)
	require.Len(t, alerts, 2)

	assert.Equal(t, "ET SCAN Potential SSH Scan", alerts[0].Signature)
	assert.Equal(t, 2001219, alerts[0].SignatureID)
	assert.Equal(t, "high", alerts[0].Severity)
	assert.Equal(t, "192.168.1.100", alerts[0].SourceIP)
	assert.Equal(t, 22, alerts[0].DestinationPort)
	assert.Equal(t, "eth0", alerts[0].Interface)

	assert.Equal(t, "ET POLICY SMB Outbound 445", alerts[1].Signature)
	assert.Equal(t, "medium", alerts[1].Severity)
}

func TestGetAlerts_NoReaderConfigured(t *testing.T) {
	mgr := newIDSManagerForTest(nil, nil, nil, nil)
	_, err := mgr.GetAlerts(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "eve log reader not configured")
}

func TestGetAlerts_FilterBySeverity(t *testing.T) {
	reader := &mockEveReader{
		alerts: []suricata.EveEvent{
			{
				Timestamp: "2025-01-15T10:30:00.000000+0000",
				EventType: "alert",
				SrcIP:     "1.2.3.4",
				Alert: &suricata.EveAlert{
					Severity:  2,
					Signature: "High",
				},
			},
			{
				Timestamp: "2025-01-15T10:31:00.000000+0000",
				EventType: "alert",
				SrcIP:     "5.6.7.8",
				Alert: &suricata.EveAlert{
					Severity:  3,
					Signature: "Medium",
				},
			},
		},
	}

	mgr := newIDSManagerForTest(nil, nil, reader, nil)
	filter := &AlertFilter{Severity: "high"}
	alerts, err := mgr.GetAlerts(filter)
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	assert.Equal(t, "High", alerts[0].Signature)
}

func TestGetAlerts_FilterBySourceIP(t *testing.T) {
	reader := &mockEveReader{
		alerts: []suricata.EveEvent{
			{
				Timestamp: "2025-01-15T10:30:00.000000+0000",
				EventType: "alert",
				SrcIP:     "192.168.1.100",
				Alert:     &suricata.EveAlert{Severity: 3, Signature: "Match"},
			},
			{
				Timestamp: "2025-01-15T10:30:00.000000+0000",
				EventType: "alert",
				SrcIP:     "10.0.0.5",
				Alert:     &suricata.EveAlert{Severity: 3, Signature: "NoMatch"},
			},
		},
	}

	mgr := newIDSManagerForTest(nil, nil, reader, nil)
	filter := &AlertFilter{SourceIPs: []string{"192.168.1.100"}}
	alerts, err := mgr.GetAlerts(filter)
	require.NoError(t, err)
	require.Len(t, alerts, 1)
	assert.Equal(t, "Match", alerts[0].Signature)
}

func TestGetAlerts_EveReaderError(t *testing.T) {
	reader := &mockEveReader{err: fmt.Errorf("file not found")}
	mgr := newIDSManagerForTest(nil, nil, reader, nil)

	_, err := mgr.GetAlerts(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file not found")
}

// --- GetStatistics tests ---

func TestGetStatistics_Success(t *testing.T) {
	sc := &mockSuricataClient{
		running: true,
		stats: &suricata.SuricataStats{
			Uptime: 7200,
			Capture: suricata.CaptureStats{
				KernelPackets: 500000,
				KernelDrops:   100,
			},
			Decoder: suricata.DecoderStats{
				Pkts:    490000,
				Bytes:   100000000,
				Invalid: 50,
			},
			Flow: suricata.FlowStats{
				Total:  10000,
				Active: 500,
			},
			Detect: suricata.DetectStats{
				Alerts:      250,
				RulesLoaded: 30000,
			},
		},
		interfaces: []string{"eth0", "br0"},
	}

	mgr := newIDSManagerForTest(sc, nil, nil, nil)
	stats, err := mgr.GetStatistics()
	require.NoError(t, err)

	assert.Equal(t, uint64(500000), stats.PacketsReceived)
	assert.Equal(t, uint64(100), stats.PacketsDropped)
	assert.Equal(t, uint64(50), stats.PacketsInvalidChecksums)
	assert.Equal(t, uint64(100000000), stats.BytesReceived)
	assert.Equal(t, uint64(250), stats.AlertsGenerated)
	assert.Equal(t, uint64(10000), stats.SessionsTotal)
	assert.Equal(t, uint64(500), stats.SessionsCurrent)
	assert.Equal(t, uint64(7200), stats.UptimeSeconds)
	assert.Contains(t, stats.InterfaceStats, "eth0")
	assert.Contains(t, stats.InterfaceStats, "br0")
}

func TestGetStatistics_NoClient(t *testing.T) {
	mgr := newIDSManagerForTest(nil, nil, nil, nil)
	_, err := mgr.GetStatistics()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suricata client not configured")
}

func TestGetStatistics_NotRunning(t *testing.T) {
	sc := &mockSuricataClient{running: false}
	mgr := newIDSManagerForTest(sc, nil, nil, nil)
	_, err := mgr.GetStatistics()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suricata is not running")
}

func TestGetStatistics_StatsError(t *testing.T) {
	sc := &mockSuricataClient{
		running:  true,
		statsErr: fmt.Errorf("connection reset"),
	}
	mgr := newIDSManagerForTest(sc, nil, nil, nil)
	_, err := mgr.GetStatistics()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection reset")
}

// --- EnableIPS / DisableIPS tests ---

func TestEnableDisableIPS(t *testing.T) {
	mgr := newIDSManagerForTest(nil, nil, nil, nil)

	require.NoError(t, mgr.EnableIPS())
	assert.True(t, mgr.ipsEnabled)

	// Verify status reflects IPS mode
	sc := &mockSuricataClient{
		running:    true,
		stats:      &suricata.SuricataStats{},
		interfaces: []string{},
	}
	mgr.suricataClient = sc
	status, err := mgr.GetStatus()
	require.NoError(t, err)
	assert.Equal(t, "IPS", status.Mode)

	require.NoError(t, mgr.DisableIPS())
	assert.False(t, mgr.ipsEnabled)

	status, err = mgr.GetStatus()
	require.NoError(t, err)
	assert.Equal(t, "IDS", status.Mode)
}

// --- Interface management tests ---

func TestAddRemoveInterface(t *testing.T) {
	mgr := newIDSManagerForTest(nil, nil, nil, nil)

	require.NoError(t, mgr.AddInterface("eth0", &InterfaceConfig{Mode: "IDS"}))
	require.NoError(t, mgr.AddInterface("eth1", &InterfaceConfig{Mode: "IPS"}))

	ifaces, err := mgr.GetInterfaces()
	require.NoError(t, err)
	assert.Len(t, ifaces, 2)

	require.NoError(t, mgr.RemoveInterface("eth0"))
	ifaces, err = mgr.GetInterfaces()
	require.NoError(t, err)
	assert.Len(t, ifaces, 1)
}

func TestRemoveNonexistentInterface(t *testing.T) {
	mgr := newIDSManagerForTest(nil, nil, nil, nil)
	err := mgr.RemoveInterface("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not being monitored")
}

func TestGetInterfaces_PrefersLiveSuricata(t *testing.T) {
	sc := &mockSuricataClient{
		running:    true,
		interfaces: []string{"eth0", "eth1", "br0"},
	}
	mgr := newIDSManagerForTest(sc, nil, nil, nil)
	// Add a local interface that should be ignored in favor of Suricata's list
	mgr.monitoredIfaces["local0"] = &InterfaceConfig{}

	ifaces, err := mgr.GetInterfaces()
	require.NoError(t, err)
	assert.Equal(t, []string{"eth0", "eth1", "br0"}, ifaces)
}

func TestGetInterfaces_FallsBackToLocal(t *testing.T) {
	sc := &mockSuricataClient{
		running:  true,
		ifaceErr: fmt.Errorf("socket error"),
	}
	mgr := newIDSManagerForTest(sc, nil, nil, nil)
	mgr.monitoredIfaces["fallback0"] = &InterfaceConfig{}

	ifaces, err := mgr.GetInterfaces()
	require.NoError(t, err)
	assert.Equal(t, []string{"fallback0"}, ifaces)
}
