package ids

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/GizmoTickler/fos1/pkg/security/ids/correlation"
	"github.com/GizmoTickler/fos1/pkg/security/ids/suricata"
	"github.com/GizmoTickler/fos1/pkg/security/ids/zeek"
)

// SuricataClient abstracts the Suricata control socket operations needed by
// the IDS manager. The concrete implementation is *suricata.Client.
type SuricataClient interface {
	IsRunning() bool
	GetStats(ctx context.Context) (*suricata.SuricataStats, error)
	ListInterfaces(ctx context.Context) ([]string, error)
	ReloadRules(ctx context.Context) error
}

// SuricataRuleManager abstracts the rule management operations needed by the
// IDS manager. The concrete implementation is *suricata.RuleManager.
type SuricataRuleManager interface {
	ListRules() ([]*suricata.Rule, error)
	AddRule(rule *suricata.Rule) error
	DisableRule(sid int) error
	EnableRule(sid int) error
	ReloadRules(ctx context.Context) error
}

// EveReader abstracts reading alerts from the Suricata Eve JSON log.
type EveReader interface {
	ReadAlerts(since time.Time, limit int) ([]suricata.EveEvent, error)
}

// ZeekBrokerClient abstracts the Zeek Broker operations needed by the IDS
// manager. The concrete implementation is *zeek.BrokerClient.
type ZeekBrokerClient interface {
	IsConnected() bool
	Connect(ctx context.Context) error
	Publish(ctx context.Context, event zeek.BrokerEvent) error
	PeerInfo() (*zeek.PeerInfo, error)
}

// IDSManager manages the IDS/IPS system by aggregating real state from
// Suricata and Zeek engine clients.
type IDSManager struct {
	// Kubernetes client
	kubeClient kubernetes.Interface

	// Controller runtime client
	client client.Client

	// Controller runtime scheme
	scheme *runtime.Scheme

	// Controller runtime manager
	mgr manager.Manager

	// Event recorder
	recorder record.EventRecorder

	// Controllers
	suricataController    *suricata.SuricataController
	zeekController        *zeek.ZeekController
	correlationController *correlation.EventCorrelationController

	// Engine clients
	suricataClient      SuricataClient
	suricataRuleManager SuricataRuleManager
	eveReader           EveReader
	zeekClient          ZeekBrokerClient

	// Tracking state
	startTime        time.Time
	lastRulesUpdate  time.Time
	ipsEnabled       bool
	monitoredIfaces  map[string]*InterfaceConfig

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	mutex  sync.RWMutex
}

// NewIDSManager creates a new IDS/IPS manager.
func NewIDSManager(kubeClient kubernetes.Interface, config *rest.Config) (*IDSManager, error) {
	if kubeClient == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}

	if config == nil {
		return nil, fmt.Errorf("kubernetes config is required")
	}

	// Create context for management
	ctx, cancel := context.WithCancel(context.Background())

	// Create controller runtime manager
	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:           runtime.NewScheme(),
		LeaderElection:   true,
		LeaderElectionID: "ids-manager-leader-election",
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create controller runtime manager: %w", err)
	}

	// Create IDS manager
	idsManager := &IDSManager{
		kubeClient:      kubeClient,
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		mgr:             mgr,
		recorder:        mgr.GetEventRecorderFor("ids-manager"),
		ctx:             ctx,
		cancel:          cancel,
		startTime:       time.Now(),
		monitoredIfaces: make(map[string]*InterfaceConfig),
	}

	// Create controllers
	idsManager.suricataController = &suricata.SuricataController{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("suricata-controller"),
	}

	idsManager.zeekController = &zeek.ZeekController{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("zeek-controller"),
	}

	idsManager.correlationController = &correlation.EventCorrelationController{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("correlation-controller"),
	}

	return idsManager, nil
}

// newIDSManagerForTest creates an IDSManager without Kubernetes dependencies,
// suitable for unit testing with injected clients.
func newIDSManagerForTest(
	suricataClient SuricataClient,
	ruleManager SuricataRuleManager,
	eveReader EveReader,
	zeekClient ZeekBrokerClient,
) *IDSManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &IDSManager{
		suricataClient:      suricataClient,
		suricataRuleManager: ruleManager,
		eveReader:           eveReader,
		zeekClient:          zeekClient,
		ctx:                 ctx,
		cancel:              cancel,
		startTime:           time.Now(),
		monitoredIfaces:     make(map[string]*InterfaceConfig),
	}
}

// SetSuricataClient configures the Suricata control socket client.
func (m *IDSManager) SetSuricataClient(c SuricataClient) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.suricataClient = c
}

// SetSuricataRuleManager configures the Suricata rule manager.
func (m *IDSManager) SetSuricataRuleManager(rm SuricataRuleManager) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.suricataRuleManager = rm
}

// SetEveReader configures the Suricata Eve log reader.
func (m *IDSManager) SetEveReader(r EveReader) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.eveReader = r
}

// SetZeekClient configures the Zeek Broker client.
func (m *IDSManager) SetZeekClient(c ZeekBrokerClient) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.zeekClient = c
}

// Initialize initializes the IDS/IPS manager.
func (m *IDSManager) Initialize(ctx context.Context) error {
	klog.Info("Initializing IDS/IPS manager")

	// Set up controllers with manager (only when running with a real k8s manager)
	if m.mgr != nil {
		if err := m.suricataController.SetupWithManager(m.mgr); err != nil {
			return fmt.Errorf("failed to set up Suricata controller: %w", err)
		}

		if err := m.zeekController.SetupWithManager(m.mgr); err != nil {
			return fmt.Errorf("failed to set up Zeek controller: %w", err)
		}

		if err := m.correlationController.SetupWithManager(m.mgr); err != nil {
			return fmt.Errorf("failed to set up Event Correlation controller: %w", err)
		}

		// Start the manager
		go func() {
			if err := m.mgr.Start(m.ctx); err != nil {
				klog.Errorf("Failed to start controller runtime manager: %v", err)
			}
		}()
	}

	m.startTime = time.Now()
	klog.Info("IDS/IPS manager initialized successfully")
	return nil
}

// Shutdown shuts down the IDS/IPS manager.
func (m *IDSManager) Shutdown(ctx context.Context) error {
	klog.Info("Shutting down IDS/IPS manager")
	m.cancel()
	return nil
}

// GetStatus queries Suricata and Zeek for their live status and returns a
// combined view. If an engine is unreachable, that is reflected in the
// Running field and in the Errors list rather than returning an error.
func (m *IDSManager) GetStatus() (*Status, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()

	status := &Status{
		Running: false,
		Mode:    "IDS",
	}

	if m.ipsEnabled {
		status.Mode = "IPS"
	}

	var errs []string

	// Query Suricata status
	suricataRunning := false
	if m.suricataClient != nil {
		suricataRunning = m.suricataClient.IsRunning()
		if suricataRunning {
			stats, err := m.suricataClient.GetStats(ctx)
			if err != nil {
				errs = append(errs, fmt.Sprintf("suricata stats: %v", err))
			} else {
				status.Uptime = time.Duration(stats.Uptime) * time.Second
				status.LastRestart = time.Now().Add(-status.Uptime)
				status.RulesCount = int(stats.Detect.RulesLoaded)
			}

			ifaces, err := m.suricataClient.ListInterfaces(ctx)
			if err != nil {
				errs = append(errs, fmt.Sprintf("suricata iface-list: %v", err))
			} else {
				status.Interfaces = ifaces
			}
		} else {
			errs = append(errs, "suricata control socket is not reachable")
		}
	} else {
		errs = append(errs, "suricata client not configured")
	}

	// Query Zeek status
	zeekConnected := false
	if m.zeekClient != nil {
		zeekConnected = m.zeekClient.IsConnected()
		if !zeekConnected {
			errs = append(errs, "zeek broker is not connected")
		}
	} else {
		errs = append(errs, "zeek client not configured")
	}

	// The system is considered running if at least one engine is up
	status.Running = suricataRunning || zeekConnected
	status.RulesLastUpdated = m.lastRulesUpdate
	status.Errors = errs

	return status, nil
}

// UpdateRules applies rule changes to the Suricata rule manager, triggers a
// Suricata live rule reload, and signals Zeek to reload its scripts.
func (m *IDSManager) UpdateRules(config *RulesConfig) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	var applyErrors []string

	// Apply custom rules to Suricata via the rule manager
	if m.suricataRuleManager != nil {
		// Disable rules
		for _, sidStr := range config.DisabledRules {
			sid, err := strconv.Atoi(sidStr)
			if err != nil {
				applyErrors = append(applyErrors, fmt.Sprintf("invalid SID %q: %v", sidStr, err))
				continue
			}
			if err := m.suricataRuleManager.DisableRule(sid); err != nil {
				applyErrors = append(applyErrors, fmt.Sprintf("disable SID %d: %v", sid, err))
			}
		}

		// Add custom rules
		for _, ruleText := range config.CustomRules {
			rule, err := suricata.ParseRule(ruleText)
			if err != nil {
				applyErrors = append(applyErrors, fmt.Sprintf("parse custom rule: %v", err))
				continue
			}
			if err := m.suricataRuleManager.AddRule(rule); err != nil {
				applyErrors = append(applyErrors, fmt.Sprintf("add custom rule SID=%d: %v", rule.SID, err))
			}
		}

		// Trigger Suricata live rule reload
		if err := m.suricataRuleManager.ReloadRules(ctx); err != nil {
			applyErrors = append(applyErrors, fmt.Sprintf("suricata rule reload: %v", err))
		}
	} else {
		applyErrors = append(applyErrors, "suricata rule manager not configured")
	}

	// Signal Zeek to reload scripts
	if m.zeekClient != nil {
		if m.zeekClient.IsConnected() {
			reloadEvent := zeek.BrokerEvent{
				Topic:     "zeek/control",
				Type:      "event",
				Timestamp: time.Now(),
				Data: map[string]any{
					"action": "reload_scripts",
				},
			}
			if err := m.zeekClient.Publish(ctx, reloadEvent); err != nil {
				applyErrors = append(applyErrors, fmt.Sprintf("zeek script reload: %v", err))
			}
		} else {
			applyErrors = append(applyErrors, "zeek broker not connected, cannot signal script reload")
		}
	} else {
		applyErrors = append(applyErrors, "zeek client not configured")
	}

	if len(applyErrors) > 0 {
		return fmt.Errorf("rule update completed with errors: %v", applyErrors)
	}

	m.lastRulesUpdate = time.Now()
	klog.Infof("IDS/IPS rules updated: %d sources, %d custom rules, %d disabled rules",
		len(config.Sources), len(config.CustomRules), len(config.DisabledRules))

	return nil
}

// GetAlerts fetches real alerts from the Suricata Eve log and applies the
// provided filter. Returns an error if the Eve reader is not configured.
func (m *IDSManager) GetAlerts(filter *AlertFilter) ([]*Alert, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.eveReader == nil {
		return nil, fmt.Errorf("eve log reader not configured")
	}

	var since time.Time
	limit := 0
	if filter != nil {
		since = filter.StartTime
		limit = filter.Limit
	}

	events, err := m.eveReader.ReadAlerts(since, limit)
	if err != nil {
		return nil, fmt.Errorf("read eve alerts: %w", err)
	}

	alerts := make([]*Alert, 0, len(events))
	for i, ev := range events {
		alert := &Alert{
			ID:              strconv.Itoa(i + 1),
			Signature:       ev.Alert.Signature,
			SignatureID:     ev.Alert.SignatureID,
			Category:        ev.Alert.Category,
			Severity:        suricata.SeverityString(ev.Alert.Severity),
			SourceIP:        ev.SrcIP,
			SourcePort:      ev.SrcPort,
			DestinationIP:   ev.DestIP,
			DestinationPort: ev.DestPort,
			Protocol:        ev.Proto,
			Interface:       ev.InIface,
			Action:          ev.Alert.Action,
		}

		ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", ev.Timestamp)
		if err == nil {
			alert.Timestamp = ts
		}

		if !matchesAlertFilter(alert, filter) {
			continue
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// matchesAlertFilter returns true if the alert passes all filter criteria.
func matchesAlertFilter(alert *Alert, filter *AlertFilter) bool {
	if filter == nil {
		return true
	}

	if !filter.EndTime.IsZero() && alert.Timestamp.After(filter.EndTime) {
		return false
	}

	if filter.Severity != "" && alert.Severity != filter.Severity {
		return false
	}

	if len(filter.Categories) > 0 && !containsString(filter.Categories, alert.Category) {
		return false
	}

	if len(filter.SourceIPs) > 0 && !containsString(filter.SourceIPs, alert.SourceIP) {
		return false
	}

	if len(filter.DestinationIPs) > 0 && !containsString(filter.DestinationIPs, alert.DestinationIP) {
		return false
	}

	return true
}

// containsString checks if the needle is present in the haystack.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// GetStatistics queries Suricata for live packet/flow/detection stats and
// returns them in the unified Statistics structure.
func (m *IDSManager) GetStatistics() (*Statistics, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()

	if m.suricataClient == nil {
		return nil, fmt.Errorf("suricata client not configured")
	}

	if !m.suricataClient.IsRunning() {
		return nil, fmt.Errorf("suricata is not running")
	}

	stats, err := m.suricataClient.GetStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("get suricata stats: %w", err)
	}

	result := &Statistics{
		PacketsReceived:         uint64(stats.Capture.KernelPackets),
		PacketsDropped:          uint64(stats.Capture.KernelDrops),
		PacketsInvalidChecksums: uint64(stats.Decoder.Invalid),
		BytesReceived:           uint64(stats.Decoder.Bytes),
		AlertsGenerated:         uint64(stats.Detect.Alerts),
		SessionsTotal:           uint64(stats.Flow.Total),
		SessionsCurrent:         uint64(stats.Flow.Active),
		UptimeSeconds:           uint64(stats.Uptime),
		InterfaceStats:          make(map[string]InterfaceStatistics),
	}

	// Populate per-interface stats from live interface list
	ifaces, err := m.suricataClient.ListInterfaces(ctx)
	if err != nil {
		klog.Warningf("Failed to list Suricata interfaces for per-iface stats: %v", err)
	} else {
		for _, iface := range ifaces {
			result.InterfaceStats[iface] = InterfaceStatistics{}
		}
	}

	return result, nil
}

// EnableIPS enables IPS mode (blocking).
func (m *IDSManager) EnableIPS() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.ipsEnabled = true
	klog.Info("IPS mode enabled")
	return nil
}

// DisableIPS disables IPS mode (detection only).
func (m *IDSManager) DisableIPS() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.ipsEnabled = false
	klog.Info("IPS mode disabled (detection only)")
	return nil
}

// AddInterface adds an interface to monitor.
func (m *IDSManager) AddInterface(name string, config *InterfaceConfig) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.monitoredIfaces[name] = config
	klog.Infof("Added interface %s to monitoring", name)
	return nil
}

// RemoveInterface removes an interface from monitoring.
func (m *IDSManager) RemoveInterface(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.monitoredIfaces[name]; !exists {
		return fmt.Errorf("interface %s is not being monitored", name)
	}

	delete(m.monitoredIfaces, name)
	klog.Infof("Removed interface %s from monitoring", name)
	return nil
}

// GetInterfaces returns the list of interfaces currently being monitored by
// querying the live Suricata instance. Falls back to the locally tracked set
// if Suricata is unreachable.
func (m *IDSManager) GetInterfaces() ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()

	if m.suricataClient != nil && m.suricataClient.IsRunning() {
		ifaces, err := m.suricataClient.ListInterfaces(ctx)
		if err == nil {
			return ifaces, nil
		}
		klog.Warningf("Failed to list Suricata interfaces, falling back to local state: %v", err)
	}

	// Fall back to locally tracked interfaces
	ifaces := make([]string, 0, len(m.monitoredIfaces))
	for name := range m.monitoredIfaces {
		ifaces = append(ifaces, name)
	}
	return ifaces, nil
}
