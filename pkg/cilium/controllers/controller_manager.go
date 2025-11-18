package controllers

import (
	"context"
	"sync"

	"k8s.io/client-go/dynamic"
	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// ControllerManager manages all Cilium-related controllers
type ControllerManager struct {
	// dynamicClient is used to interact with Kubernetes CRDs
	dynamicClient dynamic.Interface
	
	// ciliumClient is used to interact with Cilium
	ciliumClient cilium.CiliumClient
	
	// routeSynchronizer is used to synchronize routes with Cilium
	routeSynchronizer *cilium.RouteSynchronizer
	
	// networkInterfaceController manages network interfaces
	networkInterfaceController *NetworkInterfaceController
	
	// firewallController manages firewall rules
	firewallController *FirewallController
	
	// routingController manages routing
	routingController *RoutingController
	
	// dpiController manages DPI integration
	dpiController *DPIController
	
	// networkController is used for high-level network operations
	networkController *cilium.NetworkController
	
	// wg is used to wait for all controllers to stop
	wg sync.WaitGroup
	
	// stopCh is used to signal all controllers to stop
	stopCh chan struct{}
}

// NewControllerManager creates a new controller manager
func NewControllerManager(
	dynamicClient dynamic.Interface,
	ciliumClient cilium.CiliumClient,
	routeSynchronizer *cilium.RouteSynchronizer,
	networkController *cilium.NetworkController,
) *ControllerManager {
	return &ControllerManager{
		dynamicClient:      dynamicClient,
		ciliumClient:       ciliumClient,
		routeSynchronizer:  routeSynchronizer,
		networkController:  networkController,
		stopCh:             make(chan struct{}),
	}
}

// Initialize initializes all controllers
func (m *ControllerManager) Initialize() {
	klog.Info("Initializing Cilium controllers")
	
	// Create the NetworkInterface controller
	m.networkInterfaceController = NewNetworkInterfaceController(
		m.dynamicClient,
		m.networkController,
	)
	
	// Create the Firewall controller
	m.firewallController = NewFirewallController(
		m.dynamicClient,
		m.ciliumClient,
	)
	
	// Create the Routing controller
	m.routingController = NewRoutingController(
		m.dynamicClient,
		m.routeSynchronizer,
	)
	
	// Create the DPI controller
	m.dpiController = NewDPIController(
		m.dynamicClient,
		m.ciliumClient,
	)
}

// Start starts all controllers
func (m *ControllerManager) Start(ctx context.Context) error {
	klog.Info("Starting Cilium controllers")
	
	// Start the NetworkInterface controller
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := m.networkInterfaceController.Start(ctx); err != nil {
			klog.Errorf("Error starting NetworkInterface controller: %v", err)
		}
	}()
	
	// Start the Firewall controller
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := m.firewallController.Start(ctx); err != nil {
			klog.Errorf("Error starting Firewall controller: %v", err)
		}
	}()
	
	// Start the Routing controller
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := m.routingController.Start(ctx); err != nil {
			klog.Errorf("Error starting Routing controller: %v", err)
		}
	}()
	
	// Start the DPI controller
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := m.dpiController.Start(ctx); err != nil {
			klog.Errorf("Error starting DPI controller: %v", err)
		}
	}()
	
	// Start the route synchronizer
	if err := m.routeSynchronizer.Start(); err != nil {
		klog.Errorf("Error starting route synchronizer: %v", err)
		return err
	}
	
	return nil
}

// Stop stops all controllers
func (m *ControllerManager) Stop() {
	klog.Info("Stopping Cilium controllers")
	
	// Stop the NetworkInterface controller
	m.networkInterfaceController.Stop()
	
	// Stop the Firewall controller
	m.firewallController.Stop()
	
	// Stop the Routing controller
	m.routingController.Stop()
	
	// Stop the DPI controller
	m.dpiController.Stop()
	
	// Stop the route synchronizer
	m.routeSynchronizer.Stop()
	
	// Wait for all controllers to stop
	m.wg.Wait()
}
