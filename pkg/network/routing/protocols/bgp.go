package protocols

import (
	"context"
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/network/routing"
	"github.com/varuntirumala1/fos1/pkg/network/routing/frr"
)

// BGPHandler implements the protocol handler for BGP
type BGPHandler struct {
	frrClient *frr.Client
	config    *routing.BGPConfig
	status    *routing.ProtocolStatus
}

// NewBGPHandler creates a new BGP protocol handler
func NewBGPHandler(frrClient *frr.Client) *BGPHandler {
	return &BGPHandler{
		frrClient: frrClient,
		status: &routing.ProtocolStatus{
			Name:      "bgp",
			State:     "stopped",
			Uptime:    0,
			Neighbors: []routing.NeighborStatus{},
		},
	}
}

// Start starts the BGP protocol
func (h *BGPHandler) Start(config routing.ProtocolConfig) error {
	bgpConfig, ok := config.(routing.BGPConfig)
	if !ok {
		return fmt.Errorf("invalid config type for BGP protocol")
	}

	// Store the config
	h.config = &bgpConfig

	// Convert the config to FRR format
	neighbors := make([]frr.BGPNeighbor, 0, len(bgpConfig.Neighbors))
	for _, n := range bgpConfig.Neighbors {
		neighbors = append(neighbors, frr.BGPNeighbor{
			Address:              n.Address,
			RemoteASNumber:       n.RemoteASNumber,
			Description:          n.Description,
			KeepaliveInterval:    n.KeepaliveInterval,
			HoldTime:             n.HoldTime,
			ConnectRetryInterval: n.ConnectRetryInterval,
			BFDEnabled:           n.BFDEnabled,
		})
	}

	addressFamilies := make([]frr.BGPAddressFamily, 0, len(bgpConfig.AddressFamilies))
	for _, af := range bgpConfig.AddressFamilies {
		redistributions := make([]frr.Redistribution, 0, len(af.Redistributions))
		for _, r := range af.Redistributions {
			redistributions = append(redistributions, frr.Redistribution{
				Protocol:    r.Protocol,
				RouteMapRef: r.RouteMapRef,
			})
		}

		addressFamilies = append(addressFamilies, frr.BGPAddressFamily{
			Type:           af.Type,
			Enabled:        af.Enabled,
			Redistributions: redistributions,
			Networks:       af.Networks,
		})
	}

	// Configure BGP in FRR
	ctx := context.Background()
	err := h.frrClient.ConfigureBGP(ctx, bgpConfig.ASNumber, bgpConfig.RouterID, neighbors, addressFamilies)
	if err != nil {
		return fmt.Errorf("failed to configure BGP: %v", err)
	}

	// Update status
	h.status.State = "running"
	h.status.Uptime = 0
	h.status.StartTime = time.Now()

	// Start a goroutine to periodically update the status
	go h.updateStatus()

	return nil
}

// Stop stops the BGP protocol
func (h *BGPHandler) Stop() error {
	// In a real implementation, we would disable BGP in FRR
	// For now, just update the status
	h.status.State = "stopped"
	h.status.Uptime = 0
	h.status.Neighbors = []routing.NeighborStatus{}

	return nil
}

// Restart restarts the BGP protocol
func (h *BGPHandler) Restart() error {
	ctx := context.Background()
	err := h.frrClient.RestartBGP(ctx)
	if err != nil {
		return fmt.Errorf("failed to restart BGP: %v", err)
	}

	// Update status
	h.status.State = "running"
	h.status.Uptime = 0
	h.status.StartTime = time.Now()

	return nil
}

// GetStatus gets the status of the BGP protocol
func (h *BGPHandler) GetStatus() *routing.ProtocolStatus {
	return h.status
}

// updateStatus periodically updates the BGP status
func (h *BGPHandler) updateStatus() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if h.status.State != "running" {
				return
			}

			ctx := context.Background()

			// Get parsed BGP summary
			summary, err := h.frrClient.GetBGPSummaryParsed(ctx, uint32(h.config.ASNumber))
			if err != nil {
				klog.Errorf("Failed to get BGP summary: %v", err)
				// Fallback to string output
				_, err2 := h.frrClient.GetBGPSummary(ctx)
				if err2 != nil {
					klog.Errorf("Failed to get BGP summary (fallback): %v", err2)
				}
				continue
			}

			// Update neighbors status
			neighbors := make([]routing.NeighborStatus, 0, len(summary.Neighbors))
			for _, n := range summary.Neighbors {
				neighbors = append(neighbors, routing.NeighborStatus{
					Address:          n.IP,
					State:            n.State,
					Uptime:           0, // Parse uptime string if needed
					PrefixesReceived: n.PrefixReceived,
					PrefixesSent:     n.PrefixSent,
				})
			}
			h.status.Neighbors = neighbors

			// Update uptime
			if h.status.State == "running" {
				h.status.Uptime = time.Since(h.status.StartTime).Truncate(time.Second)
			}

			klog.V(4).Infof("BGP status updated: %d neighbors, uptime: %v", len(neighbors), h.status.Uptime)
		}
	}
}

// UpdateConfig updates the BGP configuration
func (h *BGPHandler) UpdateConfig(config routing.ProtocolConfig) error {
	bgpConfig, ok := config.(routing.BGPConfig)
	if !ok {
		return fmt.Errorf("invalid config type for BGP protocol")
	}

	// Store the new config
	h.config = &bgpConfig

	// Restart BGP with the new config
	return h.Start(bgpConfig)
}
