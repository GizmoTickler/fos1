package protocols

import (
	"context"
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/network/routing"
	"github.com/varuntirumala1/fos1/pkg/network/routing/frr"
)

// BFDHandler implements the protocol handler for BFD
type BFDHandler struct {
	frrClient *frr.Client
	config    *routing.BFDConfig
	status    *routing.ProtocolStatus
}

// NewBFDHandler creates a new BFD protocol handler
func NewBFDHandler(frrClient *frr.Client) *BFDHandler {
	return &BFDHandler{
		frrClient: frrClient,
		status: &routing.ProtocolStatus{
			Name:      "bfd",
			State:     "stopped",
			Uptime:    0,
			Neighbors: []routing.NeighborStatus{},
		},
	}
}

// Start starts the BFD protocol
func (h *BFDHandler) Start(config routing.ProtocolConfig) error {
	bfdConfig, ok := config.(routing.BFDConfig)
	if !ok {
		return fmt.Errorf("invalid config type for BFD protocol")
	}

	// Store the config
	h.config = &bfdConfig

	// Configure BFD in FRR
	ctx := context.Background()
	err := h.frrClient.ConfigureBFD(ctx, bfdConfig.MinTxInterval, bfdConfig.MinRxInterval, bfdConfig.Multiplier)
	if err != nil {
		return fmt.Errorf("failed to configure BFD: %v", err)
	}

	// Update status
	h.status.State = "running"
	h.status.Uptime = 0
	h.status.StartTime = time.Now()

	// Start a goroutine to periodically update the status
	go h.updateStatus()

	return nil
}

// Stop stops the BFD protocol
func (h *BFDHandler) Stop() error {
	// In a real implementation, we would disable BFD in FRR
	// For now, just update the status
	h.status.State = "stopped"
	h.status.Uptime = 0
	h.status.Neighbors = []routing.NeighborStatus{}

	return nil
}

// Restart restarts the BFD protocol
func (h *BFDHandler) Restart() error {
	// In a real implementation, we would restart BFD in FRR
	// For now, just update the status
	h.status.State = "running"
	h.status.Uptime = 0
	h.status.StartTime = time.Now()

	return nil
}

// GetStatus gets the status of the BFD protocol
func (h *BFDHandler) GetStatus() *routing.ProtocolStatus {
	return h.status
}

// updateStatus periodically updates the BFD status
func (h *BFDHandler) updateStatus() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx := context.Background()
			peers, err := h.frrClient.GetBFDPeers(ctx)
			if err != nil {
				klog.Errorf("Failed to get BFD peers: %v", err)
				continue
			}

			// In a real implementation, we would parse the peers to update the status
			// For now, just update the uptime
			if h.status.State == "running" {
				h.status.Uptime = time.Since(h.status.StartTime).Truncate(time.Second)
			}

			klog.V(4).Infof("BFD peers: %s", peers)
		}
	}
}

// UpdateConfig updates the BFD configuration
func (h *BFDHandler) UpdateConfig(config routing.ProtocolConfig) error {
	bfdConfig, ok := config.(routing.BFDConfig)
	if !ok {
		return fmt.Errorf("invalid config type for BFD protocol")
	}

	// Store the new config
	h.config = &bfdConfig

	// Restart BFD with the new config
	return h.Start(bfdConfig)
}
