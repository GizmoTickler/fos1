package protocols

import (
	"context"
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/network/routing"
	"github.com/varuntirumala1/fos1/pkg/network/routing/frr"
)

// OSPFHandler implements the protocol handler for OSPF
type OSPFHandler struct {
	frrClient *frr.Client
	config    *routing.OSPFConfig
	status    *routing.ProtocolStatus
}

// NewOSPFHandler creates a new OSPF protocol handler
func NewOSPFHandler(frrClient *frr.Client) *OSPFHandler {
	return &OSPFHandler{
		frrClient: frrClient,
		status: &routing.ProtocolStatus{
			Name:      "ospf",
			State:     "stopped",
			Uptime:    0,
			Neighbors: []routing.NeighborStatus{},
		},
	}
}

// Start starts the OSPF protocol
func (h *OSPFHandler) Start(config routing.ProtocolConfig) error {
	ospfConfig, ok := config.(routing.OSPFConfig)
	if !ok {
		return fmt.Errorf("invalid config type for OSPF protocol")
	}

	// Store the config
	h.config = &ospfConfig

	// Convert the config to FRR format
	areas := make([]frr.OSPFArea, 0, len(ospfConfig.Areas))
	for _, a := range ospfConfig.Areas {
		interfaces := make([]frr.OSPFInterface, 0, len(a.Interfaces))
		for _, i := range a.Interfaces {
			interfaces = append(interfaces, frr.OSPFInterface{
				Name:     i.Name,
				Network:  "", // Would need to determine network from interface
				Cost:     i.Cost,
				Priority: i.Priority,
			})
		}

		areas = append(areas, frr.OSPFArea{
			AreaID:    a.AreaID,
			Interfaces: interfaces,
			StubArea:   a.StubArea,
			NSSAArea:   a.NSSAArea,
		})
	}

	redistributions := make([]frr.Redistribution, 0, len(ospfConfig.Redistributions))
	for _, r := range ospfConfig.Redistributions {
		redistributions = append(redistributions, frr.Redistribution{
			Protocol:    r.Protocol,
			RouteMapRef: r.RouteMapRef,
		})
	}

	// Configure OSPF in FRR
	ctx := context.Background()
	err := h.frrClient.ConfigureOSPF(ctx, ospfConfig.RouterID, areas, redistributions)
	if err != nil {
		return fmt.Errorf("failed to configure OSPF: %v", err)
	}

	// Update status
	h.status.State = "running"
	h.status.Uptime = 0
	h.status.StartTime = time.Now()

	// Start a goroutine to periodically update the status
	go h.updateStatus()

	return nil
}

// Stop stops the OSPF protocol
func (h *OSPFHandler) Stop() error {
	// In a real implementation, we would disable OSPF in FRR
	// For now, just update the status
	h.status.State = "stopped"
	h.status.Uptime = 0
	h.status.Neighbors = []routing.NeighborStatus{}

	return nil
}

// Restart restarts the OSPF protocol
func (h *OSPFHandler) Restart() error {
	ctx := context.Background()
	err := h.frrClient.RestartOSPF(ctx)
	if err != nil {
		return fmt.Errorf("failed to restart OSPF: %v", err)
	}

	// Update status
	h.status.State = "running"
	h.status.Uptime = 0
	h.status.StartTime = time.Now()

	return nil
}

// GetStatus gets the status of the OSPF protocol
func (h *OSPFHandler) GetStatus() *routing.ProtocolStatus {
	return h.status
}

// updateStatus periodically updates the OSPF status
func (h *OSPFHandler) updateStatus() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if h.status.State != "running" {
				return
			}

			ctx := context.Background()

			// Get parsed OSPF summary
			summary, err := h.frrClient.GetOSPFSummaryParsed(ctx)
			if err != nil {
				klog.Errorf("Failed to get OSPF summary: %v", err)
				// Fallback to string output
				_, err2 := h.frrClient.GetOSPFNeighbors(ctx)
				if err2 != nil {
					klog.Errorf("Failed to get OSPF neighbors (fallback): %v", err2)
				}
				continue
			}

			// Update neighbors status
			neighbors := make([]routing.NeighborStatus, 0, len(summary.Neighbors))
			for _, n := range summary.Neighbors {
				neighbors = append(neighbors, routing.NeighborStatus{
					Address:          n.Address,
					State:            n.State,
					Uptime:           0, // Parse deadtime string if needed
					PrefixesReceived: 0, // OSPF doesn't track prefix counts like BGP
					PrefixesSent:     0,
				})
			}
			h.status.Neighbors = neighbors

			// Update uptime
			if h.status.State == "running" {
				h.status.Uptime = time.Since(h.status.StartTime).Truncate(time.Second)
			}

			klog.V(4).Infof("OSPF status updated: %d neighbors, uptime: %v", len(neighbors), h.status.Uptime)
		}
	}
}

// UpdateConfig updates the OSPF configuration
func (h *OSPFHandler) UpdateConfig(config routing.ProtocolConfig) error {
	ospfConfig, ok := config.(routing.OSPFConfig)
	if !ok {
		return fmt.Errorf("invalid config type for OSPF protocol")
	}

	// Store the new config
	h.config = &ospfConfig

	// Restart OSPF with the new config
	return h.Start(ospfConfig)
}
