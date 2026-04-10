package protocols

import (
	"context"
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/network/routing"
	"github.com/GizmoTickler/fos1/pkg/network/routing/frr"
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
	areas := convertOSPFAreasToFRR(ospfConfig.Areas)
	redistributions := convertRedistributionsToFRR(ospfConfig.Redistributions)

	// Configure OSPF in FRR
	ctx := context.Background()
	err := h.frrClient.ConfigureOSPFWithParams(
		ctx,
		ospfConfig.RouterID,
		areas,
		redistributions,
		ospfConfig.ReferenceBandwidth,
	)
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

// convertOSPFAreasToFRR converts routing.OSPFArea to frr.OSPFArea
func convertOSPFAreasToFRR(areas []routing.OSPFArea) []frr.OSPFArea {
	frrAreas := make([]frr.OSPFArea, 0, len(areas))
	for _, a := range areas {
		interfaces := make([]frr.OSPFInterface, 0, len(a.Interfaces))
		for _, i := range a.Interfaces {
			interfaces = append(interfaces, frr.OSPFInterface{
				Name:        i.Name,
				Network:     i.Network,
				Cost:        i.Cost,
				Priority:    i.Priority,
				NetworkType: i.NetworkType,
				Authentication: frr.OSPFAuthentication{
					Type:  i.Authentication.Type,
					Key:   i.Authentication.Key,
					KeyID: i.Authentication.KeyID,
				},
				HelloInterval:      i.HelloInterval,
				DeadInterval:       i.DeadInterval,
				RetransmitInterval: i.RetransmitInterval,
				TransmitDelay:      i.TransmitDelay,
			})
		}

		frrAreas = append(frrAreas, frr.OSPFArea{
			AreaID:     a.AreaID,
			Interfaces: interfaces,
			StubArea:   a.StubArea,
			NSSAArea:   a.NSSAArea,
		})
	}
	return frrAreas
}

// convertRedistributionsToFRR converts routing.Redistribution to frr.Redistribution
func convertRedistributionsToFRR(redistributions []routing.Redistribution) []frr.Redistribution {
	frrRedists := make([]frr.Redistribution, 0, len(redistributions))
	for _, r := range redistributions {
		frrRedists = append(frrRedists, frr.Redistribution{
			Protocol:    r.Protocol,
			RouteMapRef: r.RouteMapRef,
		})
	}
	return frrRedists
}

// Stop stops the OSPF protocol
func (h *OSPFHandler) Stop() error {
	// Disable OSPF in FRR
	ctx := context.Background()
	err := h.frrClient.DisableOSPF(ctx)
	if err != nil {
		return fmt.Errorf("failed to disable OSPF: %v", err)
	}

	// Update status
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

// GetStatus gets the status of the OSPF protocol by querying FRR for live state.
// If the protocol is running, it refreshes neighbor/adjacency state from vtysh
// before returning. If the live query fails, the cached status is returned.
func (h *OSPFHandler) GetStatus() *routing.ProtocolStatus {
	if h.status.State == "running" {
		if err := h.refreshStatus(); err != nil {
			klog.V(2).Infof("Failed to refresh OSPF status from FRR, returning cached: %v", err)
		}
	}
	return h.status
}

// refreshStatus queries FRR via vtysh for live OSPF neighbor/adjacency state
// and updates the cached status.
func (h *OSPFHandler) refreshStatus() error {
	ctx := context.Background()

	// Try JSON output first: "show ip ospf neighbor json"
	var neighborsJSON map[string]interface{}
	err := h.frrClient.ExecuteVtyshCommandJSON(ctx, "show ip ospf neighbor", &neighborsJSON)
	if err == nil {
		return h.parseOSPFNeighborJSON(neighborsJSON)
	}

	klog.V(3).Infof("JSON OSPF neighbor query failed, falling back to text parsing: %v", err)

	// Fallback to text-parsed output
	summary, err := h.frrClient.GetOSPFSummaryParsed(ctx)
	if err != nil {
		return fmt.Errorf("failed to get OSPF summary: %w", err)
	}

	neighbors := make([]routing.NeighborStatus, 0, len(summary.Neighbors))
	for _, n := range summary.Neighbors {
		neighbors = append(neighbors, routing.NeighborStatus{
			Address: n.Address,
			State:   n.State,
		})
	}
	h.status.Neighbors = neighbors
	if h.status.State == "running" {
		h.status.Uptime = time.Since(h.status.StartTime).Truncate(time.Second)
	}
	return nil
}

// parseOSPFNeighborJSON parses the JSON output of "show ip ospf neighbor json".
// FRR JSON format has "neighbors" key containing a map keyed by router-id,
// each with neighbor details.
func (h *OSPFHandler) parseOSPFNeighborJSON(data map[string]interface{}) error {
	neighbors := []routing.NeighborStatus{}

	// FRR "show ip ospf neighbor json" returns: {"neighbors": { "<routerID>": [{ ... }] }}
	// or in some versions a flat list under "neighbors"
	neighborsData, ok := data["neighbors"]
	if !ok {
		// Some FRR versions put neighbors at root level as array
		// Try to parse "default" VRF
		if defaultVRF, ok := data["default"].(map[string]interface{}); ok {
			neighborsData = defaultVRF["neighbors"]
		}
	}

	switch nd := neighborsData.(type) {
	case map[string]interface{}:
		// Map keyed by router-id
		for routerID, nVal := range nd {
			nList, ok := nVal.([]interface{})
			if !ok {
				continue
			}
			for _, entry := range nList {
				entryMap, ok := entry.(map[string]interface{})
				if !ok {
					continue
				}
				n := h.parseOSPFNeighborEntry(entryMap, routerID)
				neighbors = append(neighbors, n)
			}
		}
	case []interface{}:
		// Array of neighbor objects
		for _, entry := range nd {
			entryMap, ok := entry.(map[string]interface{})
			if !ok {
				continue
			}
			routerID := ""
			if rid, ok := entryMap["routerId"].(string); ok {
				routerID = rid
			}
			n := h.parseOSPFNeighborEntry(entryMap, routerID)
			neighbors = append(neighbors, n)
		}
	}

	h.status.Neighbors = neighbors
	if h.status.State == "running" {
		h.status.Uptime = time.Since(h.status.StartTime).Truncate(time.Second)
	}

	klog.V(4).Infof("OSPF status refreshed from FRR: %d neighbors", len(neighbors))
	return nil
}

// parseOSPFNeighborEntry extracts a NeighborStatus from an OSPF neighbor JSON entry
func (h *OSPFHandler) parseOSPFNeighborEntry(entryMap map[string]interface{}, routerID string) routing.NeighborStatus {
	state := "unknown"
	if s, ok := entryMap["nbrState"].(string); ok {
		state = s
	} else if s, ok := entryMap["state"].(string); ok {
		state = s
	}

	address := ""
	if a, ok := entryMap["ifaceAddress"].(string); ok {
		address = a
	} else if a, ok := entryMap["address"].(string); ok {
		address = a
	}

	if address == "" {
		address = routerID
	}

	return routing.NeighborStatus{
		Address: address,
		State:   state,
	}
}

// updateStatus periodically updates the OSPF status from live FRR state
func (h *OSPFHandler) updateStatus() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if h.status.State != "running" {
				return
			}

			if err := h.refreshStatus(); err != nil {
				klog.Errorf("Failed to refresh OSPF status: %v", err)
			}
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
