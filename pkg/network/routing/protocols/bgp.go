package protocols

import (
	"context"
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/network/routing"
	"github.com/GizmoTickler/fos1/pkg/network/routing/frr"
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

	ctx := context.Background()

	// Configure route maps first (they may be referenced by other config)
	for _, rm := range bgpConfig.RouteMaps {
		frrRouteMap := h.convertRouteMapToFRR(rm)
		if err := h.frrClient.ConfigureRouteMap(ctx, frrRouteMap); err != nil {
			return fmt.Errorf("failed to configure route map %s: %v", rm.Name, err)
		}
	}

	// Configure prefix lists
	for _, pl := range bgpConfig.PrefixLists {
		frrPrefixList := h.convertPrefixListToFRR(pl)
		if err := h.frrClient.ConfigurePrefixList(ctx, frrPrefixList); err != nil {
			return fmt.Errorf("failed to configure prefix list %s: %v", pl.Name, err)
		}
	}

	// Configure AS path access lists
	for _, apl := range bgpConfig.ASPathLists {
		frrASPathList := h.convertASPathListToFRR(apl)
		if err := h.frrClient.ConfigureASPathList(ctx, frrASPathList); err != nil {
			return fmt.Errorf("failed to configure AS path list %s: %v", apl.Name, err)
		}
	}

	// Configure community lists
	for _, cl := range bgpConfig.CommunityLists {
		frrCommunityList := h.convertCommunityListToFRR(cl)
		if err := h.frrClient.ConfigureCommunityList(ctx, frrCommunityList); err != nil {
			return fmt.Errorf("failed to configure community list %s: %v", cl.Name, err)
		}
	}

	// Configure peer groups
	for _, pg := range bgpConfig.PeerGroups {
		frrPeerGroup := h.convertPeerGroupToFRR(pg)
		if err := h.frrClient.ConfigureBGPPeerGroup(ctx, bgpConfig.ASNumber, frrPeerGroup); err != nil {
			return fmt.Errorf("failed to configure peer group %s: %v", pg.Name, err)
		}
	}

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
			PeerGroup:            n.PeerGroup,
			RouteMapIn:           n.RouteMapIn,
			RouteMapOut:          n.RouteMapOut,
			PrefixListIn:         n.PrefixListIn,
			PrefixListOut:        n.PrefixListOut,
			FilterListIn:         n.FilterListIn,
			FilterListOut:        n.FilterListOut,
			MaxPrefixes:          n.MaxPrefixes,
			DefaultOriginate:     n.DefaultOriginate,
			NextHopSelf:          n.NextHopSelf,
			RemovePrivateAS:      n.RemovePrivateAS,
			SendCommunity:        n.SendCommunity,
			SendExtendedCommunity: n.SendExtendedCommunity,
			SendLargeCommunity:   n.SendLargeCommunity,
			Weight:               n.Weight,
			AllowASIn:            n.AllowASIn,
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

		networks := make([]frr.BGPNetwork, 0, len(af.Networks))
		for _, n := range af.Networks {
			networks = append(networks, frr.BGPNetwork{
				Prefix:   n.Prefix,
				RouteMap: n.RouteMap,
				Backdoor: n.Backdoor,
			})
		}

		aggregates := make([]frr.BGPAggregate, 0, len(af.Aggregates))
		for _, a := range af.Aggregates {
			aggregates = append(aggregates, frr.BGPAggregate{
				Prefix:      a.Prefix,
				SummaryOnly: a.SummaryOnly,
				AsSet:       a.AsSet,
				RouteMap:    a.RouteMap,
			})
		}

		addressFamilies = append(addressFamilies, frr.BGPAddressFamily{
			Type:             af.Type,
			Enabled:          af.Enabled,
			Redistributions:  redistributions,
			Networks:         networks,
			Aggregates:       aggregates,
			MaximumPaths:     af.MaximumPaths,
			MaximumPathsIBGP: af.MaximumPathsIBGP,
		})
	}

	// Configure BGP in FRR
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

// convertRouteMapToFRR converts a routing.RouteMap to frr.RouteMap
func (h *BGPHandler) convertRouteMapToFRR(rm routing.RouteMap) frr.RouteMap {
	entries := make([]frr.RouteMapEntry, 0, len(rm.Entries))
	for _, e := range rm.Entries {
		entries = append(entries, frr.RouteMapEntry{
			Sequence: e.Sequence,
			Action:   e.Action,
			Match: frr.RouteMapMatch{
				Prefix:     e.Match.Prefix,
				PrefixLen:  e.Match.PrefixLen,
				Protocol:   e.Match.Protocol,
				Community:  e.Match.Community,
				ASPath:     e.Match.AsPath,
				Metric:     e.Match.Metric,
				Tag:        e.Match.Tag,
			},
			Set: frr.RouteMapSet{
				Metric:         e.Set.Metric,
				LocalPreference: e.Set.LocalPreference,
				Community:      e.Set.Community,
				NextHop:        e.Set.NextHop,
				Weight:         e.Set.Weight,
				ASPathPrepend:  e.Set.AsPathPrepend,
			},
		})
	}
	return frr.RouteMap{
		Name:    rm.Name,
		Entries: entries,
	}
}

// convertPrefixListToFRR converts a routing.PrefixList to frr.PrefixList
func (h *BGPHandler) convertPrefixListToFRR(pl routing.PrefixList) frr.PrefixList {
	entries := make([]frr.PrefixListEntry, 0, len(pl.Entries))
	for _, e := range pl.Entries {
		entries = append(entries, frr.PrefixListEntry{
			Sequence: e.Sequence,
			Action:   e.Action,
			Prefix:   e.Prefix,
			GE:       e.GE,
			LE:       e.LE,
		})
	}
	return frr.PrefixList{
		Name:          pl.Name,
		Description:   pl.Description,
		Entries:       entries,
		AddressFamily: pl.AddressFamily,
	}
}

// convertASPathListToFRR converts a routing.ASPathAccessList to frr.ASPathAccessList
func (h *BGPHandler) convertASPathListToFRR(apl routing.ASPathAccessList) frr.ASPathAccessList {
	entries := make([]frr.ASPathEntry, 0, len(apl.Entries))
	for _, e := range apl.Entries {
		entries = append(entries, frr.ASPathEntry{
			Action: e.Action,
			Regex:  e.Regex,
		})
	}
	return frr.ASPathAccessList{
		Name:    apl.Name,
		Entries: entries,
	}
}

// convertCommunityListToFRR converts a routing.CommunityList to frr.CommunityList
func (h *BGPHandler) convertCommunityListToFRR(cl routing.CommunityList) frr.CommunityList {
	entries := make([]frr.CommunityListEntry, 0, len(cl.Entries))
	for _, e := range cl.Entries {
		entries = append(entries, frr.CommunityListEntry{
			Action:      e.Action,
			Communities: e.Communities,
		})
	}
	return frr.CommunityList{
		Name:    cl.Name,
		Type:    cl.Type,
		Entries: entries,
	}
}

// convertPeerGroupToFRR converts a routing.BGPPeerGroup to frr.BGPPeerGroup
func (h *BGPHandler) convertPeerGroupToFRR(pg routing.BGPPeerGroup) frr.BGPPeerGroup {
	return frr.BGPPeerGroup{
		Name:                 pg.Name,
		RemoteASNumber:       pg.RemoteASNumber,
		Description:          pg.Description,
		KeepaliveInterval:    pg.KeepaliveInterval,
		HoldTime:             pg.HoldTime,
		ConnectRetryInterval: pg.ConnectRetryInterval,
		BFDEnabled:           pg.BFDEnabled,
		RouteMapIn:           pg.RouteMapIn,
		RouteMapOut:          pg.RouteMapOut,
		PrefixListIn:         pg.PrefixListIn,
		PrefixListOut:        pg.PrefixListOut,
		FilterListIn:         pg.FilterListIn,
		FilterListOut:        pg.FilterListOut,
		MaxPrefixes:          pg.MaxPrefixes,
		DefaultOriginate:     pg.DefaultOriginate,
		NextHopSelf:          pg.NextHopSelf,
		RemovePrivateAS:      pg.RemovePrivateAS,
		SendCommunity:        pg.SendCommunity,
		SendExtendedCommunity: pg.SendExtendedCommunity,
		SendLargeCommunity:   pg.SendLargeCommunity,
		Weight:               pg.Weight,
		AllowASIn:            pg.AllowASIn,
	}
}
