package protocols

import (
	"testing"

	"github.com/varuntirumala1/fos1/pkg/network/routing"
	"github.com/varuntirumala1/fos1/pkg/network/routing/frr"
)

func TestBGPHandler_convertRouteMapToFRR(t *testing.T) {
	handler := &BGPHandler{}

	routeMap := routing.RouteMap{
		Name: "test-map",
		Entries: []routing.RouteMapEntry{
			{
				Sequence: 10,
				Action:   "permit",
				Match: routing.RouteMapMatch{
					Prefix:    "prefix-list-1",
					Community: "100:200",
					AsPath:    "as-path-1",
				},
				Set: routing.RouteMapSet{
					Metric:          100,
					LocalPreference: 200,
					Community:       "100:300",
					ASPathPrepend:   "65001 65001",
				},
			},
		},
	}

	frrRouteMap := handler.convertRouteMapToFRR(routeMap)

	if frrRouteMap.Name != "test-map" {
		t.Errorf("Expected name 'test-map', got '%s'", frrRouteMap.Name)
	}

	if len(frrRouteMap.Entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(frrRouteMap.Entries))
	}

	entry := frrRouteMap.Entries[0]
	if entry.Sequence != 10 {
		t.Errorf("Expected sequence 10, got %d", entry.Sequence)
	}

	if entry.Action != "permit" {
		t.Errorf("Expected action 'permit', got '%s'", entry.Action)
	}

	if entry.Match.Prefix != "prefix-list-1" {
		t.Errorf("Expected prefix 'prefix-list-1', got '%s'", entry.Match.Prefix)
	}

	if entry.Set.Metric != 100 {
		t.Errorf("Expected metric 100, got %d", entry.Set.Metric)
	}
}

func TestBGPHandler_convertPrefixListToFRR(t *testing.T) {
	handler := &BGPHandler{}

	prefixList := routing.PrefixList{
		Name:          "test-prefix-list",
		Description:   "Test prefix list",
		AddressFamily: "ipv4",
		Entries: []routing.PrefixListEntry{
			{
				Sequence: 10,
				Action:   "permit",
				Prefix:   "10.0.0.0/8",
				GE:       16,
				LE:       24,
			},
		},
	}

	frrPrefixList := handler.convertPrefixListToFRR(prefixList)

	if frrPrefixList.Name != "test-prefix-list" {
		t.Errorf("Expected name 'test-prefix-list', got '%s'", frrPrefixList.Name)
	}

	if frrPrefixList.Description != "Test prefix list" {
		t.Errorf("Expected description 'Test prefix list', got '%s'", frrPrefixList.Description)
	}

	if len(frrPrefixList.Entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(frrPrefixList.Entries))
	}

	entry := frrPrefixList.Entries[0]
	if entry.Prefix != "10.0.0.0/8" {
		t.Errorf("Expected prefix '10.0.0.0/8', got '%s'", entry.Prefix)
	}

	if entry.GE != 16 {
		t.Errorf("Expected GE 16, got %d", entry.GE)
	}

	if entry.LE != 24 {
		t.Errorf("Expected LE 24, got %d", entry.LE)
	}
}

func TestBGPHandler_convertASPathListToFRR(t *testing.T) {
	handler := &BGPHandler{}

	asPathList := routing.ASPathAccessList{
		Name: "test-as-path",
		Entries: []routing.ASPathEntry{
			{
				Action: "permit",
				Regex:  "^65001_",
			},
			{
				Action: "deny",
				Regex:  "_65002$",
			},
		},
	}

	frrASPathList := handler.convertASPathListToFRR(asPathList)

	if frrASPathList.Name != "test-as-path" {
		t.Errorf("Expected name 'test-as-path', got '%s'", frrASPathList.Name)
	}

	if len(frrASPathList.Entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(frrASPathList.Entries))
	}

	if frrASPathList.Entries[0].Action != "permit" {
		t.Errorf("Expected action 'permit', got '%s'", frrASPathList.Entries[0].Action)
	}

	if frrASPathList.Entries[0].Regex != "^65001_" {
		t.Errorf("Expected regex '^65001_', got '%s'", frrASPathList.Entries[0].Regex)
	}
}

func TestBGPHandler_convertCommunityListToFRR(t *testing.T) {
	handler := &BGPHandler{}

	communityList := routing.CommunityList{
		Name: "test-community",
		Type: "standard",
		Entries: []routing.CommunityListEntry{
			{
				Action:      "permit",
				Communities: []string{"100:200", "100:300"},
			},
		},
	}

	frrCommunityList := handler.convertCommunityListToFRR(communityList)

	if frrCommunityList.Name != "test-community" {
		t.Errorf("Expected name 'test-community', got '%s'", frrCommunityList.Name)
	}

	if frrCommunityList.Type != "standard" {
		t.Errorf("Expected type 'standard', got '%s'", frrCommunityList.Type)
	}

	if len(frrCommunityList.Entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(frrCommunityList.Entries))
	}

	entry := frrCommunityList.Entries[0]
	if entry.Action != "permit" {
		t.Errorf("Expected action 'permit', got '%s'", entry.Action)
	}

	if len(entry.Communities) != 2 {
		t.Errorf("Expected 2 communities, got %d", len(entry.Communities))
	}
}

func TestBGPHandler_convertPeerGroupToFRR(t *testing.T) {
	handler := &BGPHandler{}

	peerGroup := routing.BGPPeerGroup{
		Name:               "test-peer-group",
		RemoteASNumber:     65001,
		Description:        "Test peer group",
		KeepaliveInterval:  30,
		HoldTime:           90,
		BFDEnabled:         true,
		RouteMapIn:         "map-in",
		RouteMapOut:        "map-out",
		NextHopSelf:        true,
		SendCommunity:      true,
		MaxPrefixes:        1000,
	}

	frrPeerGroup := handler.convertPeerGroupToFRR(peerGroup)

	if frrPeerGroup.Name != "test-peer-group" {
		t.Errorf("Expected name 'test-peer-group', got '%s'", frrPeerGroup.Name)
	}

	if frrPeerGroup.RemoteASNumber != 65001 {
		t.Errorf("Expected remote AS 65001, got %d", frrPeerGroup.RemoteASNumber)
	}

	if frrPeerGroup.Description != "Test peer group" {
		t.Errorf("Expected description 'Test peer group', got '%s'", frrPeerGroup.Description)
	}

	if frrPeerGroup.KeepaliveInterval != 30 {
		t.Errorf("Expected keepalive interval 30, got %d", frrPeerGroup.KeepaliveInterval)
	}

	if !frrPeerGroup.BFDEnabled {
		t.Error("Expected BFD to be enabled")
	}

	if !frrPeerGroup.NextHopSelf {
		t.Error("Expected NextHopSelf to be true")
	}

	if frrPeerGroup.MaxPrefixes != 1000 {
		t.Errorf("Expected max prefixes 1000, got %d", frrPeerGroup.MaxPrefixes)
	}
}

func TestBGPConfig_GetProtocolName(t *testing.T) {
	config := routing.BGPConfig{}
	if config.GetProtocolName() != "bgp" {
		t.Errorf("Expected protocol name 'bgp', got '%s'", config.GetProtocolName())
	}
}

func TestBGPNeighbor_AllFields(t *testing.T) {
	neighbor := routing.BGPNeighbor{
		Address:              "192.168.1.1",
		RemoteASNumber:       65001,
		Description:          "Test neighbor",
		KeepaliveInterval:    30,
		HoldTime:             90,
		ConnectRetryInterval: 120,
		BFDEnabled:           true,
		PeerGroup:            "test-group",
		RouteMapIn:           "map-in",
		RouteMapOut:          "map-out",
		PrefixListIn:         "prefix-in",
		PrefixListOut:        "prefix-out",
		FilterListIn:         "filter-in",
		FilterListOut:        "filter-out",
		MaxPrefixes:          1000,
		DefaultOriginate:     true,
		NextHopSelf:          true,
		RemovePrivateAS:      true,
		SendCommunity:        true,
		SendExtendedCommunity: true,
		SendLargeCommunity:   true,
		Weight:               100,
		AllowASIn:            3,
	}

	// Convert to FRR neighbor
	frrNeighbor := frr.BGPNeighbor{
		Address:              neighbor.Address,
		RemoteASNumber:       neighbor.RemoteASNumber,
		Description:          neighbor.Description,
		KeepaliveInterval:    neighbor.KeepaliveInterval,
		HoldTime:             neighbor.HoldTime,
		ConnectRetryInterval: neighbor.ConnectRetryInterval,
		BFDEnabled:           neighbor.BFDEnabled,
		PeerGroup:            neighbor.PeerGroup,
		RouteMapIn:           neighbor.RouteMapIn,
		RouteMapOut:          neighbor.RouteMapOut,
	}

	if frrNeighbor.Address != "192.168.1.1" {
		t.Errorf("Expected address '192.168.1.1', got '%s'", frrNeighbor.Address)
	}

	if frrNeighbor.RemoteASNumber != 65001 {
		t.Errorf("Expected remote AS 65001, got %d", frrNeighbor.RemoteASNumber)
	}

	if frrNeighbor.PeerGroup != "test-group" {
		t.Errorf("Expected peer group 'test-group', got '%s'", frrNeighbor.PeerGroup)
	}
}
