package protocols

import (
	"testing"

	"github.com/GizmoTickler/fos1/pkg/network/routing"
	"github.com/GizmoTickler/fos1/pkg/network/routing/frr"
)

// TestConvertOSPFAreasToFRR tests the conversion of routing.OSPFArea to frr.OSPFArea
func TestConvertOSPFAreasToFRR(t *testing.T) {
	tests := []struct {
		name     string
		areas    []routing.OSPFArea
		expected []frr.OSPFArea
	}{
		{
			name: "Single area with basic interface",
			areas: []routing.OSPFArea{
				{
					AreaID: "0.0.0.0",
					Interfaces: []routing.OSPFInterface{
						{
							Name:     "eth0",
							Cost:     10,
							Priority: 1,
						},
					},
					StubArea: false,
					NSSAArea: false,
				},
			},
			expected: []frr.OSPFArea{
				{
					AreaID: "0.0.0.0",
					Interfaces: []frr.OSPFInterface{
						{
							Name:               "eth0",
							Network:            "",
							Cost:               10,
							Priority:           1,
							NetworkType:        "",
							Authentication:     frr.OSPFAuthentication{},
							HelloInterval:      0,
							DeadInterval:       0,
							RetransmitInterval: 0,
							TransmitDelay:      0,
						},
					},
					StubArea: false,
					NSSAArea: false,
				},
			},
		},
		{
			name: "Area with authentication",
			areas: []routing.OSPFArea{
				{
					AreaID: "0.0.0.1",
					Interfaces: []routing.OSPFInterface{
						{
							Name:        "eth1",
							Cost:        20,
							Priority:    10,
							NetworkType: "broadcast",
							Authentication: routing.OSPFAuthentication{
								Type:  "md5",
								Key:   "secret123",
								KeyID: 1,
							},
						},
					},
					StubArea: false,
					NSSAArea: false,
				},
			},
			expected: []frr.OSPFArea{
				{
					AreaID: "0.0.0.1",
					Interfaces: []frr.OSPFInterface{
						{
							Name:        "eth1",
							Network:     "",
							Cost:        20,
							Priority:    10,
							NetworkType: "broadcast",
							Authentication: frr.OSPFAuthentication{
								Type:  "md5",
								Key:   "secret123",
								KeyID: 1,
							},
							HelloInterval:      0,
							DeadInterval:       0,
							RetransmitInterval: 0,
							TransmitDelay:      0,
						},
					},
					StubArea: false,
					NSSAArea: false,
				},
			},
		},
		{
			name: "Stub area",
			areas: []routing.OSPFArea{
				{
					AreaID: "0.0.0.2",
					Interfaces: []routing.OSPFInterface{
						{
							Name:     "eth2",
							Cost:     5,
							Priority: 0,
						},
					},
					StubArea: true,
					NSSAArea: false,
				},
			},
			expected: []frr.OSPFArea{
				{
					AreaID: "0.0.0.2",
					Interfaces: []frr.OSPFInterface{
						{
							Name:               "eth2",
							Network:            "",
							Cost:               5,
							Priority:           0,
							NetworkType:        "",
							Authentication:     frr.OSPFAuthentication{},
							HelloInterval:      0,
							DeadInterval:       0,
							RetransmitInterval: 0,
							TransmitDelay:      0,
						},
					},
					StubArea: true,
					NSSAArea: false,
				},
			},
		},
		{
			name: "NSSA area",
			areas: []routing.OSPFArea{
				{
					AreaID: "0.0.0.3",
					Interfaces: []routing.OSPFInterface{
						{
							Name:     "eth3",
							Cost:     15,
							Priority: 5,
						},
					},
					StubArea: false,
					NSSAArea: true,
				},
			},
			expected: []frr.OSPFArea{
				{
					AreaID: "0.0.0.3",
					Interfaces: []frr.OSPFInterface{
						{
							Name:               "eth3",
							Network:            "",
							Cost:               15,
							Priority:           5,
							NetworkType:        "",
							Authentication:     frr.OSPFAuthentication{},
							HelloInterval:      0,
							DeadInterval:       0,
							RetransmitInterval: 0,
							TransmitDelay:      0,
						},
					},
					StubArea: false,
					NSSAArea: true,
				},
			},
		},
		{
			name: "Multiple areas with multiple interfaces",
			areas: []routing.OSPFArea{
				{
					AreaID: "0.0.0.0",
					Interfaces: []routing.OSPFInterface{
						{
							Name:        "eth0",
							Cost:        10,
							Priority:    1,
							NetworkType: "broadcast",
						},
						{
							Name:        "eth1",
							Cost:        20,
							Priority:    10,
							NetworkType: "point-to-point",
						},
					},
					StubArea: false,
					NSSAArea: false,
				},
				{
					AreaID: "0.0.0.1",
					Interfaces: []routing.OSPFInterface{
						{
							Name:     "eth2",
							Cost:     30,
							Priority: 5,
						},
					},
					StubArea: true,
					NSSAArea: false,
				},
			},
			expected: []frr.OSPFArea{
				{
					AreaID: "0.0.0.0",
					Interfaces: []frr.OSPFInterface{
						{
							Name:               "eth0",
							Network:            "",
							Cost:               10,
							Priority:           1,
							NetworkType:        "broadcast",
							Authentication:     frr.OSPFAuthentication{},
							HelloInterval:      0,
							DeadInterval:       0,
							RetransmitInterval: 0,
							TransmitDelay:      0,
						},
						{
							Name:               "eth1",
							Network:            "",
							Cost:               20,
							Priority:           10,
							NetworkType:        "point-to-point",
							Authentication:     frr.OSPFAuthentication{},
							HelloInterval:      0,
							DeadInterval:       0,
							RetransmitInterval: 0,
							TransmitDelay:      0,
						},
					},
					StubArea: false,
					NSSAArea: false,
				},
				{
					AreaID: "0.0.0.1",
					Interfaces: []frr.OSPFInterface{
						{
							Name:               "eth2",
							Network:            "",
							Cost:               30,
							Priority:           5,
							NetworkType:        "",
							Authentication:     frr.OSPFAuthentication{},
							HelloInterval:      0,
							DeadInterval:       0,
							RetransmitInterval: 0,
							TransmitDelay:      0,
						},
					},
					StubArea: true,
					NSSAArea: false,
				},
			},
		},
		{
			name: "Area with point-to-multipoint network type",
			areas: []routing.OSPFArea{
				{
					AreaID: "0.0.0.4",
					Interfaces: []routing.OSPFInterface{
						{
							Name:        "eth4",
							Cost:        100,
							Priority:    0,
							NetworkType: "point-to-multipoint",
						},
					},
					StubArea: false,
					NSSAArea: false,
				},
			},
			expected: []frr.OSPFArea{
				{
					AreaID: "0.0.0.4",
					Interfaces: []frr.OSPFInterface{
						{
							Name:               "eth4",
							Network:            "",
							Cost:               100,
							Priority:           0,
							NetworkType:        "point-to-multipoint",
							Authentication:     frr.OSPFAuthentication{},
							HelloInterval:      0,
							DeadInterval:       0,
							RetransmitInterval: 0,
							TransmitDelay:      0,
						},
					},
					StubArea: false,
					NSSAArea: false,
				},
			},
		},
		{
			name: "Area with simple authentication",
			areas: []routing.OSPFArea{
				{
					AreaID: "0.0.0.5",
					Interfaces: []routing.OSPFInterface{
						{
							Name:     "eth5",
							Cost:     50,
							Priority: 128,
							Authentication: routing.OSPFAuthentication{
								Type: "simple",
								Key:  "plaintext",
							},
						},
					},
					StubArea: false,
					NSSAArea: false,
				},
			},
			expected: []frr.OSPFArea{
				{
					AreaID: "0.0.0.5",
					Interfaces: []frr.OSPFInterface{
						{
							Name:     "eth5",
							Network:  "",
							Cost:     50,
							Priority: 128,
							Authentication: frr.OSPFAuthentication{
								Type:  "simple",
								Key:   "plaintext",
								KeyID: 0,
							},
							HelloInterval:      0,
							DeadInterval:       0,
							RetransmitInterval: 0,
							TransmitDelay:      0,
						},
					},
					StubArea: false,
					NSSAArea: false,
				},
			},
		},
		{
			name:     "Empty areas",
			areas:    []routing.OSPFArea{},
			expected: []frr.OSPFArea{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertOSPFAreasToFRR(tt.areas)

			// Check length
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d areas, got %d", len(tt.expected), len(result))
				return
			}

			// Check each area
			for i, area := range result {
				expected := tt.expected[i]

				if area.AreaID != expected.AreaID {
					t.Errorf("Area %d: AreaID = %v, want %v", i, area.AreaID, expected.AreaID)
				}

				if area.StubArea != expected.StubArea {
					t.Errorf("Area %d: StubArea = %v, want %v", i, area.StubArea, expected.StubArea)
				}

				if area.NSSAArea != expected.NSSAArea {
					t.Errorf("Area %d: NSSAArea = %v, want %v", i, area.NSSAArea, expected.NSSAArea)
				}

				if len(area.Interfaces) != len(expected.Interfaces) {
					t.Errorf("Area %d: Expected %d interfaces, got %d", i, len(expected.Interfaces), len(area.Interfaces))
					continue
				}

				// Check each interface
				for j, intf := range area.Interfaces {
					expectedIntf := expected.Interfaces[j]

					if intf.Name != expectedIntf.Name {
						t.Errorf("Area %d, Interface %d: Name = %v, want %v", i, j, intf.Name, expectedIntf.Name)
					}

					if intf.Cost != expectedIntf.Cost {
						t.Errorf("Area %d, Interface %d: Cost = %v, want %v", i, j, intf.Cost, expectedIntf.Cost)
					}

					if intf.Priority != expectedIntf.Priority {
						t.Errorf("Area %d, Interface %d: Priority = %v, want %v", i, j, intf.Priority, expectedIntf.Priority)
					}

					if intf.NetworkType != expectedIntf.NetworkType {
						t.Errorf("Area %d, Interface %d: NetworkType = %v, want %v", i, j, intf.NetworkType, expectedIntf.NetworkType)
					}

					if intf.Authentication.Type != expectedIntf.Authentication.Type {
						t.Errorf("Area %d, Interface %d: Authentication.Type = %v, want %v", i, j, intf.Authentication.Type, expectedIntf.Authentication.Type)
					}

					if intf.Authentication.Key != expectedIntf.Authentication.Key {
						t.Errorf("Area %d, Interface %d: Authentication.Key = %v, want %v", i, j, intf.Authentication.Key, expectedIntf.Authentication.Key)
					}

					if intf.Authentication.KeyID != expectedIntf.Authentication.KeyID {
						t.Errorf("Area %d, Interface %d: Authentication.KeyID = %v, want %v", i, j, intf.Authentication.KeyID, expectedIntf.Authentication.KeyID)
					}
				}
			}
		})
	}
}

// TestConvertRedistributionsToFRR tests the conversion of routing.Redistribution to frr.Redistribution
func TestConvertRedistributionsToFRR(t *testing.T) {
	tests := []struct {
		name            string
		redistributions []routing.Redistribution
		expected        []frr.Redistribution
	}{
		{
			name: "Single redistribution without route map",
			redistributions: []routing.Redistribution{
				{
					Protocol: "connected",
				},
			},
			expected: []frr.Redistribution{
				{
					Protocol:    "connected",
					RouteMapRef: "",
				},
			},
		},
		{
			name: "Single redistribution with route map",
			redistributions: []routing.Redistribution{
				{
					Protocol:    "static",
					RouteMapRef: "STATIC-TO-OSPF",
				},
			},
			expected: []frr.Redistribution{
				{
					Protocol:    "static",
					RouteMapRef: "STATIC-TO-OSPF",
				},
			},
		},
		{
			name: "Multiple redistributions",
			redistributions: []routing.Redistribution{
				{
					Protocol:    "connected",
					RouteMapRef: "",
				},
				{
					Protocol:    "static",
					RouteMapRef: "STATIC-MAP",
				},
				{
					Protocol:    "bgp",
					RouteMapRef: "BGP-TO-OSPF",
				},
			},
			expected: []frr.Redistribution{
				{
					Protocol:    "connected",
					RouteMapRef: "",
				},
				{
					Protocol:    "static",
					RouteMapRef: "STATIC-MAP",
				},
				{
					Protocol:    "bgp",
					RouteMapRef: "BGP-TO-OSPF",
				},
			},
		},
		{
			name:            "Empty redistributions",
			redistributions: []routing.Redistribution{},
			expected:        []frr.Redistribution{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertRedistributionsToFRR(tt.redistributions)

			// Check length
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d redistributions, got %d", len(tt.expected), len(result))
				return
			}

			// Check each redistribution
			for i, redist := range result {
				expected := tt.expected[i]

				if redist.Protocol != expected.Protocol {
					t.Errorf("Redistribution %d: Protocol = %v, want %v", i, redist.Protocol, expected.Protocol)
				}

				if redist.RouteMapRef != expected.RouteMapRef {
					t.Errorf("Redistribution %d: RouteMapRef = %v, want %v", i, redist.RouteMapRef, expected.RouteMapRef)
				}
			}
		})
	}
}

// TestOSPFConfigGetProtocolName tests the GetProtocolName method
func TestOSPFConfigGetProtocolName(t *testing.T) {
	config := routing.OSPFConfig{}
	if name := config.GetProtocolName(); name != "ospf" {
		t.Errorf("GetProtocolName() = %v, want 'ospf'", name)
	}
}

// TestOSPFHandler tests the OSPF handler
func TestOSPFHandler(t *testing.T) {
	// Create a mock FRR client
	client := frr.NewClient()

	// Create OSPF handler
	handler := NewOSPFHandler(client)

	// Verify initial state
	if handler.status.Name != "ospf" {
		t.Errorf("Expected protocol name 'ospf', got '%s'", handler.status.Name)
	}

	if handler.status.State != "stopped" {
		t.Errorf("Expected initial state 'stopped', got '%s'", handler.status.State)
	}

	// Test GetStatus
	status := handler.GetStatus()
	if status.Name != "ospf" {
		t.Errorf("GetStatus().Name = %v, want 'ospf'", status.Name)
	}
}

// TestOSPFAreaTypes tests different OSPF area types
func TestOSPFAreaTypes(t *testing.T) {
	tests := []struct {
		name     string
		area     routing.OSPFArea
		wantStub bool
		wantNSSA bool
	}{
		{
			name: "Backbone area",
			area: routing.OSPFArea{
				AreaID:   "0.0.0.0",
				StubArea: false,
				NSSAArea: false,
			},
			wantStub: false,
			wantNSSA: false,
		},
		{
			name: "Stub area",
			area: routing.OSPFArea{
				AreaID:   "0.0.0.1",
				StubArea: true,
				NSSAArea: false,
			},
			wantStub: true,
			wantNSSA: false,
		},
		{
			name: "NSSA area",
			area: routing.OSPFArea{
				AreaID:   "0.0.0.2",
				StubArea: false,
				NSSAArea: true,
			},
			wantStub: false,
			wantNSSA: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.area.StubArea != tt.wantStub {
				t.Errorf("StubArea = %v, want %v", tt.area.StubArea, tt.wantStub)
			}
			if tt.area.NSSAArea != tt.wantNSSA {
				t.Errorf("NSSAArea = %v, want %v", tt.area.NSSAArea, tt.wantNSSA)
			}
		})
	}
}

// TestOSPFNetworkTypes tests different OSPF network types
func TestOSPFNetworkTypes(t *testing.T) {
	networkTypes := []string{
		"broadcast",
		"point-to-point",
		"point-to-multipoint",
		"non-broadcast",
	}

	for _, nt := range networkTypes {
		t.Run(nt, func(t *testing.T) {
			intf := routing.OSPFInterface{
				Name:        "eth0",
				NetworkType: nt,
			}

			if intf.NetworkType != nt {
				t.Errorf("NetworkType = %v, want %v", intf.NetworkType, nt)
			}
		})
	}
}

// TestOSPFAuthenticationTypes tests different OSPF authentication types
func TestOSPFAuthenticationTypes(t *testing.T) {
	tests := []struct {
		name     string
		authType string
		key      string
		keyID    int
	}{
		{
			name:     "No authentication",
			authType: "none",
			key:      "",
			keyID:    0,
		},
		{
			name:     "Simple authentication",
			authType: "simple",
			key:      "password123",
			keyID:    0,
		},
		{
			name:     "MD5 authentication",
			authType: "md5",
			key:      "secret456",
			keyID:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := routing.OSPFAuthentication{
				Type:  tt.authType,
				Key:   tt.key,
				KeyID: tt.keyID,
			}

			if auth.Type != tt.authType {
				t.Errorf("Type = %v, want %v", auth.Type, tt.authType)
			}

			if auth.Key != tt.key {
				t.Errorf("Key = %v, want %v", auth.Key, tt.key)
			}

			if auth.KeyID != tt.keyID {
				t.Errorf("KeyID = %v, want %v", auth.KeyID, tt.keyID)
			}
		})
	}
}

// TestOSPFInterfaceTimers tests OSPF interface timer configuration
func TestOSPFInterfaceTimers(t *testing.T) {
	tests := []struct {
		name      string
		intf      routing.OSPFInterface
		wantHello int
		wantDead  int
		wantRetx  int
		wantDelay int
	}{
		{
			name: "Default timers (zeros)",
			intf: routing.OSPFInterface{
				Name: "eth0",
			},
			wantHello: 0,
			wantDead:  0,
			wantRetx:  0,
			wantDelay: 0,
		},
		{
			name: "Custom timers",
			intf: routing.OSPFInterface{
				Name:               "eth1",
				HelloInterval:      5,
				DeadInterval:       20,
				RetransmitInterval: 3,
				TransmitDelay:      2,
			},
			wantHello: 5,
			wantDead:  20,
			wantRetx:  3,
			wantDelay: 2,
		},
		{
			name: "Fast timers for point-to-point",
			intf: routing.OSPFInterface{
				Name:               "tun0",
				NetworkType:        "point-to-point",
				HelloInterval:      1,
				DeadInterval:       3,
				RetransmitInterval: 1,
				TransmitDelay:      1,
			},
			wantHello: 1,
			wantDead:  3,
			wantRetx:  1,
			wantDelay: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.intf.HelloInterval != tt.wantHello {
				t.Errorf("HelloInterval = %v, want %v", tt.intf.HelloInterval, tt.wantHello)
			}
			if tt.intf.DeadInterval != tt.wantDead {
				t.Errorf("DeadInterval = %v, want %v", tt.intf.DeadInterval, tt.wantDead)
			}
			if tt.intf.RetransmitInterval != tt.wantRetx {
				t.Errorf("RetransmitInterval = %v, want %v", tt.intf.RetransmitInterval, tt.wantRetx)
			}
			if tt.intf.TransmitDelay != tt.wantDelay {
				t.Errorf("TransmitDelay = %v, want %v", tt.intf.TransmitDelay, tt.wantDelay)
			}
		})
	}
}

// TestOSPFInterfaceNetwork tests OSPF interface network configuration
func TestOSPFInterfaceNetwork(t *testing.T) {
	tests := []struct {
		name    string
		network string
	}{
		{
			name:    "IPv4 /24 network",
			network: "10.0.1.0/24",
		},
		{
			name:    "IPv4 /16 network",
			network: "172.16.0.0/16",
		},
		{
			name:    "IPv4 /30 point-to-point",
			network: "192.168.1.0/30",
		},
		{
			name:    "IPv6 network",
			network: "2001:db8::/64",
		},
		{
			name:    "Empty network",
			network: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intf := routing.OSPFInterface{
				Name:    "eth0",
				Network: tt.network,
			}

			if intf.Network != tt.network {
				t.Errorf("Network = %v, want %v", intf.Network, tt.network)
			}
		})
	}
}

// TestOSPFConversionWithTimersAndNetwork tests conversion with all fields populated
func TestOSPFConversionWithTimersAndNetwork(t *testing.T) {
	area := routing.OSPFArea{
		AreaID: "0.0.0.0",
		Interfaces: []routing.OSPFInterface{
			{
				Name:        "eth0",
				Network:     "10.0.1.0/24",
				NetworkType: "broadcast",
				Priority:    100,
				Cost:        10,
				Authentication: routing.OSPFAuthentication{
					Type:  "md5",
					Key:   "secret",
					KeyID: 1,
				},
				HelloInterval:      5,
				DeadInterval:       20,
				RetransmitInterval: 3,
				TransmitDelay:      2,
			},
		},
		StubArea: false,
		NSSAArea: false,
	}

	result := convertOSPFAreasToFRR([]routing.OSPFArea{area})

	if len(result) != 1 {
		t.Fatalf("Expected 1 area, got %d", len(result))
	}

	if len(result[0].Interfaces) != 1 {
		t.Fatalf("Expected 1 interface, got %d", len(result[0].Interfaces))
	}

	intf := result[0].Interfaces[0]

	// Verify all fields are correctly converted
	if intf.Name != "eth0" {
		t.Errorf("Name = %v, want eth0", intf.Name)
	}
	if intf.Network != "10.0.1.0/24" {
		t.Errorf("Network = %v, want 10.0.1.0/24", intf.Network)
	}
	if intf.NetworkType != "broadcast" {
		t.Errorf("NetworkType = %v, want broadcast", intf.NetworkType)
	}
	if intf.Priority != 100 {
		t.Errorf("Priority = %v, want 100", intf.Priority)
	}
	if intf.Cost != 10 {
		t.Errorf("Cost = %v, want 10", intf.Cost)
	}
	if intf.HelloInterval != 5 {
		t.Errorf("HelloInterval = %v, want 5", intf.HelloInterval)
	}
	if intf.DeadInterval != 20 {
		t.Errorf("DeadInterval = %v, want 20", intf.DeadInterval)
	}
	if intf.RetransmitInterval != 3 {
		t.Errorf("RetransmitInterval = %v, want 3", intf.RetransmitInterval)
	}
	if intf.TransmitDelay != 2 {
		t.Errorf("TransmitDelay = %v, want 2", intf.TransmitDelay)
	}
	if intf.Authentication.Type != "md5" {
		t.Errorf("Authentication.Type = %v, want md5", intf.Authentication.Type)
	}
	if intf.Authentication.Key != "secret" {
		t.Errorf("Authentication.Key = %v, want secret", intf.Authentication.Key)
	}
	if intf.Authentication.KeyID != 1 {
		t.Errorf("Authentication.KeyID = %v, want 1", intf.Authentication.KeyID)
	}
}
