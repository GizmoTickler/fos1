package cilium

import (
	"context"
	"testing"
)

func TestCreateNAT_Validation(t *testing.T) {
	client := NewDefaultCiliumClient("", "")

	tests := []struct {
		name    string
		config  *CiliumNATConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "missing source network",
			config: &CiliumNATConfig{
				DestinationIface: "eth0",
			},
			wantErr: true,
			errMsg:  "source network is required",
		},
		{
			name: "missing destination interface",
			config: &CiliumNATConfig{
				SourceNetwork: "192.168.1.0/24",
			},
			wantErr: true,
			errMsg:  "destination interface is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.CreateNAT(context.Background(), tt.config)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errMsg)
				}
			} else {
				// Note: valid configs will fail because kubectl is not available,
				// which is expected in unit tests
			}
		})
	}
}

func TestCreateNAT64_Validation(t *testing.T) {
	client := NewDefaultCiliumClient("", "")

	tests := []struct {
		name    string
		config  *NAT64Config
		wantErr bool
	}{
		{
			name: "missing source network",
			config: &NAT64Config{
				DestinationIface: "eth0",
			},
			wantErr: true,
		},
		{
			name: "missing destination interface",
			config: &NAT64Config{
				SourceNetwork: "2001:db8::/32",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.CreateNAT64(context.Background(), tt.config)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestCreatePortForward_Validation(t *testing.T) {
	client := NewDefaultCiliumClient("", "")

	tests := []struct {
		name    string
		config  *PortForwardConfig
		wantErr bool
	}{
		{
			name: "missing external IP",
			config: &PortForwardConfig{
				ExternalPort: 80,
				Protocol:     "tcp",
				InternalIP:   "10.0.0.1",
				InternalPort: 80,
			},
			wantErr: true,
		},
		{
			name: "missing internal IP",
			config: &PortForwardConfig{
				ExternalIP:   "1.2.3.4",
				ExternalPort: 80,
				Protocol:     "tcp",
				InternalPort: 80,
			},
			wantErr: true,
		},
		{
			name: "invalid external port zero",
			config: &PortForwardConfig{
				ExternalIP:   "1.2.3.4",
				ExternalPort: 0,
				Protocol:     "tcp",
				InternalIP:   "10.0.0.1",
				InternalPort: 80,
			},
			wantErr: true,
		},
		{
			name: "invalid external port too high",
			config: &PortForwardConfig{
				ExternalIP:   "1.2.3.4",
				ExternalPort: 70000,
				Protocol:     "tcp",
				InternalIP:   "10.0.0.1",
				InternalPort: 80,
			},
			wantErr: true,
		},
		{
			name: "invalid internal port",
			config: &PortForwardConfig{
				ExternalIP:   "1.2.3.4",
				ExternalPort: 80,
				Protocol:     "tcp",
				InternalIP:   "10.0.0.1",
				InternalPort: -1,
			},
			wantErr: true,
		},
		{
			name: "missing protocol",
			config: &PortForwardConfig{
				ExternalIP:   "1.2.3.4",
				ExternalPort: 80,
				InternalIP:   "10.0.0.1",
				InternalPort: 80,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.CreatePortForward(context.Background(), tt.config)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestSanitizeNetworkName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.0/24", "192-168-1-0-24"},
		{"fd00::/64", "fd00---64"},
		{"10.0.0.1", "10-0-0-1"},
		{"eth0", "eth0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeNetworkName(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeNetworkName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDefaultNAT64Prefix(t *testing.T) {
	if DefaultNAT64Prefix != "64:ff9b::/96" {
		t.Errorf("expected DefaultNAT64Prefix to be 64:ff9b::/96, got %s", DefaultNAT64Prefix)
	}
}

// TestMockCiliumClient_NATMethods verifies that the mock client in router_test.go
// properly implements the full CiliumClient interface including NAT methods.
func TestMockCiliumClient_NATMethods(t *testing.T) {
	mock := NewMockCiliumClient()

	// Verify all NAT methods work
	if err := mock.CreateNAT(context.Background(), &CiliumNATConfig{
		SourceNetwork:    "192.168.1.0/24",
		DestinationIface: "eth0",
	}); err != nil {
		t.Errorf("CreateNAT failed: %v", err)
	}

	if err := mock.RemoveNAT(context.Background(), &CiliumNATConfig{
		SourceNetwork:    "192.168.1.0/24",
		DestinationIface: "eth0",
	}); err != nil {
		t.Errorf("RemoveNAT failed: %v", err)
	}

	if err := mock.CreateNAT64(context.Background(), &NAT64Config{
		SourceNetwork:    "2001:db8::/32",
		DestinationIface: "eth0",
		Prefix64:         DefaultNAT64Prefix,
	}); err != nil {
		t.Errorf("CreateNAT64 failed: %v", err)
	}

	if err := mock.RemoveNAT64(context.Background(), &NAT64Config{
		SourceNetwork:    "2001:db8::/32",
		DestinationIface: "eth0",
	}); err != nil {
		t.Errorf("RemoveNAT64 failed: %v", err)
	}

	if err := mock.CreatePortForward(context.Background(), &PortForwardConfig{
		ExternalIP:   "1.2.3.4",
		ExternalPort: 80,
		Protocol:     "tcp",
		InternalIP:   "10.0.0.1",
		InternalPort: 8080,
	}); err != nil {
		t.Errorf("CreatePortForward failed: %v", err)
	}

	if err := mock.RemovePortForward(context.Background(), &PortForwardConfig{
		ExternalIP:   "1.2.3.4",
		ExternalPort: 80,
		Protocol:     "tcp",
		InternalIP:   "10.0.0.1",
		InternalPort: 8080,
	}); err != nil {
		t.Errorf("RemovePortForward failed: %v", err)
	}
}
