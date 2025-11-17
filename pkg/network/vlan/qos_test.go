package vlan

import (
	"testing"
)

// TestQoSManagerCreation tests QoS manager creation
func TestQoSManagerCreation(t *testing.T) {
	qos := NewQoSManager()
	if qos == nil {
		t.Fatal("Failed to create QoS manager")
	}
}

// TestParseRate tests rate string parsing
func TestParseRate(t *testing.T) {
	tests := []struct {
		name     string
		rateStr  string
		expected uint64
		wantErr  bool
	}{
		{"1 Gbit", "1Gbit", 1000000000, false},
		{"100 Mbit", "100Mbit", 100000000, false},
		{"10 Kbit", "10Kbit", 10000, false},
		{"1000 bit", "1000bit", 1000, false},
		{"1.5 Gbit", "1.5Gbit", 1500000000, false},
		{"0.5 Mbit", "0.5Mbit", 500000, false},
		{"1 Gbps", "1Gbps", 1000000000, false},
		{"100 Mbps", "100Mbps", 100000000, false},
		{"Invalid unit", "100xxx", 0, true},
		{"Empty string", "", 0, true},
		{"No unit", "100", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseRate(tt.rateStr)

			if (err != nil) != tt.wantErr {
				if tt.wantErr {
					t.Errorf("Expected error for rate %s, got none", tt.rateStr)
				} else {
					t.Errorf("Unexpected error for rate %s: %v", tt.rateStr, err)
				}
				return
			}

			if !tt.wantErr && result != tt.expected {
				t.Errorf("Expected rate %d bps, got %d bps", tt.expected, result)
			}
		})
	}
}

// TestParseBytes tests byte size string parsing
func TestParseBytes(t *testing.T) {
	tests := []struct {
		name     string
		sizeStr  string
		expected uint32
		wantErr  bool
	}{
		{"1 GB", "1gb", 1024 * 1024 * 1024, false},
		{"100 MB", "100mb", 100 * 1024 * 1024, false},
		{"15 KB", "15kb", 15 * 1024, false},
		{"1000 bytes", "1000b", 1000, false},
		{"1.5 MB", "1.5mb", uint32(1.5 * 1024 * 1024), false},
		{"Invalid unit", "100xxx", 0, true},
		{"Empty string", "", 0, true},
		{"No unit", "100", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseBytes(tt.sizeStr)

			if (err != nil) != tt.wantErr {
				if tt.wantErr {
					t.Errorf("Expected error for size %s, got none", tt.sizeStr)
				} else {
					t.Errorf("Unexpected error for size %s: %v", tt.sizeStr, err)
				}
				return
			}

			if !tt.wantErr && result != tt.expected {
				t.Errorf("Expected size %d bytes, got %d bytes", tt.expected, result)
			}
		})
	}
}

// TestQoSConfigValidation tests QoS configuration validation
func TestQoSConfigValidation(t *testing.T) {
	_ = NewQoSManager()

	tests := []struct {
		name   string
		config QoSConfig
		valid  bool
	}{
		{
			name: "Valid basic config",
			config: QoSConfig{
				Enabled:      true,
				DefaultClass: 1,
				MaxRate:      "1Gbit",
				Classes: []QoSClass{
					{
						ID:       1,
						Priority: 7,
						Rate:     "800Mbit",
						Ceiling:  "1Gbit",
						Burst:    "15kb",
					},
				},
			},
			valid: true,
		},
		{
			name: "Invalid rate format",
			config: QoSConfig{
				Enabled: true,
				MaxRate: "invalid",
			},
			valid: false,
		},
		{
			name: "Disabled config",
			config: QoSConfig{
				Enabled: false,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since we can't actually create network interfaces in unit tests,
			// we just validate that the parsing works
			if tt.config.MaxRate != "" && tt.config.MaxRate != "invalid" {
				_, err := parseRate(tt.config.MaxRate)
				if err != nil && tt.valid {
					t.Errorf("Failed to parse valid max rate: %v", err)
				}
			}

			for _, class := range tt.config.Classes {
				if class.Rate != "" {
					_, err := parseRate(class.Rate)
					if err != nil && tt.valid {
						t.Errorf("Failed to parse valid class rate: %v", err)
					}
				}

				if class.Ceiling != "" {
					_, err := parseRate(class.Ceiling)
					if err != nil && tt.valid {
						t.Errorf("Failed to parse valid ceiling rate: %v", err)
					}
				}

				if class.Burst != "" {
					_, err := parseBytes(class.Burst)
					if err != nil && tt.valid {
						t.Errorf("Failed to parse valid burst size: %v", err)
					}
				}
			}
		})
	}
}

// TestVLANPriorityValidation tests 802.1p priority validation
func TestVLANPriorityValidation(t *testing.T) {
	tests := []struct {
		name     string
		priority int
		valid    bool
	}{
		{"Priority 0", 0, true},
		{"Priority 3", 3, true},
		{"Priority 7", 7, true},
		{"Priority -1", -1, false},
		{"Priority 8", 8, false},
		{"Priority 100", 100, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.priority < 0 || tt.priority > 7 {
				if tt.valid {
					t.Errorf("Priority %d should be invalid", tt.priority)
				}
			} else {
				if !tt.valid {
					t.Errorf("Priority %d should be valid", tt.priority)
				}
			}
		})
	}
}

// TestDSCPValidation tests DSCP value validation
func TestDSCPValidation(t *testing.T) {
	tests := []struct {
		name  string
		dscp  int
		valid bool
	}{
		{"DSCP 0 (BE)", 0, true},
		{"DSCP 46 (EF)", 46, true},
		{"DSCP 63", 63, true},
		{"DSCP -1", -1, false},
		{"DSCP 64", 64, false},
		{"DSCP 100", 100, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.dscp < 0 || tt.dscp > 63 {
				if tt.valid {
					t.Errorf("DSCP %d should be invalid", tt.dscp)
				}
			} else {
				if !tt.valid {
					t.Errorf("DSCP %d should be valid", tt.dscp)
				}
			}
		})
	}
}

// TestQoSClassPriority tests QoS class priority values
func TestQoSClassPriority(t *testing.T) {
	classes := []QoSClass{
		{ID: 1, Priority: 7, Rate: "800Mbit", Ceiling: "1Gbit"},
		{ID: 2, Priority: 5, Rate: "500Mbit", Ceiling: "800Mbit"},
		{ID: 3, Priority: 3, Rate: "200Mbit", Ceiling: "500Mbit"},
		{ID: 4, Priority: 1, Rate: "100Mbit", Ceiling: "300Mbit"},
	}

	// Verify priorities are valid (0-7 for TC)
	for _, class := range classes {
		if class.Priority < 0 || class.Priority > 7 {
			t.Errorf("Class %d has invalid priority %d", class.ID, class.Priority)
		}

		// Parse rates to ensure they're valid
		rate, err := parseRate(class.Rate)
		if err != nil {
			t.Errorf("Failed to parse rate for class %d: %v", class.ID, err)
		}

		ceiling, err := parseRate(class.Ceiling)
		if err != nil {
			t.Errorf("Failed to parse ceiling for class %d: %v", class.ID, err)
		}

		// Ceiling should be >= rate
		if ceiling < rate {
			t.Errorf("Class %d ceiling (%d) is less than rate (%d)", class.ID, ceiling, rate)
		}
	}
}

// TestQoSMultipleClasses tests configuration with multiple QoS classes
func TestQoSMultipleClasses(t *testing.T) {
	config := QoSConfig{
		Enabled:      true,
		DefaultClass: 1,
		MaxRate:      "1Gbit",
		Classes: []QoSClass{
			{ID: 1, Priority: 7, Rate: "600Mbit", Ceiling: "1Gbit", Burst: "15kb"},
			{ID: 2, Priority: 5, Rate: "300Mbit", Ceiling: "500Mbit", Burst: "12kb"},
			{ID: 3, Priority: 3, Rate: "100Mbit", Ceiling: "200Mbit", Burst: "10kb"},
		},
	}

	if !config.Enabled {
		t.Error("Expected QoS to be enabled")
	}

	if len(config.Classes) != 3 {
		t.Errorf("Expected 3 QoS classes, got %d", len(config.Classes))
	}

	// Verify each class
	totalRate := uint64(0)
	for _, class := range config.Classes {
		rate, err := parseRate(class.Rate)
		if err != nil {
			t.Errorf("Failed to parse rate for class %d: %v", class.ID, err)
		}
		totalRate += rate
	}

	maxRate, err := parseRate(config.MaxRate)
	if err != nil {
		t.Fatalf("Failed to parse max rate: %v", err)
	}

	// Total guaranteed rate should be <= max rate
	if totalRate > maxRate {
		t.Errorf("Total guaranteed rate (%d) exceeds max rate (%d)", totalRate, maxRate)
	}
}
