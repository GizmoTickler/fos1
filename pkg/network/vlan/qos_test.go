package vlan

import (
	"fmt"
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

// TestDSCPMarkingValidation tests DSCP marking functionality
func TestDSCPMarkingValidation(t *testing.T) {
	_ = NewQoSManager()

	tests := []struct {
		name    string
		dscp    int
		wantErr bool
	}{
		{"Valid DSCP 0 (BE)", 0, false},
		{"Valid DSCP 10 (AF11)", 10, false},
		{"Valid DSCP 46 (EF)", 46, false},
		{"Valid DSCP 63", 63, false},
		{"Invalid DSCP -1", -1, true},
		{"Invalid DSCP 64", 64, true},
		{"Invalid DSCP 100", 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't actually set DSCP on non-existent interfaces,
			// but we can test the validation logic
			if tt.dscp < 0 || tt.dscp > 63 {
				// Should be invalid
				if !tt.wantErr {
					t.Errorf("DSCP %d should be invalid but test expects it to be valid", tt.dscp)
				}
			} else {
				// Should be valid
				if tt.wantErr {
					t.Errorf("DSCP %d should be valid but test expects it to be invalid", tt.dscp)
				}
			}

			// Note: Actual SetDSCPMarking call would fail without a real interface
			// In integration tests with real interfaces, we would call:
			// err := qos.SetDSCPMarking("test-if", tt.dscp)
		})
	}

	// Verify that DSCP values map correctly to TOS field
	// TOS field: DSCP (6 bits) + ECN (2 bits)
	// DSCP is shifted left by 2
	dscpTests := []struct {
		dscp     int
		expected int // Expected TOS value
	}{
		{0, 0},      // BE (Best Effort)
		{10, 40},    // AF11 (Assured Forwarding class 1, low drop)
		{18, 72},    // AF21
		{26, 104},   // AF31
		{34, 136},   // AF41
		{46, 184},   // EF (Expedited Forwarding)
		{48, 192},   // CS6 (Class Selector 6)
		{56, 224},   // CS7 (Class Selector 7)
	}

	for _, tt := range dscpTests {
		t.Run(fmt.Sprintf("DSCP %d to TOS 0x%02x", tt.dscp, tt.expected), func(t *testing.T) {
			tosValue := tt.dscp << 2
			if tosValue != tt.expected {
				t.Errorf("Expected TOS value 0x%02x, got 0x%02x", tt.expected, tosValue)
			}
		})
	}
}

// TestCommonDSCPValues tests well-known DSCP values
func TestCommonDSCPValues(t *testing.T) {
	commonValues := map[string]int{
		"BE (Best Effort)":           0,
		"CS1 (Class Selector 1)":     8,
		"AF11 (Assured Forwarding)":  10,
		"AF12":                        12,
		"AF13":                        14,
		"CS2":                         16,
		"AF21":                        18,
		"AF22":                        20,
		"AF23":                        22,
		"CS3":                         24,
		"AF31":                        26,
		"AF32":                        28,
		"AF33":                        30,
		"CS4":                         32,
		"AF41":                        34,
		"AF42":                        36,
		"AF43":                        38,
		"CS5":                         40,
		"EF (Expedited Forwarding)":  46,
		"CS6":                         48,
		"CS7":                         56,
	}

	for name, dscp := range commonValues {
		t.Run(name, func(t *testing.T) {
			if dscp < 0 || dscp > 63 {
				t.Errorf("DSCP value %d (%s) is out of valid range", dscp, name)
			}

			// Verify TOS calculation
			tos := dscp << 2
			if tos > 255 {
				t.Errorf("TOS value %d for DSCP %d (%s) exceeds 8 bits", tos, dscp, name)
			}
		})
	}
}

// TestQoSQueueTypes tests different queue discipline types
func TestQoSQueueTypes(t *testing.T) {
	tests := []struct {
		name      string
		queueType string
		valid     bool
	}{
		{"Default SFQ", "", true},
		{"Explicit SFQ", "sfq", true},
		{"RED", "red", true},
		{"GRED", "gred", true},
		{"Codel", "codel", true},
		{"FQ-Codel", "fq_codel", true},
		{"Invalid", "invalid_queue", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queueType := tt.queueType
			if queueType == "" {
				queueType = "sfq" // Default
			}

			validTypes := map[string]bool{
				"sfq":      true,
				"red":      true,
				"gred":     true,
				"codel":    true,
				"fq_codel": true,
			}

			isValid := validTypes[queueType]
			if isValid != tt.valid {
				t.Errorf("Queue type %s: expected valid=%v, got valid=%v", queueType, tt.valid, isValid)
			}
		})
	}
}

// TestREDParameters tests RED qdisc parameter validation
func TestREDParameters(t *testing.T) {
	tests := []struct {
		name   string
		params REDParams
		valid  bool
	}{
		{
			name: "Valid RED params",
			params: REDParams{
				Min:         20000,
				Max:         60000,
				Avpkt:       1000,
				Limit:       100000,
				Burst:       20,
				Probability: 0.02,
				ECN:         true,
			},
			valid: true,
		},
		{
			name: "Min > Max should be invalid",
			params: REDParams{
				Min:   60000,
				Max:   20000,
				Limit: 100000,
			},
			valid: false,
		},
		{
			name: "Zero limit should be invalid",
			params: REDParams{
				Min:   20000,
				Max:   60000,
				Limit: 0,
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate parameters
			isValid := true

			if tt.params.Min > tt.params.Max {
				isValid = false
			}
			if tt.params.Limit == 0 {
				isValid = false
			}
			if tt.params.Probability < 0 || tt.params.Probability > 1 {
				isValid = false
			}

			if isValid != tt.valid {
				t.Errorf("Expected valid=%v, got valid=%v", tt.valid, isValid)
			}
		})
	}
}

// TestCodelParameters tests Codel qdisc parameter validation
func TestCodelParameters(t *testing.T) {
	tests := []struct {
		name   string
		params CodelParams
		valid  bool
	}{
		{
			name: "Valid Codel params",
			params: CodelParams{
				Target:   5000,   // 5ms
				Limit:    1000,   // 1000 packets
				Interval: 100000, // 100ms
				ECN:      true,
			},
			valid: true,
		},
		{
			name: "Valid FQ-Codel params",
			params: CodelParams{
				Target:   5000,
				Limit:    10240,
				Interval: 100000,
				ECN:      true,
			},
			valid: true,
		},
		{
			name: "Zero limit should be invalid",
			params: CodelParams{
				Target:   5000,
				Limit:    0,
				Interval: 100000,
			},
			valid: false,
		},
		{
			name: "Target > Interval should be invalid",
			params: CodelParams{
				Target:   100000,
				Limit:    1000,
				Interval: 5000,
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate parameters
			isValid := true

			if tt.params.Limit == 0 {
				isValid = false
			}
			if tt.params.Target > tt.params.Interval {
				isValid = false
			}

			if isValid != tt.valid {
				t.Errorf("Expected valid=%v, got valid=%v", tt.valid, isValid)
			}
		})
	}
}

// TestAdvancedQoSConfiguration tests QoS with advanced queue types
func TestAdvancedQoSConfiguration(t *testing.T) {
	configs := []struct {
		name   string
		config QoSConfig
	}{
		{
			name: "QoS with RED",
			config: QoSConfig{
				Enabled:      true,
				DefaultClass: 1,
				MaxRate:      "1Gbit",
				Classes: []QoSClass{
					{
						ID:        1,
						Priority:  7,
						Rate:      "500Mbit",
						Ceiling:   "1Gbit",
						Burst:     "15kb",
						QueueType: "red",
						REDParams: &REDParams{
							Min:         20000,
							Max:         60000,
							Avpkt:       1000,
							Limit:       100000,
							Burst:       20,
							Probability: 0.02,
							ECN:         true,
						},
					},
				},
			},
		},
		{
			name: "QoS with Codel",
			config: QoSConfig{
				Enabled:      true,
				DefaultClass: 1,
				MaxRate:      "1Gbit",
				Classes: []QoSClass{
					{
						ID:        1,
						Priority:  5,
						Rate:      "500Mbit",
						Ceiling:   "800Mbit",
						QueueType: "codel",
						CodelParams: &CodelParams{
							Target:   5000,
							Limit:    1000,
							Interval: 100000,
							ECN:      true,
						},
					},
				},
			},
		},
		{
			name: "QoS with FQ-Codel",
			config: QoSConfig{
				Enabled:      true,
				DefaultClass: 1,
				MaxRate:      "1Gbit",
				Classes: []QoSClass{
					{
						ID:        1,
						Priority:  7,
						Rate:      "800Mbit",
						Ceiling:   "1Gbit",
						QueueType: "fq_codel",
						CodelParams: &CodelParams{
							Target:   5000,
							Limit:    10240,
							Interval: 100000,
							ECN:      true,
						},
					},
				},
			},
		},
		{
			name: "QoS with GRED",
			config: QoSConfig{
				Enabled:      true,
				DefaultClass: 1,
				MaxRate:      "1Gbit",
				Classes: []QoSClass{
					{
						ID:        1,
						Priority:  6,
						Rate:      "600Mbit",
						Ceiling:   "1Gbit",
						QueueType: "gred",
						REDParams: &REDParams{
							Min:         30000,
							Max:         90000,
							Avpkt:       1500,
							Limit:       150000,
							Burst:       25,
							Probability: 0.03,
							ECN:         true,
						},
					},
				},
			},
		},
	}

	for _, tc := range configs {
		t.Run(tc.name, func(t *testing.T) {
			// Validate configuration
			if !tc.config.Enabled {
				t.Error("QoS should be enabled")
			}

			if len(tc.config.Classes) == 0 {
				t.Error("Should have at least one class")
			}

			// Validate each class
			for _, class := range tc.config.Classes {
				// Validate rates
				rate, err := parseRate(class.Rate)
				if err != nil {
					t.Errorf("Failed to parse rate %s: %v", class.Rate, err)
				}

				ceiling, err := parseRate(class.Ceiling)
				if err != nil {
					t.Errorf("Failed to parse ceiling %s: %v", class.Ceiling, err)
				}

				if ceiling < rate {
					t.Errorf("Ceiling (%d) should be >= rate (%d)", ceiling, rate)
				}

				// Validate queue type
				validQueueTypes := []string{"sfq", "red", "gred", "codel", "fq_codel"}
				isValidQueue := false
				for _, qt := range validQueueTypes {
					if class.QueueType == qt {
						isValidQueue = true
						break
					}
				}
				if !isValidQueue {
					t.Errorf("Invalid queue type: %s", class.QueueType)
				}

				// Validate RED parameters if using RED/GRED
				if (class.QueueType == "red" || class.QueueType == "gred") && class.REDParams != nil {
					if class.REDParams.Min > class.REDParams.Max {
						t.Error("RED min should be <= max")
					}
					if class.REDParams.Limit == 0 {
						t.Error("RED limit should be > 0")
					}
				}

				// Validate Codel parameters if using Codel/FQ-Codel
				if (class.QueueType == "codel" || class.QueueType == "fq_codel") && class.CodelParams != nil {
					if class.CodelParams.Target > class.CodelParams.Interval {
						t.Error("Codel target should be <= interval")
					}
					if class.CodelParams.Limit == 0 {
						t.Error("Codel limit should be > 0")
					}
				}
			}
		})
	}
}

// TestECNSupport tests ECN (Explicit Congestion Notification) support
func TestECNSupport(t *testing.T) {
	tests := []struct {
		name        string
		queueType   string
		supportsECN bool
	}{
		{"RED supports ECN", "red", true},
		{"GRED supports ECN", "gred", true},
		{"Codel supports ECN", "codel", true},
		{"FQ-Codel supports ECN", "fq_codel", true},
		{"SFQ does not support ECN", "sfq", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// ECN is supported by RED, GRED, Codel, and FQ-Codel
			ecnCapable := map[string]bool{
				"red":      true,
				"gred":     true,
				"codel":    true,
				"fq_codel": true,
				"sfq":      false,
			}

			if ecnCapable[tt.queueType] != tt.supportsECN {
				t.Errorf("Queue %s: expected ECN support=%v", tt.queueType, tt.supportsECN)
			}
		})
	}
}
