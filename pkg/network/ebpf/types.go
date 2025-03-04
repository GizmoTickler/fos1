package ebpf

import (
	"time"
)

// ProgramType represents the type of eBPF program
type ProgramType string

const (
	// ProgramTypeXDP is an XDP program
	ProgramTypeXDP ProgramType = "xdp"
	
	// ProgramTypeTCIngress is a TC ingress program
	ProgramTypeTCIngress ProgramType = "tc-ingress"
	
	// ProgramTypeTCEgress is a TC egress program
	ProgramTypeTCEgress ProgramType = "tc-egress"
	
	// ProgramTypeSockOps is a sockops program
	ProgramTypeSockOps ProgramType = "sockops"
	
	// ProgramTypeCGroup is a cgroup program
	ProgramTypeCGroup ProgramType = "cgroup"
)

// MapType represents the type of eBPF map
type MapType string

const (
	// MapTypeHash is a hash map
	MapTypeHash MapType = "hash"
	
	// MapTypeArray is an array map
	MapTypeArray MapType = "array"
	
	// MapTypeLRUHash is an LRU hash map
	MapTypeLRUHash MapType = "lru_hash"
	
	// MapTypePerCPUHash is a per-CPU hash map
	MapTypePerCPUHash MapType = "percpu_hash"
	
	// MapTypePerCPUArray is a per-CPU array map
	MapTypePerCPUArray MapType = "percpu_array"
	
	// MapTypeProgArray is a program array map
	MapTypeProgArray MapType = "prog_array"
	
	// MapTypeRingBuf is a ring buffer map
	MapTypeRingBuf MapType = "ringbuf"
)

// MetricType represents the type of metric
type MetricType string

const (
	// MetricTypeCounter is a counter metric
	MetricTypeCounter MetricType = "counter"
	
	// MetricTypeGauge is a gauge metric
	MetricTypeGauge MetricType = "gauge"
	
	// MetricTypeHistogram is a histogram metric
	MetricTypeHistogram MetricType = "histogram"
)

// Program represents an eBPF program
type Program struct {
	Name        string
	Description string
	Type        ProgramType
	Interface   string
	Priority    int
	Settings    map[string]interface{}
	Maps        []Map
}

// ProgramInfo represents information about a loaded program
type ProgramInfo struct {
	Name        string
	Type        ProgramType
	ID          uint32
	Tag         string
	Loaded      bool
	Attached    bool
	MapRefs     []string
	LastUpdated time.Time
}

// Map represents an eBPF map
type Map struct {
	Name        string
	Type        MapType
	KeySize     int
	ValueSize   int
	MaxEntries  int
	Flags       uint32
	ID          uint32
	PinPath     string
}

// Metric represents a metric collected from eBPF programs or maps
type Metric struct {
	Name        string
	Type        MetricType
	Value       interface{}
	Labels      map[string]string
	Description string
	LastUpdated time.Time
}

// Endpoint represents a network endpoint
type Endpoint struct {
	ID          string
	IP          string
	Namespace   string
	PodName     string
	Labels      map[string]string
}

// ProgramManager defines the interface for managing eBPF programs
type ProgramManager interface {
	// LoadProgram loads an eBPF program
	LoadProgram(program Program) error
	
	// UnloadProgram unloads an eBPF program
	UnloadProgram(name string) error
	
	// AttachProgram attaches an eBPF program to a hook
	AttachProgram(programName, hookName string) error
	
	// DetachProgram detaches an eBPF program from a hook
	DetachProgram(programName, hookName string) error
	
	// ReplaceProgram replaces an existing program with a new one
	ReplaceProgram(oldName, newName string) error
	
	// ListPrograms lists all loaded eBPF programs
	ListPrograms() ([]ProgramInfo, error)
	
	// GetProgram retrieves information about a program
	GetProgram(name string) (*ProgramInfo, error)
}

// MapManager defines the interface for managing eBPF maps
type MapManager interface {
	// CreateMap creates a new eBPF map
	CreateMap(name string, mapType MapType, keySize, valueSize, maxEntries int) (Map, error)
	
	// DeleteMap removes an eBPF map
	DeleteMap(name string) error
	
	// GetMap retrieves an eBPF map
	GetMap(name string) (Map, error)
	
	// ListMaps lists all eBPF maps
	ListMaps() ([]Map, error)
	
	// UpdateMap updates entries in an eBPF map
	UpdateMap(name string, entries map[interface{}]interface{}) error
	
	// DumpMap dumps the contents of an eBPF map
	DumpMap(name string) (map[interface{}]interface{}, error)
	
	// PinMap pins a map to the BPF filesystem
	PinMap(name, path string) error
	
	// UnpinMap unpins a map from the BPF filesystem
	UnpinMap(name string) error
}

// EBPFMetrics defines the interface for collecting metrics from eBPF programs and maps
type EBPFMetrics interface {
	// CollectMetrics collects metrics from eBPF programs and maps
	CollectMetrics() (map[string]Metric, error)
	
	// GetProgramMetrics retrieves metrics for a specific program
	GetProgramMetrics(programName string) ([]Metric, error)
	
	// GetMapMetrics retrieves metrics for a specific map
	GetMapMetrics(mapName string) ([]Metric, error)
	
	// RegisterCustomMetric registers a custom metric
	RegisterCustomMetric(name, help string, metricType MetricType) error
}

// CiliumIntegration defines the interface for integrating with Cilium
type CiliumIntegration interface {
	// GetCiliumMaps gets maps managed by Cilium
	GetCiliumMaps() ([]Map, error)
	
	// GetCiliumPrograms gets programs managed by Cilium
	GetCiliumPrograms() ([]ProgramInfo, error)
	
	// RegisterWithCilium registers a custom program with Cilium
	RegisterWithCilium(program Program) error
	
	// UnregisterFromCilium unregisters a custom program from Cilium
	UnregisterFromCilium(programName string) error
	
	// GetCiliumEndpoints gets Cilium endpoint information
	GetCiliumEndpoints() ([]Endpoint, error)
	
	// SyncWithCilium synchronizes state with Cilium
	SyncWithCilium() error
}

// ConfigTranslator defines the interface for translating CRD configs to eBPF program configs
type ConfigTranslator interface {
	// TranslateProgram translates a program CRD to a Program
	TranslateProgram(crd interface{}) (Program, error)
	
	// TranslateTrafficControl translates a traffic control CRD to a Program
	TranslateTrafficControl(crd interface{}) (Program, error)
	
	// TranslateNAT translates a NAT CRD to a Program
	TranslateNAT(crd interface{}) (Program, error)
	
	// TranslateContainerPolicy translates a container policy CRD to a Program
	TranslateContainerPolicy(crd interface{}) (Program, error)
}

// EBPFController manages the eBPF programs and maps
type EBPFController struct {
	ProgramManager    ProgramManager
	MapManager        MapManager
	CiliumIntegration CiliumIntegration
	Metrics           EBPFMetrics
	ConfigTranslator  ConfigTranslator
}

// DDoSProtectionConfig defines configuration for DDoS protection
type DDoSProtectionConfig struct {
	RateLimiting struct {
		Enabled              bool
		PacketsPerSecond     int
		ConnectionsPerSecond int
		ConnectionsPerIP     int
	}
	SYNFloodProtection  bool
	ICMPFloodProtection bool
	UDPFloodProtection  bool
	Blacklist           struct {
		Enabled  bool
		IPSetRef string
	}
}

// NATConfig defines configuration for NAT
type NATConfig struct {
	Interfaces struct {
		Source      string
		Destination string
	}
	Type         string // masquerade, static
	IPVersion    string // ipv4, ipv6, both
	PortMappings []struct {
		Protocol     string
		InternalIP   string
		InternalPort int
		ExternalPort int
	}
	SourceCIDRs       []string
	ExcludeCIDRs      []string
	ConnectionTracking struct {
		Enabled        bool
		TCPTimeout     int
		UDPTimeout     int
		MaxConnections int
	}
	Hairpinning         bool
	EndpointIndependent bool
}

// TrafficControlConfig defines configuration for traffic control
type TrafficControlConfig struct {
	Interface           string
	Direction           string // ingress, egress
	Priority            int
	QueueingDiscipline  string
	Classes             []TrafficClass
}

// TrafficClass defines a traffic class for QoS
type TrafficClass struct {
	Name     string
	Priority int
	Rate     string
	Ceiling  string
	Match    struct {
		Applications []string
		IPProto      string
		DstPorts     []interface{} // Can be int or string range
		SrcPorts     []interface{}
	}
	MarkDSCP int
}

// ContainerPolicyConfig defines configuration for container network policies
type ContainerPolicyConfig struct {
	Selector struct {
		MatchLabels map[string]string
	}
	Ingress []struct {
		From struct {
			PodSelector struct {
				MatchLabels map[string]string
			}
		}
		Ports []struct {
			Protocol string
			Port     int
		}
	}
	Egress []struct {
		To struct {
			PodSelector struct {
				MatchLabels map[string]string
			}
		}
		Ports []struct {
			Protocol string
			Port     int
		}
	}
	Enforcement string // ebpf-cgroup
}