package ebpf

import (
	"encoding/binary"
	"net"
)

// Go struct definitions mirroring BPF C structs from cilium_common.h.
// These types are used for typed map operations and must match the
// kernel-side structs exactly in size and layout.

// XDPConfig mirrors `struct config` used by XDP programs.
// Map: "config_map", key: uint32(0), value: XDPConfig
type XDPConfig struct {
	RateLimit         uint32
	RatePeriod        uint32
	EnableBlacklist   uint8
	EnableRateLimit   uint8
	EnableStateful    uint8
	DefaultAction     uint8
	CiliumIntegration uint8
	HWOffload         uint8
	EnableIPv6        uint8
	_                 [1]uint8 // padding to align
}

// IPv4BlacklistKey mirrors `struct bpf_lpm_trie_key4` for LPM trie lookups.
// Map: "ipv4_blacklist", key: IPv4BlacklistKey, value: uint32
type IPv4BlacklistKey struct {
	PrefixLen uint32
	Addr      uint32
}

// NewIPv4BlacklistKey creates a key from a CIDR string (e.g., "10.0.0.0/8").
func NewIPv4BlacklistKey(cidr string) (IPv4BlacklistKey, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return IPv4BlacklistKey{}, err
	}
	ones, _ := ipNet.Mask.Size()
	ipv4 := ip.To4()
	return IPv4BlacklistKey{
		PrefixLen: uint32(ones),
		Addr:      binary.BigEndian.Uint32(ipv4),
	}, nil
}

// NewIPv4BlacklistKeyFromIP creates a key for a single IP (/32).
func NewIPv4BlacklistKeyFromIP(ip net.IP) IPv4BlacklistKey {
	ipv4 := ip.To4()
	return IPv4BlacklistKey{
		PrefixLen: 32,
		Addr:      binary.BigEndian.Uint32(ipv4),
	}
}

// IPv6Addr mirrors `struct ipv6_addr` — 16 bytes.
type IPv6Addr [16]byte

// NewIPv6Addr creates an IPv6Addr from a net.IP.
func NewIPv6Addr(ip net.IP) IPv6Addr {
	var addr IPv6Addr
	copy(addr[:], ip.To16())
	return addr
}

// IPv6BlacklistKey mirrors `struct bpf_lpm_trie_key6` for LPM trie lookups.
// Map: "ipv6_blacklist", key: IPv6BlacklistKey, value: uint32
type IPv6BlacklistKey struct {
	PrefixLen uint32
	Addr      IPv6Addr
}

// FlowKey4 mirrors `struct flow_key4` for connection tracking.
// Map: "ipv4_state_map", key: FlowKey4, value: uint8
type FlowKey4 struct {
	SrcAddr uint32
	DstAddr uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	_       [3]uint8 // padding
}

// FlowKey6 mirrors `struct flow_key6` for IPv6 connection tracking.
// Map: "ipv6_state_map", key: FlowKey6, value: uint8
type FlowKey6 struct {
	SrcAddr IPv6Addr
	DstAddr IPv6Addr
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	_       [3]uint8 // padding
}

// CiliumIdentity mirrors `struct cilium_identity`.
type CiliumIdentity struct {
	ID       uint32
	Reserved uint32
}

// CiliumPolicyVerdict mirrors `struct cilium_policy_verdict`.
type CiliumPolicyVerdict struct {
	Verdict      uint8
	HasPolicy    uint8
	Pad1         uint8
	Pad2         uint8
	RedirectPort uint32
}

// CiliumCTEntry mirrors `struct cilium_ct_entry`.
type CiliumCTEntry struct {
	LastSeen  uint64
	Flags     uint32
	RxPackets uint32
	RxBytes   uint32
	TxPackets uint32
	TxBytes   uint32
	Lifetime  uint16
	CiliumID  uint16
}

// BPFTrafficClass mirrors `struct traffic_class` in BPF programs for QoS.
type BPFTrafficClass struct {
	Priority     uint32
	Mark         uint32
	RateLimit    uint32
	BurstLimit   uint32
	QueueID      uint32
	DSCPValue    uint8
	_            [3]uint8 // padding
}

// NATEntry mirrors `struct nat_entry` for NAT maps.
type NATEntry struct {
	OrigSrcAddr uint32
	OrigDstAddr uint32
	OrigSrcPort uint16
	OrigDstPort uint16
	NewSrcAddr  uint32
	NewDstAddr  uint32
	NewSrcPort  uint16
	NewDstPort  uint16
	Proto       uint8
	Flags       uint8
	_           [2]uint8 // padding
}
