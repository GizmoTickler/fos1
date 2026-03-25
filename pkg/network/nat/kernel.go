//go:build linux

package nat

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

const (
	natTableName = "fos1-nat"
)

// KernelNATManager manages NAT rules via nftables netlink.
type KernelNATManager struct {
	conn      *nftables.Conn
	natTable  *nftables.Table
	preChain  *nftables.Chain
	postChain *nftables.Chain
	rules     map[string][]*nftables.Rule // policyKey -> rules
	mu        sync.Mutex
}

// NewKernelNATManager creates a new kernel-based NAT manager.
func NewKernelNATManager() (*KernelNATManager, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create nftables connection: %w", err)
	}

	mgr := &KernelNATManager{
		conn:  conn,
		rules: make(map[string][]*nftables.Rule),
	}

	if err := mgr.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize NAT tables: %w", err)
	}

	return mgr, nil
}

// initialize creates the NAT table and base chains.
func (m *KernelNATManager) initialize() error {
	// Create NAT table (inet family for dual-stack)
	m.natTable = m.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   natTableName,
	})

	policyAccept := nftables.ChainPolicyAccept

	// Prerouting chain for DNAT
	m.preChain = m.conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    m.natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Policy:   &policyAccept,
	})

	// Postrouting chain for SNAT/masquerade
	m.postChain = m.conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    m.natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   &policyAccept,
	})

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush NAT initialization: %w", err)
	}

	klog.Info("NAT nftables tables initialized")
	return nil
}

// ApplySNAT creates a Source NAT rule.
func (m *KernelNATManager) ApplySNAT(policyKey, sourceNet, outIface, externalIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, srcNet, err := net.ParseCIDR(sourceNet)
	if err != nil {
		return fmt.Errorf("invalid source network %s: %w", sourceNet, err)
	}

	extIP := net.ParseIP(externalIP)
	if extIP == nil {
		return fmt.Errorf("invalid external IP: %s", externalIP)
	}
	extIPv4 := extIP.To4()
	if extIPv4 == nil {
		return fmt.Errorf("SNAT currently supports IPv4 only, got: %s", externalIP)
	}

	srcIPBytes := srcNet.IP.To4()
	maskBits, _ := srcNet.Mask.Size()

	exprs := []expr.Any{
		// Match source network
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           net.CIDRMask(maskBits, 32),
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     srcIPBytes,
		},
	}

	// Match output interface if specified
	if outIface != "" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(outIface),
			},
		)
	}

	// SNAT to external IP
	exprs = append(exprs,
		&expr.Immediate{
			Register: 1,
			Data:     extIPv4,
		},
		&expr.NAT{
			Type:       expr.NATTypeSourceNAT,
			Family:     unix.NFPROTO_IPV4,
			RegAddrMin: 1,
		},
	)

	rule := m.conn.AddRule(&nftables.Rule{
		Table: m.natTable,
		Chain: m.postChain,
		Exprs: exprs,
	})

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply SNAT rule: %w", err)
	}

	m.rules[policyKey] = append(m.rules[policyKey], rule)
	klog.Infof("Applied SNAT: %s -> %s via %s", sourceNet, externalIP, outIface)
	return nil
}

// ApplyMasquerade creates a masquerade NAT rule.
func (m *KernelNATManager) ApplyMasquerade(policyKey, sourceNet, outIface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, srcNet, err := net.ParseCIDR(sourceNet)
	if err != nil {
		return fmt.Errorf("invalid source network %s: %w", sourceNet, err)
	}

	srcIPBytes := srcNet.IP.To4()
	maskBits, _ := srcNet.Mask.Size()

	exprs := []expr.Any{
		// Match source network
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           net.CIDRMask(maskBits, 32),
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     srcIPBytes,
		},
	}

	// Match output interface
	if outIface != "" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(outIface),
			},
		)
	}

	// Masquerade
	exprs = append(exprs, &expr.Masq{})

	rule := m.conn.AddRule(&nftables.Rule{
		Table: m.natTable,
		Chain: m.postChain,
		Exprs: exprs,
	})

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply masquerade rule: %w", err)
	}

	m.rules[policyKey] = append(m.rules[policyKey], rule)
	klog.Infof("Applied masquerade: %s via %s", sourceNet, outIface)
	return nil
}

// ApplyDNAT creates a Destination NAT (port forwarding) rule.
func (m *KernelNATManager) ApplyDNAT(policyKey, externalIP string, externalPort uint16, proto string, internalIP string, internalPort uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	intIP := net.ParseIP(internalIP).To4()
	if intIP == nil {
		return fmt.Errorf("invalid internal IP: %s", internalIP)
	}

	var l4proto byte
	switch proto {
	case "tcp":
		l4proto = unix.IPPROTO_TCP
	case "udp":
		l4proto = unix.IPPROTO_UDP
	default:
		return fmt.Errorf("unsupported protocol for DNAT: %s", proto)
	}

	exprs := []expr.Any{
		// Match L4 protocol
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{l4proto},
		},
	}

	// Match external IP if specified
	if externalIP != "" {
		extIP := net.ParseIP(externalIP).To4()
		if extIP != nil {
			exprs = append(exprs,
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       16,
					Len:          4,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     extIP,
				},
			)
		}
	}

	// Match destination port
	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     portBytes(externalPort),
		},
	)

	// DNAT to internal IP:port
	exprs = append(exprs,
		&expr.Immediate{Register: 1, Data: intIP},
		&expr.Immediate{Register: 2, Data: portBytes(internalPort)},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      unix.NFPROTO_IPV4,
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	)

	rule := m.conn.AddRule(&nftables.Rule{
		Table: m.natTable,
		Chain: m.preChain,
		Exprs: exprs,
	})

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply DNAT rule: %w", err)
	}

	m.rules[policyKey] = append(m.rules[policyKey], rule)
	klog.Infof("Applied DNAT: %s:%d/%s -> %s:%d", externalIP, externalPort, proto, internalIP, internalPort)
	return nil
}

// RemoveNATRules removes all NAT rules for a given policy key.
func (m *KernelNATManager) RemoveNATRules(policyKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rules, exists := m.rules[policyKey]
	if !exists {
		return nil
	}

	for _, rule := range rules {
		if err := m.conn.DelRule(rule); err != nil {
			klog.Warningf("Failed to delete NAT rule for %s: %v", policyKey, err)
		}
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush NAT rule deletion for %s: %w", policyKey, err)
	}

	delete(m.rules, policyKey)
	klog.Infof("Removed NAT rules for policy %s", policyKey)
	return nil
}

// Close cleans up the NAT manager.
func (m *KernelNATManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Delete the NAT table (cascades to all chains and rules)
	m.conn.DelTable(m.natTable)
	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to clean up NAT table: %w", err)
	}

	klog.Info("NAT nftables tables cleaned up")
	return nil
}

// GetActiveRuleCount returns the number of active NAT rules.
func (m *KernelNATManager) GetActiveRuleCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for _, rules := range m.rules {
		count += len(rules)
	}
	return count
}

// ifname returns the interface name bytes padded to 16 bytes (IFNAMSIZ).
func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

// portBytes converts a port number to network-order bytes.
func portBytes(port uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, port)
	return b
}
