package rules

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/GizmoTickler/fos1/pkg/security/policy"
)

// RuleBuilder builds nftables rules from FilterPolicy
type RuleBuilder struct {
	policy *policy.FilterPolicy
}

// NewRuleBuilder creates a new rule builder
func NewRuleBuilder(policy *policy.FilterPolicy) *RuleBuilder {
	return &RuleBuilder{
		policy: policy,
	}
}

// BuildRules builds nftables rules from the filter policy
func (b *RuleBuilder) BuildRules(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
	var rules []*nftables.Rule

	// Build rules for each action in the policy
	for _, action := range b.policy.Spec.Actions {
		// Build expressions based on selectors
		exprs, err := b.buildExpressions(&b.policy.Spec.Selectors, table.Family)
		if err != nil {
			return nil, fmt.Errorf("failed to build expressions: %w", err)
		}

		// Add counter
		exprs = append(exprs, &expr.Counter{})

		// Add verdict based on action type
		verdict, err := b.buildVerdict(&action)
		if err != nil {
			return nil, fmt.Errorf("failed to build verdict: %w", err)
		}
		exprs = append(exprs, verdict)

		// Create the rule
		rule := &nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: exprs,
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// buildExpressions builds nftables expressions from selectors
func (b *RuleBuilder) buildExpressions(selectors *policy.FilterSelectors, family nftables.TableFamily) ([]expr.Any, error) {
	var exprs []expr.Any

	// Build source selectors
	for _, src := range selectors.Sources {
		srcExprs, err := b.buildSourceExpression(&src, family)
		if err != nil {
			return nil, fmt.Errorf("failed to build source expression: %w", err)
		}
		exprs = append(exprs, srcExprs...)
	}

	// Build destination selectors
	for _, dst := range selectors.Destinations {
		dstExprs, err := b.buildDestinationExpression(&dst, family)
		if err != nil {
			return nil, fmt.Errorf("failed to build destination expression: %w", err)
		}
		exprs = append(exprs, dstExprs...)
	}

	// Build port selectors
	for _, port := range selectors.Ports {
		portExprs, err := b.buildPortExpression(&port, family)
		if err != nil {
			return nil, fmt.Errorf("failed to build port expression: %w", err)
		}
		exprs = append(exprs, portExprs...)
	}

	return exprs, nil
}

// buildSourceExpression builds expressions for source matching
func (b *RuleBuilder) buildSourceExpression(selector *policy.Selector, family nftables.TableFamily) ([]expr.Any, error) {
	var exprs []expr.Any

	switch selector.Type {
	case "ip":
		// Match source IP address
		for _, val := range selector.Values {
			ipStr, ok := val.(string)
			if !ok {
				continue
			}

			ip, ipnet, err := net.ParseCIDR(ipStr)
			if err != nil {
				// Try parsing as IP
				ip = net.ParseIP(ipStr)
				if ip == nil {
					return nil, fmt.Errorf("invalid IP address: %s", ipStr)
				}
			}

			offset := uint32(12) // IPv4 source address offset
			length := uint32(4)
			if family == nftables.TableFamilyIPv6 {
				offset = 8 // IPv6 source address offset
				length = 16
			}

			exprs = append(exprs,
				// Load source address
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,
					Len:          length,
				},
			)

			if ipnet != nil {
				// CIDR match with mask
				mask := ipnet.Mask
				exprs = append(exprs,
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            length,
						Mask:           mask,
						Xor:            make([]byte, length),
					},
				)
				ip = ipnet.IP
			}

			// Compare
			var ipData []byte
			if family == nftables.TableFamilyIPv4 {
				ipData = ip.To4()
			} else {
				ipData = ip.To16()
			}

			exprs = append(exprs,
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ipData,
				},
			)
		}

	case "interface":
		// Match input interface
		for _, val := range selector.Values {
			ifname, ok := val.(string)
			if !ok {
				continue
			}

			exprs = append(exprs,
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte(ifname + "\x00"),
				},
			)
		}

	case "ipset":
		// Match against IP set (requires set to be created first)
		for _, val := range selector.Values {
			setName, ok := val.(string)
			if !ok {
				continue
			}

			offset := uint32(12) // IPv4 source address offset
			length := uint32(4)
			if family == nftables.TableFamilyIPv6 {
				offset = 8 // IPv6 source address offset
				length = 16
			}

			exprs = append(exprs,
				// Load source address
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,
					Len:          length,
				},
				// Lookup in set
				&expr.Lookup{
					SourceRegister: 1,
					SetName:        setName,
				},
			)
		}
	}

	return exprs, nil
}

// buildDestinationExpression builds expressions for destination matching
func (b *RuleBuilder) buildDestinationExpression(selector *policy.Selector, family nftables.TableFamily) ([]expr.Any, error) {
	var exprs []expr.Any

	switch selector.Type {
	case "ip":
		// Match destination IP address
		for _, val := range selector.Values {
			ipStr, ok := val.(string)
			if !ok {
				continue
			}

			ip, ipnet, err := net.ParseCIDR(ipStr)
			if err != nil {
				// Try parsing as IP
				ip = net.ParseIP(ipStr)
				if ip == nil {
					return nil, fmt.Errorf("invalid IP address: %s", ipStr)
				}
			}

			offset := uint32(16) // IPv4 destination address offset
			length := uint32(4)
			if family == nftables.TableFamilyIPv6 {
				offset = 24 // IPv6 destination address offset
				length = 16
			}

			exprs = append(exprs,
				// Load destination address
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,
					Len:          length,
				},
			)

			if ipnet != nil {
				// CIDR match with mask
				mask := ipnet.Mask
				exprs = append(exprs,
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            length,
						Mask:           mask,
						Xor:            make([]byte, length),
					},
				)
				ip = ipnet.IP
			}

			// Compare
			var ipData []byte
			if family == nftables.TableFamilyIPv4 {
				ipData = ip.To4()
			} else {
				ipData = ip.To16()
			}

			exprs = append(exprs,
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ipData,
				},
			)
		}

	case "interface":
		// Match output interface
		for _, val := range selector.Values {
			ifname, ok := val.(string)
			if !ok {
				continue
			}

			exprs = append(exprs,
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte(ifname + "\x00"),
				},
			)
		}

	case "ipset":
		// Match against IP set
		for _, val := range selector.Values {
			setName, ok := val.(string)
			if !ok {
				continue
			}

			offset := uint32(16) // IPv4 destination address offset
			length := uint32(4)
			if family == nftables.TableFamilyIPv6 {
				offset = 24 // IPv6 destination address offset
				length = 16
			}

			exprs = append(exprs,
				// Load destination address
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,
					Len:          length,
				},
				// Lookup in set
				&expr.Lookup{
					SourceRegister: 1,
					SetName:        setName,
				},
			)
		}
	}

	return exprs, nil
}

// buildPortExpression builds expressions for port matching
func (b *RuleBuilder) buildPortExpression(selector *policy.PortSelector, family nftables.TableFamily) ([]expr.Any, error) {
	var exprs []expr.Any

	// Match protocol
	proto := protocolToNumber(strings.ToLower(selector.Protocol))
	if proto == 0 {
		return nil, fmt.Errorf("unsupported protocol: %s", selector.Protocol)
	}

	exprs = append(exprs,
		// Load L4 protocol
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{proto},
		},
	)

	// Match ports
	for _, port := range selector.Ports {
		portData := make([]byte, 2)
		binary.BigEndian.PutUint16(portData, uint16(port))

		exprs = append(exprs,
			// Load destination port
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // Destination port offset for TCP/UDP
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     portData,
			},
		)
	}

	return exprs, nil
}

// buildVerdict builds the verdict expression based on action
func (b *RuleBuilder) buildVerdict(action *policy.PolicyAction) (expr.Any, error) {
	switch action.Type {
	case "accept":
		return &expr.Verdict{Kind: expr.VerdictAccept}, nil

	case "drop":
		return &expr.Verdict{Kind: expr.VerdictDrop}, nil

	case "reject":
		// For reject, we need to send ICMP unreachable
		// This is more complex and may require additional expressions
		return &expr.Verdict{Kind: expr.VerdictDrop}, nil

	case "log":
		// Logging - add log expression before verdict
		prefix := "filter-policy: "
		if logPrefix, ok := action.Parameters["prefix"].(string); ok {
			prefix = logPrefix
		}

		return &expr.Log{
			Key:  0, // NFT_LOG_PREFIX
			Data: []byte(prefix),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported action type: %s", action.Type)
	}
}

// protocolToNumber converts protocol string to number
func protocolToNumber(protocol string) uint8 {
	switch protocol {
	case "tcp":
		return unix.IPPROTO_TCP
	case "udp":
		return unix.IPPROTO_UDP
	case "icmp":
		return unix.IPPROTO_ICMP
	case "icmpv6":
		return unix.IPPROTO_ICMPV6
	case "sctp":
		return unix.IPPROTO_SCTP
	default:
		return 0
	}
}

// BuildNATRule builds an SNAT or DNAT rule
func BuildNATRule(table *nftables.Table, chain *nftables.Chain, srcIP string, natIP string, natType string) (*nftables.Rule, error) {
	var exprs []expr.Any

	// Match source IP
	if srcIP != "" {
		ip, _, err := net.ParseCIDR(srcIP)
		if err != nil {
			ip = net.ParseIP(srcIP)
			if ip == nil {
				return nil, fmt.Errorf("invalid source IP: %s", srcIP)
			}
		}

		offset := uint32(12) // IPv4 source address offset
		length := uint32(4)
		if table.Family == nftables.TableFamilyIPv6 {
			offset = 8 // IPv6 source address offset
			length = 16
		}

		var ipData []byte
		if table.Family == nftables.TableFamilyIPv4 {
			ipData = ip.To4()
		} else {
			ipData = ip.To16()
		}

		exprs = append(exprs,
			// Load source address
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          length,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ipData,
			},
		)
	}

	// Add counter
	exprs = append(exprs, &expr.Counter{})

	// Add NAT expression
	natIP_parsed := net.ParseIP(natIP)
	if natIP_parsed == nil {
		return nil, fmt.Errorf("invalid NAT IP: %s", natIP)
	}

	var natIPData []byte
	if table.Family == nftables.TableFamilyIPv4 {
		natIPData = natIP_parsed.To4()
	} else {
		natIPData = natIP_parsed.To16()
	}

	if natType == "snat" || natType == "masquerade" {
		exprs = append(exprs, &expr.NAT{
			Type:        expr.NATTypeSourceNAT,
			Family:      uint32(table.Family),
			RegAddrMin:  1,
			RegAddrMax:  1,
			Random:      natType == "masquerade",
			FullyRandom: natType == "masquerade",
		})

		// Load NAT address into register
		exprs = append(exprs, &expr.Immediate{
			Register: 1,
			Data:     natIPData,
		})

	} else if natType == "dnat" {
		exprs = append(exprs, &expr.NAT{
			Type:       expr.NATTypeDestNAT,
			Family:     uint32(table.Family),
			RegAddrMin: 1,
			RegAddrMax: 1,
		})

		// Load NAT address into register
		exprs = append(exprs, &expr.Immediate{
			Register: 1,
			Data:     natIPData,
		})
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: exprs,
	}

	return rule, nil
}
