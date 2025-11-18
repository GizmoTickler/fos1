package policy

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

// KernelRuleManager handles Linux IP rules via netlink
type KernelRuleManager struct {
}

// NewKernelRuleManager creates a new kernel rule manager
func NewKernelRuleManager() *KernelRuleManager {
	return &KernelRuleManager{}
}

// AddRule adds an IP rule to the kernel
func (k *KernelRuleManager) AddRule(rule IPRule) error {
	klog.V(2).Infof("Adding IP rule: %+v", rule)

	// Create netlink rule
	nlRule := k.convertToNetlinkRule(rule)
	if nlRule == nil {
		return fmt.Errorf("failed to convert rule to netlink rule")
	}

	// Add the rule to the kernel
	if err := netlink.RuleAdd(nlRule); err != nil {
		return fmt.Errorf("failed to add IP rule: %w", err)
	}

	klog.V(2).Infof("Successfully added IP rule: priority %d, table %d", rule.Priority, rule.Table)
	return nil
}

// DeleteRule deletes an IP rule from the kernel
func (k *KernelRuleManager) DeleteRule(rule IPRule) error {
	klog.V(2).Infof("Deleting IP rule: %+v", rule)

	// Create netlink rule
	nlRule := k.convertToNetlinkRule(rule)
	if nlRule == nil {
		return fmt.Errorf("failed to convert rule to netlink rule")
	}

	// Delete the rule from the kernel
	if err := netlink.RuleDel(nlRule); err != nil {
		return fmt.Errorf("failed to delete IP rule: %w", err)
	}

	klog.V(2).Infof("Successfully deleted IP rule: priority %d, table %d", rule.Priority, rule.Table)
	return nil
}

// ListRules lists all IP rules in the kernel
func (k *KernelRuleManager) ListRules(family int) ([]IPRule, error) {
	klog.V(2).Infof("Listing IP rules for family %d", family)

	// List netlink rules
	nlRules, err := netlink.RuleList(family)
	if err != nil {
		return nil, fmt.Errorf("failed to list IP rules: %w", err)
	}

	// Convert to IPRule structs
	rules := make([]IPRule, 0, len(nlRules))
	for _, nlRule := range nlRules {
		rule := k.convertFromNetlinkRule(nlRule)
		if rule != nil {
			rules = append(rules, *rule)
		}
	}

	klog.V(2).Infof("Found %d IP rules", len(rules))
	return rules, nil
}

// CreateRoutingTable creates a custom routing table (by adding routes to it)
// Note: In Linux, routing tables don't need to be explicitly created
// They exist implicitly when rules reference them or routes are added to them
func (k *KernelRuleManager) CreateRoutingTable(tableID int, tableName string) error {
	klog.V(2).Infof("Routing table %d (%s) will be created implicitly when rules or routes reference it", tableID, tableName)
	// Tables are created implicitly in Linux, no action needed
	return nil
}

// DeleteRoutingTable deletes all routes from a routing table
func (k *KernelRuleManager) DeleteRoutingTable(tableID int) error {
	klog.V(2).Infof("Deleting all routes from routing table %d", tableID)

	// List all routes in the table
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{
		Table: tableID,
	}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list routes in table %d: %w", tableID, err)
	}

	// Delete each route
	for _, route := range routes {
		if err := netlink.RouteDel(&route); err != nil {
			klog.Warningf("Failed to delete route from table %d: %v", tableID, err)
		}
	}

	klog.V(2).Infof("Deleted %d routes from table %d", len(routes), tableID)
	return nil
}

// convertToNetlinkRule converts an IPRule to a netlink.Rule
func (k *KernelRuleManager) convertToNetlinkRule(rule IPRule) *netlink.Rule {
	nlRule := netlink.NewRule()

	// Set priority
	nlRule.Priority = rule.Priority

	// Set table
	nlRule.Table = rule.Table

	// Set family
	if rule.Family == FamilyIPv4 {
		nlRule.Family = netlink.FAMILY_V4
	} else if rule.Family == FamilyIPv6 {
		nlRule.Family = netlink.FAMILY_V6
	} else {
		nlRule.Family = netlink.FAMILY_ALL
	}

	// Set source network
	if rule.Src != "" {
		if ip, ipNet, err := net.ParseCIDR(rule.Src); err == nil {
			nlRule.Src = ipNet
			nlRule.Src.IP = ip
		} else {
			// Try as a single IP
			if ip := net.ParseIP(rule.Src); ip != nil {
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				nlRule.Src = &net.IPNet{IP: ip, Mask: mask}
			}
		}
	}

	// Set destination network
	if rule.Dst != "" {
		if ip, ipNet, err := net.ParseCIDR(rule.Dst); err == nil {
			nlRule.Dst = ipNet
			nlRule.Dst.IP = ip
		} else {
			// Try as a single IP
			if ip := net.ParseIP(rule.Dst); ip != nil {
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				nlRule.Dst = &net.IPNet{IP: ip, Mask: mask}
			}
		}
	}

	// Set input interface
	if rule.IifName != "" {
		nlRule.IifName = rule.IifName
	}

	// Set output interface
	if rule.OifName != "" {
		nlRule.OifName = rule.OifName
	}

	// Set fwmark
	if rule.Mark != 0 {
		nlRule.Mark = uint32(rule.Mark)
		if rule.Mask != 0 {
			mask := uint32(rule.Mask)
			nlRule.Mask = &mask
		} else {
			mask := uint32(0xFFFFFFFF)
			nlRule.Mask = &mask
		}
	}

	// Set TOS/DSCP
	if rule.Tos != 0 {
		nlRule.Tos = uint(rule.Tos)
	}

	// Set action
	switch rule.Action {
	case ActionToTable:
		nlRule.Goto = -1 // Use default (to table)
	case ActionBlacklist:
		nlRule.Goto = 6 // FR_ACT_BLACKHOLE
	case ActionProhibit:
		nlRule.Goto = 7 // FR_ACT_PROHIBIT
	case ActionUnreachable:
		nlRule.Goto = 8 // FR_ACT_UNREACHABLE
	default:
		nlRule.Goto = -1 // Default to table
	}

	return nlRule
}

// convertFromNetlinkRule converts a netlink.Rule to an IPRule
func (k *KernelRuleManager) convertFromNetlinkRule(nlRule netlink.Rule) *IPRule {
	rule := &IPRule{
		Priority: nlRule.Priority,
		Table:    nlRule.Table,
		Mark:     int(nlRule.Mark),
		Tos:      int(nlRule.Tos),
		IifName:  nlRule.IifName,
		OifName:  nlRule.OifName,
	}

	// Set mask if present
	if nlRule.Mask != nil {
		rule.Mask = int(*nlRule.Mask)
	}

	// Set family
	if nlRule.Family == netlink.FAMILY_V4 {
		rule.Family = FamilyIPv4
	} else if nlRule.Family == netlink.FAMILY_V6 {
		rule.Family = FamilyIPv6
	} else {
		rule.Family = FamilyAll
	}

	// Set source network
	if nlRule.Src != nil {
		rule.Src = nlRule.Src.String()
	}

	// Set destination network
	if nlRule.Dst != nil {
		rule.Dst = nlRule.Dst.String()
	}

	// Set action based on Goto value
	switch nlRule.Goto {
	case 6: // FR_ACT_BLACKHOLE
		rule.Action = ActionBlacklist
	case 7: // FR_ACT_PROHIBIT
		rule.Action = ActionProhibit
	case 8: // FR_ACT_UNREACHABLE
		rule.Action = ActionUnreachable
	default:
		rule.Action = ActionToTable
	}

	return rule
}

// GetRoutesInTable gets all routes in a specific routing table
func (k *KernelRuleManager) GetRoutesInTable(tableID int, family int) ([]netlink.Route, error) {
	klog.V(2).Infof("Getting routes in table %d for family %d", tableID, family)

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{
		Table: tableID,
	}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes in table %d: %w", tableID, err)
	}

	klog.V(2).Infof("Found %d routes in table %d", len(routes), tableID)
	return routes, nil
}

// AddRouteToTable adds a route to a specific routing table
func (k *KernelRuleManager) AddRouteToTable(tableID int, dst *net.IPNet, gw net.IP, dev string, metric int) error {
	klog.V(2).Infof("Adding route to table %d: dst=%s gw=%s dev=%s metric=%d", tableID, dst, gw, dev, metric)

	route := &netlink.Route{
		Dst:      dst,
		Gw:       gw,
		Table:    tableID,
		Priority: metric,
	}

	// Get link if device is specified
	if dev != "" {
		link, err := netlink.LinkByName(dev)
		if err != nil {
			return fmt.Errorf("failed to get link %s: %w", dev, err)
		}
		route.LinkIndex = link.Attrs().Index
	}

	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("failed to add route to table %d: %w", tableID, err)
	}

	klog.V(2).Infof("Successfully added route to table %d", tableID)
	return nil
}

// DeleteRouteFromTable deletes a route from a specific routing table
func (k *KernelRuleManager) DeleteRouteFromTable(tableID int, dst *net.IPNet) error {
	klog.V(2).Infof("Deleting route from table %d: dst=%s", tableID, dst)

	route := &netlink.Route{
		Dst:   dst,
		Table: tableID,
	}

	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("failed to delete route from table %d: %w", tableID, err)
	}

	klog.V(2).Infof("Successfully deleted route from table %d", tableID)
	return nil
}
