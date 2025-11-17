package vlan

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

// QoSManager handles QoS configuration for VLAN interfaces
type QoSManager struct{}

// NewQoSManager creates a new QoS manager
func NewQoSManager() *QoSManager {
	return &QoSManager{}
}

// SetVLANPriority sets the 802.1p priority for a VLAN interface
// This configures the egress mapping so packets are tagged with the specified priority
func (q *QoSManager) SetVLANPriority(linkName string, priority int) error {
	if priority < 0 || priority > 7 {
		return fmt.Errorf("invalid 802.1p priority %d, must be between 0 and 7", priority)
	}

	klog.V(4).Infof("Setting 802.1p priority %d for interface %s", priority, linkName)

	// Get the link
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	// Check if it's a VLAN interface
	vlan, ok := link.(*netlink.Vlan)
	if !ok {
		return fmt.Errorf("interface %s is not a VLAN interface", linkName)
	}

	// Set egress QoS mapping (map all socket priorities to the desired VLAN priority)
	// This ensures all outgoing packets get the specified 802.1p priority tag
	egressMap := make(map[uint32]uint32)
	for i := uint32(0); i <= 15; i++ {
		egressMap[i] = uint32(priority)
	}

	// Use netlink to set VLAN QoS egress mapping
	// Note: vishvananda/netlink doesn't fully support VLAN QoS mapping manipulation
	// We'll use the /proc/net/vlan interface or ip command as a fallback
	err = q.setVLANPriorityViaSysfs(vlan.Name, priority)
	if err != nil {
		klog.Warningf("Failed to set VLAN priority via sysfs: %v, trying ip command", err)
		err = q.setVLANPriorityViaIP(vlan.Name, priority)
		if err != nil {
			return fmt.Errorf("failed to set VLAN priority: %w", err)
		}
	}

	return nil
}

// setVLANPriorityViaSysfs sets VLAN priority using sysfs
func (q *QoSManager) setVLANPriorityViaSysfs(ifname string, priority int) error {
	// Modern kernels expose VLAN egress priority mapping via sysfs
	// This is a simplified approach - in production you might need more sophisticated handling
	// The actual sysfs path and method may vary by kernel version

	// For now, we'll return an error to fall back to the ip command
	// In a production system, you'd implement proper sysfs manipulation here
	return fmt.Errorf("sysfs VLAN priority setting not implemented, will use ip command")
}

// setVLANPriorityViaIP sets VLAN priority using the ip command
func (q *QoSManager) setVLANPriorityViaIP(ifname string, priority int) error {
	// Use ip command to set egress QoS mapping
	// This maps all internal priorities (0-7) to the desired VLAN priority
	for i := 0; i <= 7; i++ {
		cmd := exec.Command("ip", "link", "set", "dev", ifname, "type", "vlan",
			"egress", fmt.Sprintf("%d:%d", i, priority))

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to set VLAN egress mapping for priority %d: %w, output: %s",
				i, err, string(output))
		}
	}

	klog.V(4).Infof("Successfully set 802.1p priority %d for VLAN interface %s", priority, ifname)
	return nil
}

// ConfigureQoS configures Traffic Control (TC) QoS for a VLAN interface
func (q *QoSManager) ConfigureQoS(linkName string, config QoSConfig) error {
	if !config.Enabled {
		// Remove any existing QoS configuration
		return q.RemoveQoS(linkName)
	}

	klog.Infof("Configuring QoS for interface %s", linkName)

	// Get the link
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	ifindex := link.Attrs().Index

	// Remove existing qdisc first
	if err := q.RemoveQoS(linkName); err != nil {
		klog.V(4).Infof("No existing QoS to remove on %s (this is normal): %v", linkName, err)
	}

	// Create HTB (Hierarchical Token Bucket) qdisc as the root
	// HTB is ideal for bandwidth limiting and prioritization
	attrs := netlink.QdiscAttrs{
		LinkIndex: ifindex,
		Handle:    netlink.MakeHandle(1, 0),
		Parent:    netlink.HANDLE_ROOT,
	}

	htbQdisc := netlink.NewHtb(attrs)

	// Set default class if specified
	if config.DefaultClass > 0 {
		htbQdisc.Defcls = uint32(config.DefaultClass)
	}

	if err := netlink.QdiscAdd(htbQdisc); err != nil {
		return fmt.Errorf("failed to add HTB qdisc: %w", err)
	}

	klog.V(4).Infof("Added HTB qdisc to interface %s", linkName)

	// Parse maximum rate if specified
	var maxRateBits uint64
	if config.MaxRate != "" {
		maxRateBits, err = parseRate(config.MaxRate)
		if err != nil {
			return fmt.Errorf("invalid max rate %s: %w", config.MaxRate, err)
		}
	}

	// Add root HTB class if max rate is specified
	if maxRateBits > 0 {
		rootClass := netlink.HtbClassAttrs{
			Rate:    maxRateBits,
			Ceil:    maxRateBits,
			Buffer:  0, // Will be calculated by kernel
		}

		htbClass := &netlink.HtbClass{
			ClassAttrs: netlink.ClassAttrs{
				LinkIndex: ifindex,
				Parent:    netlink.MakeHandle(1, 0),
				Handle:    netlink.MakeHandle(1, 1),
			},
			Rate:   rootClass.Rate,
			Ceil:   rootClass.Ceil,
			Buffer: rootClass.Buffer,
		}

		if err := netlink.ClassAdd(htbClass); err != nil {
			return fmt.Errorf("failed to add root HTB class: %w", err)
		}

		klog.V(4).Infof("Added root HTB class with rate %d bps to interface %s", maxRateBits, linkName)
	}

	// Add QoS classes
	for _, class := range config.Classes {
		if err := q.addQoSClass(linkName, ifindex, class); err != nil {
			return fmt.Errorf("failed to add QoS class %d: %w", class.ID, err)
		}
	}

	klog.Infof("Successfully configured QoS on interface %s with %d classes", linkName, len(config.Classes))
	return nil
}

// addQoSClass adds a single QoS class to an interface
func (q *QoSManager) addQoSClass(linkName string, ifindex int, class QoSClass) error {
	klog.V(4).Infof("Adding QoS class %d to interface %s", class.ID, linkName)

	// Parse rates
	rateBits, err := parseRate(class.Rate)
	if err != nil {
		return fmt.Errorf("invalid rate %s: %w", class.Rate, err)
	}

	ceilBits := rateBits
	if class.Ceiling != "" {
		ceilBits, err = parseRate(class.Ceiling)
		if err != nil {
			return fmt.Errorf("invalid ceiling %s: %w", class.Ceiling, err)
		}
	}

	// Parse burst if specified
	var burstBytes uint32
	if class.Burst != "" {
		burstBytes, err = parseBytes(class.Burst)
		if err != nil {
			return fmt.Errorf("invalid burst %s: %w", class.Burst, err)
		}
	}

	// Create HTB class
	htbClass := &netlink.HtbClass{
		ClassAttrs: netlink.ClassAttrs{
			LinkIndex: ifindex,
			Parent:    netlink.MakeHandle(1, 1), // Attach to root class
			Handle:    netlink.MakeHandle(1, uint16(class.ID+10)),
		},
		Rate:     rateBits,
		Ceil:     ceilBits,
		Buffer:   burstBytes,
		Prio:     uint32(class.Priority),
	}

	if err := netlink.ClassAdd(htbClass); err != nil {
		return fmt.Errorf("failed to add HTB class: %w", err)
	}

	// Add SFQ (Stochastic Fairness Queueing) as leaf qdisc for fairness
	sfqAttrs := netlink.QdiscAttrs{
		LinkIndex: ifindex,
		Handle:    netlink.MakeHandle(uint16(class.ID+10), 0),
		Parent:    netlink.MakeHandle(1, uint16(class.ID+10)),
	}

	sfq := &netlink.Sfq{
		QdiscAttrs: sfqAttrs,
	}
	if err := netlink.QdiscAdd(sfq); err != nil {
		return fmt.Errorf("failed to add SFQ qdisc: %w", err)
	}

	klog.V(4).Infof("Added QoS class %d with rate %d bps, ceiling %d bps, priority %d",
		class.ID, rateBits, ceilBits, class.Priority)

	return nil
}

// RemoveQoS removes all QoS configuration from an interface
func (q *QoSManager) RemoveQoS(linkName string) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	// List all qdiscs on the interface
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("failed to list qdiscs: %w", err)
	}

	// Delete all qdiscs except the default one
	for _, qdisc := range qdiscs {
		attrs := qdisc.Attrs()
		// Don't try to delete the default qdisc
		if attrs.Parent == netlink.HANDLE_ROOT && attrs.Handle != 0 {
			if err := netlink.QdiscDel(qdisc); err != nil {
				klog.V(4).Infof("Failed to delete qdisc on %s: %v", linkName, err)
			}
		}
	}

	klog.V(4).Infof("Removed QoS configuration from interface %s", linkName)
	return nil
}

// parseRate converts a rate string (e.g., "1Gbit", "100Mbit", "10Kbit") to bits per second
func parseRate(rateStr string) (uint64, error) {
	rateStr = strings.TrimSpace(rateStr)
	if rateStr == "" {
		return 0, fmt.Errorf("empty rate string")
	}

	// Extract numeric part and unit
	var value float64
	var unit string

	// Try to parse with common suffixes
	suffixes := []string{"Gbit", "Mbit", "Kbit", "bit", "Gbps", "Mbps", "Kbps", "bps"}
	for _, suffix := range suffixes {
		if strings.HasSuffix(rateStr, suffix) {
			valueStr := strings.TrimSuffix(rateStr, suffix)
			_, err := fmt.Sscanf(valueStr, "%f", &value)
			if err != nil {
				return 0, fmt.Errorf("invalid rate value: %w", err)
			}
			unit = suffix
			break
		}
	}

	if unit == "" {
		return 0, fmt.Errorf("unknown rate unit in %s", rateStr)
	}

	// Convert to bits per second
	var multiplier uint64
	switch unit {
	case "Gbit", "Gbps":
		multiplier = 1000000000
	case "Mbit", "Mbps":
		multiplier = 1000000
	case "Kbit", "Kbps":
		multiplier = 1000
	case "bit", "bps":
		multiplier = 1
	default:
		return 0, fmt.Errorf("unknown rate unit %s", unit)
	}

	return uint64(value * float64(multiplier)), nil
}

// parseBytes converts a size string (e.g., "15kb", "100mb") to bytes
func parseBytes(sizeStr string) (uint32, error) {
	sizeStr = strings.TrimSpace(strings.ToLower(sizeStr))
	if sizeStr == "" {
		return 0, fmt.Errorf("empty size string")
	}

	// Extract numeric part and unit
	var value float64
	var unit string

	suffixes := []string{"gb", "mb", "kb", "b"}
	for _, suffix := range suffixes {
		if strings.HasSuffix(sizeStr, suffix) {
			valueStr := strings.TrimSuffix(sizeStr, suffix)
			_, err := fmt.Sscanf(valueStr, "%f", &value)
			if err != nil {
				return 0, fmt.Errorf("invalid size value: %w", err)
			}
			unit = suffix
			break
		}
	}

	if unit == "" {
		return 0, fmt.Errorf("unknown size unit in %s", sizeStr)
	}

	// Convert to bytes
	var multiplier uint32
	switch unit {
	case "gb":
		multiplier = 1024 * 1024 * 1024
	case "mb":
		multiplier = 1024 * 1024
	case "kb":
		multiplier = 1024
	case "b":
		multiplier = 1
	default:
		return 0, fmt.Errorf("unknown size unit %s", unit)
	}

	return uint32(value * float64(multiplier)), nil
}

// SetDSCPMarking sets DSCP marking for packets on a VLAN interface
func (q *QoSManager) SetDSCPMarking(linkName string, dscp int) error {
	if dscp < 0 || dscp > 63 {
		return fmt.Errorf("invalid DSCP value %d, must be between 0 and 63", dscp)
	}

	klog.V(4).Infof("Setting DSCP marking %d for interface %s", dscp, linkName)

	// Get the link
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	ifindex := link.Attrs().Index

	// First, ensure there's a qdisc
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("failed to list qdiscs: %w", err)
	}

	hasQdisc := false
	var qdiscHandle uint32
	for _, qd := range qdiscs {
		attrs := qd.Attrs()
		if attrs.Parent == netlink.HANDLE_ROOT && attrs.Handle != 0 {
			hasQdisc = true
			qdiscHandle = attrs.Handle
			break
		}
	}

	if !hasQdisc {
		// Add a simple prio qdisc if none exists
		attrs := netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		}
		qdisc := netlink.NewPrio(attrs)
		if err := netlink.QdiscAdd(qdisc); err != nil {
			return fmt.Errorf("failed to add prio qdisc: %w", err)
		}
		qdiscHandle = netlink.MakeHandle(1, 0)
	}

	// Use tc command to set DSCP marking with u32 filter and skbedit action
	// This matches all IP packets and sets the DSCP value in the TOS field
	// The TOS field structure: DSCP (6 bits) + ECN (2 bits)
	// We need to shift DSCP left by 2 bits to position it correctly
	tosValue := dscp << 2

	// Remove any existing DSCP filter first
	if err := q.RemoveDSCPMarking(linkName); err != nil {
		klog.V(4).Infof("No existing DSCP filter to remove on %s: %v", linkName, err)
	}

	// Add TC filter with u32 match and skbedit action
	// Match all IP packets (0.0.0.0/0) and set DSCP
	// tc filter add dev <if> parent <handle> protocol ip prio 1 u32 match ip dst 0.0.0.0/0 action skbedit dscp <value>
	cmd := exec.Command("tc", "filter", "add", "dev", linkName,
		"parent", fmt.Sprintf("%x:", qdiscHandle>>16),
		"protocol", "ip",
		"prio", "1",
		"u32",
		"match", "ip", "dst", "0.0.0.0/0",
		"action", "skbedit", "dscp", fmt.Sprintf("%d", dscp))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add DSCP filter: %w, output: %s", err, string(output))
	}

	// Also add filter for IPv6 if this is an IPv6-capable interface
	cmd = exec.Command("tc", "filter", "add", "dev", linkName,
		"parent", fmt.Sprintf("%x:", qdiscHandle>>16),
		"protocol", "ipv6",
		"prio", "1",
		"u32",
		"match", "ip6", "dst", "::/0",
		"action", "skbedit", "dscp", fmt.Sprintf("%d", dscp))

	output, err = cmd.CombinedOutput()
	if err != nil {
		// IPv6 filter failure is non-fatal, just log it
		klog.V(4).Infof("Failed to add IPv6 DSCP filter on %s (may not support IPv6): %v", linkName, err)
	}

	klog.Infof("Successfully set DSCP marking %d (TOS: 0x%02x) for interface %s", dscp, tosValue, linkName)
	return nil
}

// RemoveDSCPMarking removes DSCP marking filters from a VLAN interface
func (q *QoSManager) RemoveDSCPMarking(linkName string) error {
	// Get the link
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	// List all qdiscs to find the parent
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("failed to list qdiscs: %w", err)
	}

	var qdiscHandle uint32
	for _, qd := range qdiscs {
		attrs := qd.Attrs()
		if attrs.Parent == netlink.HANDLE_ROOT && attrs.Handle != 0 {
			qdiscHandle = attrs.Handle
			break
		}
	}

	if qdiscHandle == 0 {
		return fmt.Errorf("no qdisc found on interface %s", linkName)
	}

	// Remove IPv4 DSCP filter
	cmd := exec.Command("tc", "filter", "del", "dev", linkName,
		"parent", fmt.Sprintf("%x:", qdiscHandle>>16),
		"protocol", "ip",
		"prio", "1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		klog.V(4).Infof("Failed to remove IPv4 DSCP filter on %s: %v, output: %s", linkName, err, string(output))
	}

	// Remove IPv6 DSCP filter
	cmd = exec.Command("tc", "filter", "del", "dev", linkName,
		"parent", fmt.Sprintf("%x:", qdiscHandle>>16),
		"protocol", "ipv6",
		"prio", "1")

	output, err = cmd.CombinedOutput()
	if err != nil {
		klog.V(4).Infof("Failed to remove IPv6 DSCP filter on %s: %v, output: %s", linkName, err, string(output))
	}

	klog.V(4).Infof("Removed DSCP marking from interface %s", linkName)
	return nil
}
