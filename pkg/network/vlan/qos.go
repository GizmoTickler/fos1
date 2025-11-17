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

	// Add leaf qdisc based on QueueType (default: SFQ)
	queueType := class.QueueType
	if queueType == "" {
		queueType = "sfq" // Default to SFQ for backward compatibility
	}

	leafHandle := netlink.MakeHandle(uint16(class.ID+10), 0)
	parentHandle := netlink.MakeHandle(1, uint16(class.ID+10))

	var leafErr error
	switch queueType {
	case "sfq":
		leafErr = q.addSFQQdisc(ifindex, leafHandle, parentHandle)
	case "red":
		leafErr = q.addREDQdisc(ifindex, leafHandle, parentHandle, class.REDParams)
	case "gred":
		leafErr = q.addGREDQdisc(ifindex, leafHandle, parentHandle, class.REDParams)
	case "codel":
		leafErr = q.addCodelQdisc(ifindex, leafHandle, parentHandle, class.CodelParams)
	case "fq_codel":
		leafErr = q.addFQCodelQdisc(ifindex, leafHandle, parentHandle, class.CodelParams)
	default:
		return fmt.Errorf("unsupported queue type: %s", queueType)
	}

	if leafErr != nil {
		return fmt.Errorf("failed to add %s qdisc: %w", queueType, leafErr)
	}

	klog.V(4).Infof("Added QoS class %d with rate %d bps, ceiling %d bps, priority %d, queue: %s",
		class.ID, rateBits, ceilBits, class.Priority, queueType)

	return nil
}

// ConfigureIngressQoS configures ingress QoS using IFB (Intermediate Functional Block) device
// IFB allows applying egress QoS to ingress traffic by redirecting to a virtual device
func (q *QoSManager) ConfigureIngressQoS(linkName string, config QoSConfig) error {
	if !config.Enabled {
		return q.RemoveIngressQoS(linkName)
	}

	klog.Infof("Configuring ingress QoS for interface %s using IFB device", linkName)

	// Get the link
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	ifindex := link.Attrs().Index

	// Create IFB device name based on the interface
	ifbName := fmt.Sprintf("ifb-%s", linkName)
	if len(ifbName) > 15 {
		// Interface names are limited to 15 characters
		ifbName = fmt.Sprintf("ifb%d", ifindex)
	}

	// Check if IFB device exists, create if not
	ifbLink, err := netlink.LinkByName(ifbName)
	if err != nil {
		// IFB device doesn't exist, create it
		klog.V(4).Infof("Creating IFB device %s for ingress QoS", ifbName)

		// First, ensure IFB module is loaded
		if err := q.ensureIFBModule(); err != nil {
			return fmt.Errorf("failed to ensure IFB module: %w", err)
		}

		// Create IFB device
		ifb := &netlink.Ifb{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifbName,
			},
		}

		if err := netlink.LinkAdd(ifb); err != nil {
			return fmt.Errorf("failed to create IFB device %s: %w", ifbName, err)
		}

		// Get the newly created IFB device
		ifbLink, err = netlink.LinkByName(ifbName)
		if err != nil {
			return fmt.Errorf("failed to get IFB device %s: %w", ifbName, err)
		}
	}

	// Bring up the IFB device
	if err := netlink.LinkSetUp(ifbLink); err != nil {
		return fmt.Errorf("failed to bring up IFB device %s: %w", ifbName, err)
	}

	klog.V(4).Infof("IFB device %s is ready", ifbName)

	// Remove existing ingress qdisc on main interface
	qdiscs, _ := netlink.QdiscList(link)
	for _, qd := range qdiscs {
		if qd.Attrs().Parent == netlink.HANDLE_INGRESS {
			netlink.QdiscDel(qd)
		}
	}

	// Add ingress qdisc to the main interface
	ingressQdisc := &netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_INGRESS,
		},
	}

	if err := netlink.QdiscAdd(ingressQdisc); err != nil {
		return fmt.Errorf("failed to add ingress qdisc: %w", err)
	}

	// Add filter to redirect ingress traffic to IFB device
	// We use tc command for this as netlink filter support is limited
	cmd := exec.Command("tc", "filter", "add", "dev", linkName,
		"parent", "ffff:",
		"protocol", "all",
		"u32",
		"match", "u32", "0", "0",
		"action", "mirred", "egress", "redirect", "dev", ifbName)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add ingress redirect filter: %w, output: %s", err, string(output))
	}

	klog.V(4).Infof("Added ingress redirect from %s to %s", linkName, ifbName)

	// Now configure egress QoS on the IFB device
	// This affects the ingress traffic of the original interface
	if err := q.ConfigureQoS(ifbName, config); err != nil {
		return fmt.Errorf("failed to configure QoS on IFB device %s: %w", ifbName, err)
	}

	klog.Infof("Successfully configured ingress QoS for %s via IFB device %s", linkName, ifbName)
	return nil
}

// RemoveIngressQoS removes ingress QoS configuration and IFB device
func (q *QoSManager) RemoveIngressQoS(linkName string) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	ifindex := link.Attrs().Index

	// Calculate IFB device name
	ifbName := fmt.Sprintf("ifb-%s", linkName)
	if len(ifbName) > 15 {
		ifbName = fmt.Sprintf("ifb%d", ifindex)
	}

	// Remove ingress qdisc (this also removes filters)
	qdiscs, _ := netlink.QdiscList(link)
	for _, qd := range qdiscs {
		if qd.Attrs().Parent == netlink.HANDLE_INGRESS {
			if err := netlink.QdiscDel(qd); err != nil {
				klog.V(4).Infof("Failed to delete ingress qdisc on %s: %v", linkName, err)
			}
		}
	}

	// Delete IFB device if it exists
	ifbLink, err := netlink.LinkByName(ifbName)
	if err == nil {
		// Remove QoS from IFB device first
		q.RemoveQoS(ifbName)

		// Delete the IFB device
		if err := netlink.LinkDel(ifbLink); err != nil {
			klog.V(4).Infof("Failed to delete IFB device %s: %v", ifbName, err)
		} else {
			klog.V(4).Infof("Deleted IFB device %s", ifbName)
		}
	}

	klog.V(4).Infof("Removed ingress QoS from interface %s", linkName)
	return nil
}

// ensureIFBModule ensures the IFB kernel module is loaded
func (q *QoSManager) ensureIFBModule() error {
	// Try to load the IFB module
	cmd := exec.Command("modprobe", "ifb")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Module might already be loaded, which is fine
		klog.V(4).Infof("modprobe ifb: %v, output: %s (may already be loaded)", err, string(output))
	}

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

// addSFQQdisc adds a Stochastic Fairness Queueing (SFQ) qdisc
func (q *QoSManager) addSFQQdisc(ifindex int, handle, parent uint32) error {
	sfqAttrs := netlink.QdiscAttrs{
		LinkIndex: ifindex,
		Handle:    handle,
		Parent:    parent,
	}

	sfq := &netlink.Sfq{
		QdiscAttrs: sfqAttrs,
	}

	if err := netlink.QdiscAdd(sfq); err != nil {
		return fmt.Errorf("failed to add SFQ qdisc: %w", err)
	}

	klog.V(4).Infof("Added SFQ qdisc with handle %x:%x", handle>>16, handle&0xffff)
	return nil
}

// addREDQdisc adds a Random Early Detection (RED) qdisc
func (q *QoSManager) addREDQdisc(ifindex int, handle, parent uint32, params *REDParams) error {
	// Set default RED parameters if not provided
	if params == nil {
		params = &REDParams{
			Min:         20000,  // 20KB
			Max:         60000,  // 60KB
			Avpkt:       1000,   // 1KB average packet size
			Limit:       100000, // 100KB queue limit
			Burst:       20,     // 20 packet burst
			Probability: 0.02,   // 2% mark probability
			ECN:         true,   // Enable ECN by default
			Adaptive:    false,
		}
	}

	// Use tc command for RED as netlink has limited support
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("failed to get link by index %d: %w", ifindex, err)
	}

	args := []string{"qdisc", "add", "dev", link.Attrs().Name,
		"parent", fmt.Sprintf("%x:%x", parent>>16, parent&0xffff),
		"handle", fmt.Sprintf("%x:", handle>>16),
		"red",
		"limit", fmt.Sprintf("%d", params.Limit),
		"min", fmt.Sprintf("%d", params.Min),
		"max", fmt.Sprintf("%d", params.Max),
		"avpkt", fmt.Sprintf("%d", params.Avpkt),
		"burst", fmt.Sprintf("%d", params.Burst),
		"probability", fmt.Sprintf("%f", params.Probability),
	}

	if params.ECN {
		args = append(args, "ecn")
	}

	if params.Adaptive {
		args = append(args, "adaptive")
	}

	cmd := exec.Command("tc", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add RED qdisc: %w, output: %s", err, string(output))
	}

	klog.V(4).Infof("Added RED qdisc with min=%d, max=%d, limit=%d, ecn=%v",
		params.Min, params.Max, params.Limit, params.ECN)
	return nil
}

// addGREDQdisc adds a Generalized Random Early Detection (GRED) qdisc
// GRED provides multiple RED queues for different traffic classes
func (q *QoSManager) addGREDQdisc(ifindex int, handle, parent uint32, params *REDParams) error {
	// Note: vishvananda/netlink has limited GRED support
	// We'll use tc command for full GRED functionality

	// Set default GRED parameters if not provided
	if params == nil {
		params = &REDParams{
			Min:         20000,
			Max:         60000,
			Avpkt:       1000,
			Limit:       100000,
			Burst:       20,
			Probability: 0.02,
			ECN:         true,
			Adaptive:    false,
		}
	}

	// Use tc command to add GRED qdisc
	// GRED requires DPs (Drop Priorities) configuration
	// We'll configure it with 8 DPs for 8 priority levels
	cmd := exec.Command("tc", "qdisc", "add", "dev", fmt.Sprintf("ifindex_%d", ifindex),
		"parent", fmt.Sprintf("%x:%x", parent>>16, parent&0xffff),
		"handle", fmt.Sprintf("%x:", handle>>16),
		"gred", "setup", "DPs", "8", "default", "0")

	// Note: We need to find the interface name from ifindex
	// For now, we'll use netlink.LinkByIndex
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("failed to get link by index %d: %w", ifindex, err)
	}

	cmd = exec.Command("tc", "qdisc", "add", "dev", link.Attrs().Name,
		"parent", fmt.Sprintf("%x:%x", parent>>16, parent&0xffff),
		"handle", fmt.Sprintf("%x:", handle>>16),
		"gred", "setup", "DPs", "8", "default", "0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add GRED qdisc: %w, output: %s", err, string(output))
	}

	// Configure each DP with RED parameters
	for dp := 0; dp < 8; dp++ {
		cmd = exec.Command("tc", "qdisc", "change", "dev", link.Attrs().Name,
			"handle", fmt.Sprintf("%x:", handle>>16),
			"gred",
			"limit", fmt.Sprintf("%d", params.Limit),
			"min", fmt.Sprintf("%d", params.Min),
			"max", fmt.Sprintf("%d", params.Max),
			"avpkt", fmt.Sprintf("%d", params.Avpkt),
			"burst", fmt.Sprintf("%d", params.Burst),
			"probability", fmt.Sprintf("%f", params.Probability),
			"DP", fmt.Sprintf("%d", dp),
			"prio", fmt.Sprintf("%d", dp))

		if params.ECN {
			cmd.Args = append(cmd.Args, "ecn")
		}

		output, err = cmd.CombinedOutput()
		if err != nil {
			klog.Warningf("Failed to configure GRED DP %d: %v, output: %s", dp, err, string(output))
		}
	}

	klog.V(4).Infof("Added GRED qdisc with 8 DPs, min=%d, max=%d, ecn=%v",
		params.Min, params.Max, params.ECN)
	return nil
}

// addCodelQdisc adds a Controlled Delay (Codel) qdisc
func (q *QoSManager) addCodelQdisc(ifindex int, handle, parent uint32, params *CodelParams) error {
	// Set default Codel parameters if not provided
	if params == nil {
		params = &CodelParams{
			Target:   5000,   // 5ms target delay
			Limit:    1000,   // 1000 packet limit
			Interval: 100000, // 100ms interval
			ECN:      true,   // Enable ECN by default
		}
	}

	// Use tc command as netlink doesn't have full Codel support
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("failed to get link by index %d: %w", ifindex, err)
	}

	args := []string{"qdisc", "add", "dev", link.Attrs().Name,
		"parent", fmt.Sprintf("%x:%x", parent>>16, parent&0xffff),
		"handle", fmt.Sprintf("%x:", handle>>16),
		"codel",
		"target", fmt.Sprintf("%dus", params.Target),
		"limit", fmt.Sprintf("%d", params.Limit),
		"interval", fmt.Sprintf("%dus", params.Interval),
	}

	if params.ECN {
		args = append(args, "ecn")
	}

	if params.CE > 0 {
		args = append(args, "ce_threshold", fmt.Sprintf("%dus", params.CE))
	}

	cmd := exec.Command("tc", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add Codel qdisc: %w, output: %s", err, string(output))
	}

	klog.V(4).Infof("Added Codel qdisc with target=%dus, limit=%d, interval=%dus, ecn=%v",
		params.Target, params.Limit, params.Interval, params.ECN)
	return nil
}

// addFQCodelQdisc adds a Fair Queue Controlled Delay (FQ-Codel) qdisc
// FQ-Codel combines Fair Queueing with Codel AQM for improved performance
func (q *QoSManager) addFQCodelQdisc(ifindex int, handle, parent uint32, params *CodelParams) error {
	// Set default FQ-Codel parameters if not provided
	if params == nil {
		params = &CodelParams{
			Target:   5000,   // 5ms target delay
			Limit:    10240,  // 10240 packet limit (typical for FQ-Codel)
			Interval: 100000, // 100ms interval
			ECN:      true,
		}
	}

	// Use tc command for FQ-Codel
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("failed to get link by index %d: %w", ifindex, err)
	}

	args := []string{"qdisc", "add", "dev", link.Attrs().Name,
		"parent", fmt.Sprintf("%x:%x", parent>>16, parent&0xffff),
		"handle", fmt.Sprintf("%x:", handle>>16),
		"fq_codel",
		"target", fmt.Sprintf("%dus", params.Target),
		"limit", fmt.Sprintf("%d", params.Limit),
		"interval", fmt.Sprintf("%dus", params.Interval),
	}

	if params.ECN {
		args = append(args, "ecn")
	}

	if params.CE > 0 {
		args = append(args, "ce_threshold", fmt.Sprintf("%dus", params.CE))
	}

	cmd := exec.Command("tc", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add FQ-Codel qdisc: %w, output: %s", err, string(output))
	}

	klog.V(4).Infof("Added FQ-Codel qdisc with target=%dus, limit=%d, interval=%dus, ecn=%v",
		params.Target, params.Limit, params.Interval, params.ECN)
	return nil
}
