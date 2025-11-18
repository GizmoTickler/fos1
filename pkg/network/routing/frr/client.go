package frr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// Client represents a client for interacting with FRRouting
type Client struct {
	config *ClientConfig
	mutex  sync.Mutex
}

// NewClient creates a new FRR client with default configuration
func NewClient() *Client {
	return &Client{
		config: DefaultClientConfig(),
	}
}

// NewClientWithConfig creates a new FRR client with custom configuration
func NewClientWithConfig(config *ClientConfig) *Client {
	return &Client{
		config: config,
	}
}

// ExecuteVtyshCommand executes a command using vtysh with retries
func (c *Client) ExecuteVtyshCommand(ctx context.Context, command string) (string, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var lastErr error
	for attempt := 0; attempt < c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			klog.V(2).Infof("Retrying vtysh command (attempt %d/%d): %s", attempt+1, c.config.MaxRetries, command)
			time.Sleep(time.Duration(c.config.RetryDelay) * time.Second)
		}

		output, err := c.executeVtyshCommandOnce(ctx, command)
		if err == nil {
			return output, nil
		}
		lastErr = err
	}

	return "", fmt.Errorf("failed after %d attempts: %w", c.config.MaxRetries, lastErr)
}

// executeVtyshCommandOnce executes a command using vtysh once without retries
func (c *Client) executeVtyshCommandOnce(ctx context.Context, command string) (string, error) {
	klog.V(4).Infof("Executing vtysh command: %s", command)

	// Create context with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(c.config.CommandTimeout)*time.Second)
	defer cancel()

	// Create the command
	cmd := exec.CommandContext(cmdCtx, c.config.VTYSHPath, "-c", command)

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command
	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	if err != nil {
		return "", fmt.Errorf("vtysh command failed (took %v): %v, stderr: %s", duration, err, stderr.String())
	}

	klog.V(4).Infof("Command completed successfully in %v", duration)
	return stdout.String(), nil
}

// ExecuteVtyshCommandJSON executes a command using vtysh and parses JSON output
func (c *Client) ExecuteVtyshCommandJSON(ctx context.Context, command string, result interface{}) error {
	// Add JSON flag to command
	jsonCommand := command
	if !strings.Contains(command, "json") {
		jsonCommand += " json"
	}

	output, err := c.ExecuteVtyshCommand(ctx, jsonCommand)
	if err != nil {
		return err
	}

	// Parse JSON
	if err := json.Unmarshal([]byte(output), result); err != nil {
		return fmt.Errorf("failed to parse JSON output: %w", err)
	}

	return nil
}

// ExecuteVtyshCommands executes multiple commands using vtysh
func (c *Client) ExecuteVtyshCommands(ctx context.Context, commands []string) (string, error) {
	// Join commands with newlines
	command := strings.Join(commands, "\n")
	return c.ExecuteVtyshCommand(ctx, command)
}

// ConfigureRouter configures the router ID
func (c *Client) ConfigureRouter(ctx context.Context, routerID string) error {
	command := fmt.Sprintf("configure terminal\nrouter-id %s\nend\nwrite memory", routerID)
	_, err := c.ExecuteVtyshCommand(ctx, command)
	return err
}

// ConfigureBGP configures BGP
func (c *Client) ConfigureBGP(ctx context.Context, asNumber int, routerID string, neighbors []BGPNeighbor, addressFamilies []BGPAddressFamily) error {
	var commands strings.Builder

	// Start configuration
	commands.WriteString("configure terminal\n")

	// Configure BGP router
	commands.WriteString(fmt.Sprintf("router bgp %d\n", asNumber))
	commands.WriteString(fmt.Sprintf("bgp router-id %s\n", routerID))

	// Configure neighbors
	for _, neighbor := range neighbors {
		// If the neighbor belongs to a peer group, specify that first
		if neighbor.PeerGroup != "" {
			commands.WriteString(fmt.Sprintf("neighbor %s peer-group %s\n", neighbor.Address, neighbor.PeerGroup))
		} else {
			commands.WriteString(fmt.Sprintf("neighbor %s remote-as %d\n", neighbor.Address, neighbor.RemoteASNumber))
		}

		if neighbor.Description != "" {
			commands.WriteString(fmt.Sprintf("neighbor %s description %s\n", neighbor.Address, neighbor.Description))
		}

		if neighbor.KeepaliveInterval > 0 && neighbor.HoldTime > 0 {
			commands.WriteString(fmt.Sprintf("neighbor %s timers %d %d\n",
				neighbor.Address, neighbor.KeepaliveInterval, neighbor.HoldTime))
		}

		if neighbor.ConnectRetryInterval > 0 {
			commands.WriteString(fmt.Sprintf("neighbor %s timers connect %d\n",
				neighbor.Address, neighbor.ConnectRetryInterval))
		}

		if neighbor.BFDEnabled {
			commands.WriteString(fmt.Sprintf("neighbor %s bfd\n", neighbor.Address))
		}

		if neighbor.RouteMapIn != "" {
			commands.WriteString(fmt.Sprintf("neighbor %s route-map %s in\n", neighbor.Address, neighbor.RouteMapIn))
		}

		if neighbor.RouteMapOut != "" {
			commands.WriteString(fmt.Sprintf("neighbor %s route-map %s out\n", neighbor.Address, neighbor.RouteMapOut))
		}

		if neighbor.PrefixListIn != "" {
			commands.WriteString(fmt.Sprintf("neighbor %s prefix-list %s in\n", neighbor.Address, neighbor.PrefixListIn))
		}

		if neighbor.PrefixListOut != "" {
			commands.WriteString(fmt.Sprintf("neighbor %s prefix-list %s out\n", neighbor.Address, neighbor.PrefixListOut))
		}

		if neighbor.FilterListIn != "" {
			commands.WriteString(fmt.Sprintf("neighbor %s filter-list %s in\n", neighbor.Address, neighbor.FilterListIn))
		}

		if neighbor.FilterListOut != "" {
			commands.WriteString(fmt.Sprintf("neighbor %s filter-list %s out\n", neighbor.Address, neighbor.FilterListOut))
		}

		if neighbor.MaxPrefixes > 0 {
			commands.WriteString(fmt.Sprintf("neighbor %s maximum-prefix %d\n", neighbor.Address, neighbor.MaxPrefixes))
		}

		if neighbor.DefaultOriginate {
			commands.WriteString(fmt.Sprintf("neighbor %s default-originate\n", neighbor.Address))
		}

		if neighbor.NextHopSelf {
			commands.WriteString(fmt.Sprintf("neighbor %s next-hop-self\n", neighbor.Address))
		}

		if neighbor.RemovePrivateAS {
			commands.WriteString(fmt.Sprintf("neighbor %s remove-private-AS\n", neighbor.Address))
		}

		if neighbor.SendCommunity {
			commands.WriteString(fmt.Sprintf("neighbor %s send-community\n", neighbor.Address))
		}

		if neighbor.SendExtendedCommunity {
			commands.WriteString(fmt.Sprintf("neighbor %s send-community extended\n", neighbor.Address))
		}

		if neighbor.SendLargeCommunity {
			commands.WriteString(fmt.Sprintf("neighbor %s send-community large\n", neighbor.Address))
		}

		if neighbor.Weight > 0 {
			commands.WriteString(fmt.Sprintf("neighbor %s weight %d\n", neighbor.Address, neighbor.Weight))
		}

		if neighbor.AllowASIn > 0 {
			commands.WriteString(fmt.Sprintf("neighbor %s allowas-in %d\n", neighbor.Address, neighbor.AllowASIn))
		}
	}

	// Configure address families
	for _, af := range addressFamilies {
		if !af.Enabled {
			continue
		}

		commands.WriteString(fmt.Sprintf("address-family %s\n", af.Type))

		// Configure networks
		for _, network := range af.Networks {
			if network.RouteMap != "" {
				commands.WriteString(fmt.Sprintf("network %s route-map %s\n", network.Prefix, network.RouteMap))
			} else if network.Backdoor {
				commands.WriteString(fmt.Sprintf("network %s backdoor\n", network.Prefix))
			} else {
				commands.WriteString(fmt.Sprintf("network %s\n", network.Prefix))
			}
		}

		// Configure aggregates
		for _, aggregate := range af.Aggregates {
			cmd := fmt.Sprintf("aggregate-address %s", aggregate.Prefix)
			if aggregate.SummaryOnly {
				cmd += " summary-only"
			}
			if aggregate.AsSet {
				cmd += " as-set"
			}
			if aggregate.RouteMap != "" {
				cmd += fmt.Sprintf(" route-map %s", aggregate.RouteMap)
			}
			commands.WriteString(cmd + "\n")
		}

		// Configure redistributions
		for _, redist := range af.Redistributions {
			if redist.RouteMapRef != "" {
				commands.WriteString(fmt.Sprintf("redistribute %s route-map %s\n",
					redist.Protocol, redist.RouteMapRef))
			} else {
				commands.WriteString(fmt.Sprintf("redistribute %s\n", redist.Protocol))
			}
		}

		// Configure maximum paths
		if af.MaximumPaths > 0 {
			commands.WriteString(fmt.Sprintf("maximum-paths %d\n", af.MaximumPaths))
		}

		if af.MaximumPathsIBGP > 0 {
			commands.WriteString(fmt.Sprintf("maximum-paths ibgp %d\n", af.MaximumPathsIBGP))
		}

		// Activate neighbors for this address family
		for _, neighbor := range neighbors {
			commands.WriteString(fmt.Sprintf("neighbor %s activate\n", neighbor.Address))
		}

		commands.WriteString("exit-address-family\n")
	}

	// End configuration
	commands.WriteString("end\nwrite memory\n")

	// Execute the commands
	_, err := c.ExecuteVtyshCommand(ctx, commands.String())
	return err
}

// ConfigureOSPF configures OSPF
func (c *Client) ConfigureOSPF(ctx context.Context, routerID string, areas []OSPFArea, redistributions []Redistribution) error {
	return c.ConfigureOSPFWithParams(ctx, routerID, areas, redistributions, 0)
}

// ConfigureOSPFWithParams configures OSPF with additional parameters
func (c *Client) ConfigureOSPFWithParams(ctx context.Context, routerID string, areas []OSPFArea, redistributions []Redistribution, referenceBandwidth int) error {
	var commands strings.Builder

	// Start configuration
	commands.WriteString("configure terminal\n")

	// Configure OSPF router
	commands.WriteString("router ospf\n")
	commands.WriteString(fmt.Sprintf("ospf router-id %s\n", routerID))

	// Set reference bandwidth if specified
	if referenceBandwidth > 0 {
		commands.WriteString(fmt.Sprintf("auto-cost reference-bandwidth %d\n", referenceBandwidth))
	}

	// Configure areas
	for _, area := range areas {
		// Configure networks in this area
		for _, intf := range area.Interfaces {
			if intf.Network != "" {
				commands.WriteString(fmt.Sprintf("network %s area %s\n", intf.Network, area.AreaID))
			}
		}

		// Configure area properties
		if area.StubArea {
			commands.WriteString(fmt.Sprintf("area %s stub\n", area.AreaID))
		}

		if area.NSSAArea {
			commands.WriteString(fmt.Sprintf("area %s nssa\n", area.AreaID))
		}

		// Configure area authentication if specified on first interface
		if len(area.Interfaces) > 0 && area.Interfaces[0].Authentication.Type != "" && area.Interfaces[0].Authentication.Type != "none" {
			if area.Interfaces[0].Authentication.Type == "md5" {
				commands.WriteString(fmt.Sprintf("area %s authentication message-digest\n", area.AreaID))
			} else if area.Interfaces[0].Authentication.Type == "simple" {
				commands.WriteString(fmt.Sprintf("area %s authentication\n", area.AreaID))
			}
		}
	}

	// Configure redistributions
	for _, redist := range redistributions {
		if redist.RouteMapRef != "" {
			commands.WriteString(fmt.Sprintf("redistribute %s route-map %s\n",
				redist.Protocol, redist.RouteMapRef))
		} else {
			commands.WriteString(fmt.Sprintf("redistribute %s\n", redist.Protocol))
		}
	}

	// Exit router configuration
	commands.WriteString("exit\n")

	// Configure interface-specific settings
	for _, area := range areas {
		for _, intf := range area.Interfaces {
			if intf.Name != "" {
				commands.WriteString(fmt.Sprintf("interface %s\n", intf.Name))

				// Configure cost
				if intf.Cost > 0 {
					commands.WriteString(fmt.Sprintf("ip ospf cost %d\n", intf.Cost))
				}

				// Configure priority
				if intf.Priority > 0 {
					commands.WriteString(fmt.Sprintf("ip ospf priority %d\n", intf.Priority))
				}

				// Configure network type
				if intf.NetworkType != "" {
					commands.WriteString(fmt.Sprintf("ip ospf network %s\n", intf.NetworkType))
				}

				// Configure authentication
				if intf.Authentication.Type != "" && intf.Authentication.Type != "none" {
					if intf.Authentication.Type == "md5" {
						commands.WriteString(fmt.Sprintf("ip ospf message-digest-key %d md5 %s\n",
							intf.Authentication.KeyID, intf.Authentication.Key))
					} else if intf.Authentication.Type == "simple" {
						commands.WriteString(fmt.Sprintf("ip ospf authentication-key %s\n",
							intf.Authentication.Key))
					}
				}

				// Configure timers
				if intf.HelloInterval > 0 {
					commands.WriteString(fmt.Sprintf("ip ospf hello-interval %d\n", intf.HelloInterval))
				}
				if intf.DeadInterval > 0 {
					commands.WriteString(fmt.Sprintf("ip ospf dead-interval %d\n", intf.DeadInterval))
				}
				if intf.RetransmitInterval > 0 {
					commands.WriteString(fmt.Sprintf("ip ospf retransmit-interval %d\n", intf.RetransmitInterval))
				}
				if intf.TransmitDelay > 0 {
					commands.WriteString(fmt.Sprintf("ip ospf transmit-delay %d\n", intf.TransmitDelay))
				}

				commands.WriteString("exit\n")
			}
		}
	}

	// End configuration
	commands.WriteString("end\nwrite memory\n")

	// Execute the commands
	_, err := c.ExecuteVtyshCommand(ctx, commands.String())
	return err
}

// ConfigureBFD configures BFD
func (c *Client) ConfigureBFD(ctx context.Context, minTxInterval, minRxInterval, multiplier int) error {
	var commands strings.Builder

	// Start configuration
	commands.WriteString("configure terminal\n")

	// Configure BFD
	commands.WriteString("bfd\n")
	commands.WriteString(fmt.Sprintf("min-tx-interval %d\n", minTxInterval))
	commands.WriteString(fmt.Sprintf("min-rx-interval %d\n", minRxInterval))
	commands.WriteString(fmt.Sprintf("multiplier %d\n", multiplier))

	// End configuration
	commands.WriteString("end\nwrite memory\n")

	// Execute the commands
	_, err := c.ExecuteVtyshCommand(ctx, commands.String())
	return err
}

// GetBGPSummary gets a summary of BGP status
func (c *Client) GetBGPSummary(ctx context.Context) (string, error) {
	return c.ExecuteVtyshCommand(ctx, "show ip bgp summary")
}

// GetOSPFNeighbors gets OSPF neighbors
func (c *Client) GetOSPFNeighbors(ctx context.Context) (string, error) {
	return c.ExecuteVtyshCommand(ctx, "show ip ospf neighbor")
}

// GetBFDPeers gets BFD peers
func (c *Client) GetBFDPeers(ctx context.Context) (string, error) {
	return c.ExecuteVtyshCommand(ctx, "show bfd peers")
}

// GetRoutes gets all routes
func (c *Client) GetRoutes(ctx context.Context) (string, error) {
	return c.ExecuteVtyshCommand(ctx, "show ip route")
}

// GetRoutesByProtocol gets routes learned from a specific protocol
func (c *Client) GetRoutesByProtocol(ctx context.Context, protocol string) (string, error) {
	return c.ExecuteVtyshCommand(ctx, fmt.Sprintf("show ip route %s", protocol))
}

// ParseRoutingTable parses the output of "show ip route" commands into Route structures
func (c *Client) ParseRoutingTable(output string) ([]Route, error) {
	routes := []Route{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Codes:") || strings.HasPrefix(line, "VRF") {
			continue
		}

		// Parse route lines - FRR format: "O>* 10.0.1.0/24 [110/10] via 192.168.1.1, eth0, 00:05:23"
		// or simpler: "O   10.0.2.0/24 [110/20] via 192.168.1.2, eth1"

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// First field contains protocol code and flags
		protocolField := fields[0]
		if len(protocolField) == 0 {
			continue
		}

		// Extract protocol from first character
		protocol := ""
		switch protocolField[0] {
		case 'O':
			protocol = "ospf"
		case 'B':
			protocol = "bgp"
		case 'C':
			protocol = "connected"
		case 'S':
			protocol = "static"
		case 'K':
			protocol = "kernel"
		default:
			continue // Skip unknown protocols
		}

		// Check if route is selected (contains '>')
		selected := strings.Contains(protocolField, ">")
		fibInstalled := strings.Contains(protocolField, "*")

		// Second field is the destination prefix
		if len(fields) < 2 {
			continue
		}
		prefix := fields[1]

		// Parse metric and distance from [distance/metric] format
		var distance, metric int
		if len(fields) >= 3 && strings.HasPrefix(fields[2], "[") {
			metricStr := strings.Trim(fields[2], "[]")
			fmt.Sscanf(metricStr, "%d/%d", &distance, &metric)
		}

		// Parse next hop - look for "via" keyword
		nextHop := ""
		iface := ""
		for i := 3; i < len(fields); i++ {
			if fields[i] == "via" && i+1 < len(fields) {
				nextHop = strings.TrimRight(fields[i+1], ",")
			} else if fields[i] != "via" && !strings.HasPrefix(fields[i], "[") &&
			          !strings.Contains(fields[i], ":") && strings.Contains(fields[i], ",") {
				// Likely an interface
				iface = strings.TrimRight(fields[i], ",")
			}
		}

		route := Route{
			Prefix:       prefix,
			NextHop:      nextHop,
			Interface:    iface,
			Protocol:     protocol,
			Metric:       metric,
			Distance:     distance,
			Selected:     selected,
			FIBInstalled: fibInstalled,
		}

		routes = append(routes, route)
	}

	return routes, nil
}

// ClearBGP clears BGP connections
func (c *Client) ClearBGP(ctx context.Context) error {
	_, err := c.ExecuteVtyshCommand(ctx, "clear ip bgp *")
	return err
}

// RestartBGP restarts the BGP daemon
func (c *Client) RestartBGP(ctx context.Context) error {
	_, err := c.ExecuteVtyshCommand(ctx, "service restart bgpd")
	return err
}

// RestartOSPF restarts the OSPF daemon
func (c *Client) RestartOSPF(ctx context.Context) error {
	_, err := c.ExecuteVtyshCommand(ctx, "service restart ospfd")
	return err
}

// DisableOSPF disables OSPF routing
func (c *Client) DisableOSPF(ctx context.Context) error {
	var commands strings.Builder

	// Start configuration
	commands.WriteString("configure terminal\n")

	// Remove OSPF router configuration
	commands.WriteString("no router ospf\n")

	// End configuration
	commands.WriteString("end\nwrite memory\n")

	// Execute the commands
	_, err := c.ExecuteVtyshCommand(ctx, commands.String())
	return err
}

// GetDaemonStatus gets the status of an FRR daemon
func (c *Client) GetDaemonStatus(ctx context.Context, daemon DaemonType) (*DaemonInfo, error) {
	output, err := c.ExecuteVtyshCommand(ctx, fmt.Sprintf("show %s", daemon))
	if err != nil {
		return nil, fmt.Errorf("failed to get daemon status: %w", err)
	}

	info := &DaemonInfo{
		Type:   daemon,
		Status: DaemonStatusUnknown,
	}

	// Parse the output to extract daemon information
	// This is a basic implementation that can be enhanced
	if strings.Contains(output, "is not running") {
		info.Status = DaemonStatusStopped
	} else if strings.Contains(output, "running") || len(output) > 0 {
		info.Status = DaemonStatusRunning
	}

	return info, nil
}

// GetAllDaemonStatus gets the status of all FRR daemons
func (c *Client) GetAllDaemonStatus(ctx context.Context) (map[DaemonType]*DaemonInfo, error) {
	daemons := []DaemonType{
		DaemonTypeZEBRA,
		DaemonTypeBGPD,
		DaemonTypeOSPFD,
		DaemonTypeOSPF6D,
		DaemonTypeBFDD,
	}

	result := make(map[DaemonType]*DaemonInfo)
	for _, daemon := range daemons {
		info, err := c.GetDaemonStatus(ctx, daemon)
		if err != nil {
			klog.V(2).Infof("Failed to get status for %s: %v", daemon, err)
			continue
		}
		result[daemon] = info
	}

	return result, nil
}

// ReloadConfiguration reloads FRR configuration
func (c *Client) ReloadConfiguration(ctx context.Context) error {
	_, err := c.ExecuteVtyshCommand(ctx, "configure terminal\nend\nwrite memory")
	return err
}

// SaveConfiguration saves the running configuration to startup config
func (c *Client) SaveConfiguration(ctx context.Context) error {
	_, err := c.ExecuteVtyshCommand(ctx, "write memory")
	return err
}

// GetRunningConfig gets the running configuration
func (c *Client) GetRunningConfig(ctx context.Context) (string, error) {
	return c.ExecuteVtyshCommand(ctx, "show running-config")
}

// GetBGPSummaryParsed gets and parses BGP summary information
func (c *Client) GetBGPSummaryParsed(ctx context.Context, asn uint32) (*BGPSummary, error) {
	output, err := c.ExecuteVtyshCommand(ctx, fmt.Sprintf("show bgp %d summary", asn))
	if err != nil {
		return nil, err
	}

	summary := &BGPSummary{
		LocalAS:   asn,
		Neighbors: []BGPNeighborStatus{},
	}

	// Parse the output to extract BGP information
	// This is a basic implementation using regex
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Look for router ID line
		if strings.Contains(line, "router identifier") {
			re := regexp.MustCompile(`router identifier (\d+\.\d+\.\d+\.\d+)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				summary.RouterID = matches[1]
			}
		}

		// Parse neighbor entries (simplified)
		// Real implementation would need more robust parsing
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			// Check if first field looks like an IP address
			if matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+\.\d+$`, fields[0]); matched {
				asn, _ := strconv.ParseUint(fields[2], 10, 32)
				neighbor := BGPNeighborStatus{
					IP:    fields[0],
					ASN:   uint32(asn),
					State: fields[len(fields)-1],
				}
				summary.Neighbors = append(summary.Neighbors, neighbor)
			}
		}
	}

	return summary, nil
}

// GetOSPFSummaryParsed gets and parses OSPF summary information
func (c *Client) GetOSPFSummaryParsed(ctx context.Context) (*OSPFSummary, error) {
	output, err := c.ExecuteVtyshCommand(ctx, "show ip ospf")
	if err != nil {
		return nil, err
	}

	summary := &OSPFSummary{
		Interfaces: []OSPFInterfaceStatus{},
		Neighbors:  []OSPFNeighborStatus{},
	}

	// Parse the output to extract OSPF information
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Look for router ID line
		if strings.Contains(line, "Router ID") {
			re := regexp.MustCompile(`Router ID (\d+\.\d+\.\d+\.\d+)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				summary.RouterID = matches[1]
			}
		}

		// Count areas
		if strings.Contains(line, "Area ID") {
			summary.Areas++
		}
	}

	// Get neighbor information
	neighborOutput, err := c.GetOSPFNeighbors(ctx)
	if err == nil {
		neighborLines := strings.Split(neighborOutput, "\n")
		for _, line := range neighborLines {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				// Check if first field looks like a router ID
				if matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+\.\d+$`, fields[0]); matched {
					neighbor := OSPFNeighborStatus{
						RouterID:  fields[0],
						Interface: fields[4],
						State:     fields[2],
					}
					summary.Neighbors = append(summary.Neighbors, neighbor)
				}
			}
		}
	}

	return summary, nil
}

// GetRoutingTableParsed gets and parses the routing table
func (c *Client) GetRoutingTableParsed(ctx context.Context) (*RoutingTable, error) {
	output, err := c.GetRoutes(ctx)
	if err != nil {
		return nil, err
	}

	table := &RoutingTable{
		Routes: []Route{},
	}

	// Parse the output to extract routing information
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Skip empty lines and headers
		if len(strings.TrimSpace(line)) == 0 || strings.HasPrefix(line, "Codes:") {
			continue
		}

		// Parse route entries (simplified)
		// Format: <protocol> <prefix> [metric/distance] via <nexthop> <interface>
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			route := Route{
				Selected:     strings.Contains(line, ">"),
				FIBInstalled: strings.Contains(line, "*"),
			}

			// Extract protocol (first character)
			if len(fields[0]) > 0 {
				route.Protocol = string(fields[0][0])
			}

			// Extract prefix
			if len(fields) > 1 {
				route.Prefix = fields[1]
			}

			// Look for "via" keyword for next hop
			for i, field := range fields {
				if field == "via" && i+1 < len(fields) {
					route.NextHop = fields[i+1]
				}
			}

			table.Routes = append(table.Routes, route)
			table.TotalRoutes++
			if route.Selected {
				table.SelectedRoutes++
			}
			if route.FIBInstalled {
				table.FIBRoutes++
			}
		}
	}

	return table, nil
}

// HealthCheck performs a health check on FRR
func (c *Client) HealthCheck(ctx context.Context) error {
	// Try to execute a simple command
	_, err := c.ExecuteVtyshCommand(ctx, "show version")
	if err != nil {
		return fmt.Errorf("FRR health check failed: %w", err)
	}
	return nil
}

// IsAvailable checks if FRR vtysh is available
func (c *Client) IsAvailable(ctx context.Context) bool {
	return c.HealthCheck(ctx) == nil
}

// ConfigureRouteMap configures a route map in FRR
func (c *Client) ConfigureRouteMap(ctx context.Context, routeMap RouteMap) error {
	var commands strings.Builder
	commands.WriteString("configure terminal\n")

	for _, entry := range routeMap.Entries {
		// Create route map entry
		commands.WriteString(fmt.Sprintf("route-map %s %s %d\n",
			routeMap.Name, entry.Action, entry.Sequence))

		// Add match conditions
		if entry.Match.Prefix != "" {
			commands.WriteString(fmt.Sprintf("match ip address prefix-list %s\n", entry.Match.Prefix))
		}
		if entry.Match.PrefixLen != "" {
			commands.WriteString(fmt.Sprintf("match ip address prefix-len %s\n", entry.Match.PrefixLen))
		}
		if entry.Match.Protocol != "" {
			commands.WriteString(fmt.Sprintf("match source-protocol %s\n", entry.Match.Protocol))
		}
		if entry.Match.Community != "" {
			commands.WriteString(fmt.Sprintf("match community %s\n", entry.Match.Community))
		}
		if entry.Match.ASPath != "" {
			commands.WriteString(fmt.Sprintf("match as-path %s\n", entry.Match.ASPath))
		}
		if entry.Match.Metric > 0 {
			commands.WriteString(fmt.Sprintf("match metric %d\n", entry.Match.Metric))
		}
		if entry.Match.Tag != "" {
			commands.WriteString(fmt.Sprintf("match tag %s\n", entry.Match.Tag))
		}

		// Add set actions
		if entry.Set.Metric > 0 {
			commands.WriteString(fmt.Sprintf("set metric %d\n", entry.Set.Metric))
		}
		if entry.Set.LocalPreference > 0 {
			commands.WriteString(fmt.Sprintf("set local-preference %d\n", entry.Set.LocalPreference))
		}
		if entry.Set.Community != "" {
			commands.WriteString(fmt.Sprintf("set community %s\n", entry.Set.Community))
		}
		if entry.Set.NextHop != "" {
			commands.WriteString(fmt.Sprintf("set ip next-hop %s\n", entry.Set.NextHop))
		}
		if entry.Set.Weight > 0 {
			commands.WriteString(fmt.Sprintf("set weight %d\n", entry.Set.Weight))
		}
		if entry.Set.ASPathPrepend != "" {
			commands.WriteString(fmt.Sprintf("set as-path prepend %s\n", entry.Set.ASPathPrepend))
		}

		commands.WriteString("exit\n")
	}

	commands.WriteString("end\nwrite memory\n")
	_, err := c.ExecuteVtyshCommand(ctx, commands.String())
	return err
}

// ConfigurePrefixList configures an IP prefix list in FRR
func (c *Client) ConfigurePrefixList(ctx context.Context, prefixList PrefixList) error {
	var commands strings.Builder
	commands.WriteString("configure terminal\n")

	ipVersion := "ip"
	if prefixList.AddressFamily == "ipv6" {
		ipVersion = "ipv6"
	}

	// Add description if provided
	if prefixList.Description != "" {
		commands.WriteString(fmt.Sprintf("%s prefix-list %s description %s\n",
			ipVersion, prefixList.Name, prefixList.Description))
	}

	for _, entry := range prefixList.Entries {
		cmd := fmt.Sprintf("%s prefix-list %s seq %d %s %s",
			ipVersion, prefixList.Name, entry.Sequence, entry.Action, entry.Prefix)

		if entry.GE > 0 {
			cmd += fmt.Sprintf(" ge %d", entry.GE)
		}
		if entry.LE > 0 {
			cmd += fmt.Sprintf(" le %d", entry.LE)
		}

		commands.WriteString(cmd + "\n")
	}

	commands.WriteString("end\nwrite memory\n")
	_, err := c.ExecuteVtyshCommand(ctx, commands.String())
	return err
}

// ConfigureASPathList configures an AS path access list in FRR
func (c *Client) ConfigureASPathList(ctx context.Context, asPathList ASPathAccessList) error {
	var commands strings.Builder
	commands.WriteString("configure terminal\n")

	for _, entry := range asPathList.Entries {
		commands.WriteString(fmt.Sprintf("bgp as-path access-list %s %s %s\n",
			asPathList.Name, entry.Action, entry.Regex))
	}

	commands.WriteString("end\nwrite memory\n")
	_, err := c.ExecuteVtyshCommand(ctx, commands.String())
	return err
}

// ConfigureCommunityList configures a community list in FRR
func (c *Client) ConfigureCommunityList(ctx context.Context, communityList CommunityList) error {
	var commands strings.Builder
	commands.WriteString("configure terminal\n")

	listType := "standard"
	if communityList.Type == "expanded" {
		listType = "expanded"
	}

	for _, entry := range communityList.Entries {
		communities := strings.Join(entry.Communities, " ")
		commands.WriteString(fmt.Sprintf("bgp community-list %s %s %s %s\n",
			listType, communityList.Name, entry.Action, communities))
	}

	commands.WriteString("end\nwrite memory\n")
	_, err := c.ExecuteVtyshCommand(ctx, commands.String())
	return err
}

// ConfigureBGPPeerGroup configures a BGP peer group in FRR
func (c *Client) ConfigureBGPPeerGroup(ctx context.Context, asNumber int, peerGroup BGPPeerGroup) error {
	var commands strings.Builder
	commands.WriteString("configure terminal\n")
	commands.WriteString(fmt.Sprintf("router bgp %d\n", asNumber))

	// Configure peer group
	commands.WriteString(fmt.Sprintf("neighbor %s peer-group\n", peerGroup.Name))

	if peerGroup.RemoteASNumber > 0 {
		commands.WriteString(fmt.Sprintf("neighbor %s remote-as %d\n", peerGroup.Name, peerGroup.RemoteASNumber))
	}

	if peerGroup.Description != "" {
		commands.WriteString(fmt.Sprintf("neighbor %s description %s\n", peerGroup.Name, peerGroup.Description))
	}

	if peerGroup.KeepaliveInterval > 0 && peerGroup.HoldTime > 0 {
		commands.WriteString(fmt.Sprintf("neighbor %s timers %d %d\n",
			peerGroup.Name, peerGroup.KeepaliveInterval, peerGroup.HoldTime))
	}

	if peerGroup.ConnectRetryInterval > 0 {
		commands.WriteString(fmt.Sprintf("neighbor %s timers connect %d\n",
			peerGroup.Name, peerGroup.ConnectRetryInterval))
	}

	if peerGroup.BFDEnabled {
		commands.WriteString(fmt.Sprintf("neighbor %s bfd\n", peerGroup.Name))
	}

	if peerGroup.RouteMapIn != "" {
		commands.WriteString(fmt.Sprintf("neighbor %s route-map %s in\n", peerGroup.Name, peerGroup.RouteMapIn))
	}

	if peerGroup.RouteMapOut != "" {
		commands.WriteString(fmt.Sprintf("neighbor %s route-map %s out\n", peerGroup.Name, peerGroup.RouteMapOut))
	}

	if peerGroup.PrefixListIn != "" {
		commands.WriteString(fmt.Sprintf("neighbor %s prefix-list %s in\n", peerGroup.Name, peerGroup.PrefixListIn))
	}

	if peerGroup.PrefixListOut != "" {
		commands.WriteString(fmt.Sprintf("neighbor %s prefix-list %s out\n", peerGroup.Name, peerGroup.PrefixListOut))
	}

	if peerGroup.FilterListIn != "" {
		commands.WriteString(fmt.Sprintf("neighbor %s filter-list %s in\n", peerGroup.Name, peerGroup.FilterListIn))
	}

	if peerGroup.FilterListOut != "" {
		commands.WriteString(fmt.Sprintf("neighbor %s filter-list %s out\n", peerGroup.Name, peerGroup.FilterListOut))
	}

	if peerGroup.MaxPrefixes > 0 {
		commands.WriteString(fmt.Sprintf("neighbor %s maximum-prefix %d\n", peerGroup.Name, peerGroup.MaxPrefixes))
	}

	if peerGroup.DefaultOriginate {
		commands.WriteString(fmt.Sprintf("neighbor %s default-originate\n", peerGroup.Name))
	}

	if peerGroup.NextHopSelf {
		commands.WriteString(fmt.Sprintf("neighbor %s next-hop-self\n", peerGroup.Name))
	}

	if peerGroup.RemovePrivateAS {
		commands.WriteString(fmt.Sprintf("neighbor %s remove-private-AS\n", peerGroup.Name))
	}

	if peerGroup.SendCommunity {
		commands.WriteString(fmt.Sprintf("neighbor %s send-community\n", peerGroup.Name))
	}

	if peerGroup.SendExtendedCommunity {
		commands.WriteString(fmt.Sprintf("neighbor %s send-community extended\n", peerGroup.Name))
	}

	if peerGroup.SendLargeCommunity {
		commands.WriteString(fmt.Sprintf("neighbor %s send-community large\n", peerGroup.Name))
	}

	if peerGroup.Weight > 0 {
		commands.WriteString(fmt.Sprintf("neighbor %s weight %d\n", peerGroup.Name, peerGroup.Weight))
	}

	if peerGroup.AllowASIn > 0 {
		commands.WriteString(fmt.Sprintf("neighbor %s allowas-in %d\n", peerGroup.Name, peerGroup.AllowASIn))
	}

	commands.WriteString("end\nwrite memory\n")
	_, err := c.ExecuteVtyshCommand(ctx, commands.String())
	return err
}

// DeleteRouteMap deletes a route map from FRR
func (c *Client) DeleteRouteMap(ctx context.Context, name string) error {
	command := fmt.Sprintf("configure terminal\nno route-map %s\nend\nwrite memory", name)
	_, err := c.ExecuteVtyshCommand(ctx, command)
	return err
}

// DeletePrefixList deletes a prefix list from FRR
func (c *Client) DeletePrefixList(ctx context.Context, name string, addressFamily string) error {
	ipVersion := "ip"
	if addressFamily == "ipv6" {
		ipVersion = "ipv6"
	}
	command := fmt.Sprintf("configure terminal\nno %s prefix-list %s\nend\nwrite memory", ipVersion, name)
	_, err := c.ExecuteVtyshCommand(ctx, command)
	return err
}

// DeleteASPathList deletes an AS path access list from FRR
func (c *Client) DeleteASPathList(ctx context.Context, name string) error {
	command := fmt.Sprintf("configure terminal\nno bgp as-path access-list %s\nend\nwrite memory", name)
	_, err := c.ExecuteVtyshCommand(ctx, command)
	return err
}

// DeleteCommunityList deletes a community list from FRR
func (c *Client) DeleteCommunityList(ctx context.Context, name string) error {
	command := fmt.Sprintf("configure terminal\nno bgp community-list %s\nend\nwrite memory", name)
	_, err := c.ExecuteVtyshCommand(ctx, command)
	return err
}

// DeleteBGPPeerGroup deletes a BGP peer group from FRR
func (c *Client) DeleteBGPPeerGroup(ctx context.Context, asNumber int, peerGroupName string) error {
	command := fmt.Sprintf("configure terminal\nrouter bgp %d\nno neighbor %s peer-group\nend\nwrite memory", asNumber, peerGroupName)
	_, err := c.ExecuteVtyshCommand(ctx, command)
	return err
}
