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
		commands.WriteString(fmt.Sprintf("neighbor %s remote-as %d\n", neighbor.Address, neighbor.RemoteASNumber))
		
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
	}

	// Configure address families
	for _, af := range addressFamilies {
		if !af.Enabled {
			continue
		}

		commands.WriteString(fmt.Sprintf("address-family %s\n", af.Type))
		
		// Configure networks
		for _, network := range af.Networks {
			commands.WriteString(fmt.Sprintf("network %s\n", network))
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
	var commands strings.Builder

	// Start configuration
	commands.WriteString("configure terminal\n")

	// Configure OSPF router
	commands.WriteString("router ospf\n")
	commands.WriteString(fmt.Sprintf("ospf router-id %s\n", routerID))

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
