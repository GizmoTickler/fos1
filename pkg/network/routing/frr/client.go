package frr

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// Client represents a client for interacting with FRRouting
type Client struct {
	mutex sync.Mutex
}

// NewClient creates a new FRR client
func NewClient() *Client {
	return &Client{}
}

// ExecuteVtyshCommand executes a command using vtysh
func (c *Client) ExecuteVtyshCommand(ctx context.Context, command string) (string, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	klog.V(4).Infof("Executing vtysh command: %s", command)

	// Create the command
	cmd := exec.CommandContext(ctx, "vtysh", "-c", command)

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to execute vtysh command: %v, stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
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
