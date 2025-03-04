# Cilium Unified Networking Package

This package provides a unified network controller based on Cilium's eBPF capabilities, replacing the separate NFTables-based implementations for firewall and NAT functionality.

## Features

- **NAT/NAT66**: IPv4 and IPv6 Network Address Translation
- **Inter-VLAN Routing**: Policy-based routing between VLANs
- **Stateful Firewall**: eBPF-based firewall with connection tracking
- **DPI Integration**: Deep Packet Inspection integration for application-aware policies
- **Service Mesh**: Integration with Kubernetes service mesh

## Components

- `NetworkController`: Main controller for managing all network functionality
- `CiliumClient`: Interface for interacting with Cilium's API
- `DefaultCiliumClient`: Implementation of the CiliumClient interface

## Usage

```go
// Create Cilium client
client := cilium.NewDefaultCiliumClient("http://localhost:9234", "")
controller := cilium.NewNetworkController(client)

// Configure NAT for IPv4
err := controller.ConfigureNAT(ctx, "192.168.1.0/24", "eth0", false)

// Configure NAT66 for IPv6
err = controller.ConfigureNAT(ctx, "2001:db8::/64", "eth0", true)

// Configure inter-VLAN routing
err = controller.ConfigureInterVLANRouting(ctx, []uint16{10, 20, 30}, false)

// Add specific VLAN policy
err = controller.AddVLANPolicy(ctx, 10, 20, false, []cilium.VLANRule{
    {
        Protocol: "tcp",
        Port:     80,
        Allow:    true,
    },
})

// Integrate with DPI
err = controller.IntegrateDPI(ctx, map[string]cilium.AppPolicy{
    "http": {
        Application: "http",
        Action:      "allow",
        Priority:    1,
    },
})
```

## Migration from NFTables

This package replaces the following deprecated implementations:

- `/pkg/security/firewall/nftables.go`: NFTables-based firewall
- `/pkg/network/nat/nat66.go`: NFTables-based NAT66

When migrating from the previous implementations:

1. Replace `NFTablesFirewall` with `cilium.NetworkController`
2. Replace `NAT66Manager` with `cilium.NetworkController`
3. Convert firewall rules to Cilium network policies
4. Update CRDs to use Cilium's CRD types instead of custom firewall CRDs

## Command-Line Tool

The package includes a command-line tool in `/cmd/cilium-controller/` for managing Cilium networking from the command line.