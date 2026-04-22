# Cilium Unified Networking Package

This package provides a unified network controller based on Cilium's eBPF capabilities, replacing the separate NFTables-based implementations for firewall and NAT functionality.

## Features

- **NAT/NAT66**: IPv4 and IPv6 Network Address Translation
- **Inter-VLAN Routing**: Policy-based routing between VLANs
- **Stateful Firewall**: eBPF-based firewall with connection tracking
- **DPI Integration**: Deep Packet Inspection integration for application-aware policies
- **Service Mesh**: Integration with Kubernetes service mesh

## Components

### Core Components
- `NetworkController`: Main controller for managing all network functionality
- `CiliumClient`: Interface for interacting with Cilium's API
- `DefaultCiliumClient`: Implementation of the CiliumClient interface
- `RouteSynchronizer`: Ensures routes are synchronized between kernel routing tables and Cilium's eBPF maps

### Controllers
- `NetworkInterfaceController`: Watches for NetworkInterface CRDs and translates them to Cilium configurations
- `RoutingController`: Watches for Route CRDs and translates them to Cilium route configurations
- `DPIController`: Watches for DPIPolicy CRDs and translates them to Cilium DPI configurations
- `ControllerManager`: Coordinates all controllers for seamless integration

> FirewallRule / `FirewallController` were removed in sprint 29 ticket 33 per ADR-0001.
> FilterPolicy (see `pkg/security/policy`) is the authoritative policy surface.

## Usage

### Basic NetworkController Usage

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

### Setting Up Controllers with Kubernetes CRDs

```go
// Create Kubernetes dynamic client
config, err := rest.InClusterConfig()
if err != nil {
    // handle error
}
dynamicClient, err := dynamic.NewForConfig(config)
if err != nil {
    // handle error
}

// Create Cilium client
ciliumClient := cilium.NewDefaultCiliumClient("http://localhost:9234", "")

// Create NetworkController
networkController := cilium.NewNetworkController(ciliumClient)

// Create RouteSynchronizer
routeSynchronizer := cilium.NewRouteSynchronizer(
    ciliumClient,
    30*time.Second, // Poll period
)

// Create ControllerManager
manager := controllers.NewControllerManager(
    dynamicClient,
    ciliumClient,
    routeSynchronizer,
    networkController,
)

// Initialize controllers
manager.Initialize()

// Start controllers
ctx := context.Background()
err = manager.Start(ctx)
if err != nil {
    // handle error
}

// Later, when shutting down
manager.Stop()
```

### Integration with VLAN Manager

```go
// Create VLAN manager with Cilium integration
vlanManager := vlan.NewVLANManager()

// Create VLAN config and event handler
vlanConfig := &vlan.VLANControllerConfig{
    // Standard VLAN config...
    CiliumClient:       ciliumClient, // Pass the Cilium client
    NetworkController:  networkController, // Pass the Cilium network controller
}

// Initialize VLAN controller with Cilium event handlers
vlanController, err := vlan.NewVLANController(vlanConfig)
if err != nil {
    // handle error
}

// Start VLAN controller
err = vlanController.Start(ctx)
if err != nil {
    // handle error
}
```

## Migration from NFTables

Per ADR-0001 (Cilium-First Control Plane) and sprint 29 ticket 33, the
NFTables-based firewall implementations have been fully removed:

- `pkg/security/firewall/nftables.go` — removed along with the rest of the
  `pkg/security/firewall/` package
- `pkg/security/policy/translator.go` — rewritten from nftables
  (`NFTFirewallRule`) to Cilium (`*cilium.CiliumPolicy`)
- `pkg/security/policy/zone_manager.go` — removed (nftables-backed zone
  chains are not part of the Cilium-first surface)
- `pkg/cilium/controllers/firewall_controller.go` — removed along with the
  `FirewallRule` CRD manifest

Existing clusters that had `FirewallRule` CRs applied must migrate them to
`FilterPolicy` before upgrading. See the `FilterPolicy` example at
`manifests/examples/policy/filter-policy-example.yaml`.

## Command-Line Tool

The package includes a command-line tool in `/cmd/cilium-controller/` for managing Cilium networking from the command line.