# VLAN Implementation for FOS1

This package implements VLAN management for the FOS1 platform, leveraging Kubernetes CRDs for configuration and state management.

## Overview

The VLAN implementation provides a way to create and manage IEEE 802.1Q VLAN interfaces in a Kubernetes-native way. It consists of:

- A VLAN Manager that interacts with the Linux networking stack
- A VLAN Controller that reconciles VLAN CRDs with the actual system state
- Event handlers for notifications about VLAN-related events

## Features

- Create, update, and delete VLAN interfaces
- Configure Quality of Service (QoS) settings for VLANs
- Support for trunk interfaces with multiple VLANs
- Automatic status updates with interface statistics
- Integration with Kubernetes CRDs
- Event-driven architecture with callbacks

## Usage Example

### Creating a VLAN interface via CRD

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: vlan100
spec:
  name: vlan100
  type: vlan
  parent: eth0
  vlanId: 100
  mtu: 1500
  addresses:
    - "192.168.100.1/24"
    - "2001:db8::1/64"
  qos:
    priority: 3
    dscp: 0
```

### Using the VLAN Manager programmatically

```go
import (
    "fmt"
    "net"
    "github.com/fos1/pkg/network/vlan"
)

func main() {
    // Create a VLAN manager
    manager := vlan.NewVLANManagerImpl()
    
    // Define VLAN configuration
    config := vlan.VLANConfig{
        MTU: 1500,
        Addresses: []vlan.IPConfig{
            {
                Address: net.ParseIP("192.168.100.1"),
                Prefix:  24,
            },
        },
        QoSPriority: 3,
        State:       "up",
    }
    
    // Create a VLAN interface
    vlanInterface, err := manager.CreateVLAN("eth0", 100, "vlan100", config)
    if err != nil {
        fmt.Printf("Failed to create VLAN: %v\n", err)
        return
    }
    
    fmt.Printf("Created VLAN interface %s (state: %s)\n", 
               vlanInterface.Name, vlanInterface.OperationalState)
}
```

### Starting the VLAN Controller

```go
import (
    "context"
    "github.com/fos1/pkg/network/vlan"
    "k8s.io/client-go/kubernetes"
)

func StartVLANController(kubeClient kubernetes.Interface) error {
    // Create a VLAN manager
    manager := vlan.NewVLANManagerImpl()
    
    // Create controller configuration
    config := vlan.VLANControllerConfig{
        ResyncInterval:           60,
        MaxConcurrentReconciles:  2,
        DefaultQoSPriority:       0,
        DefaultDSCP:              0,
        DefaultMTU:               1500,
        VLANNetlinkTimeout:       5,
        EnableSysctlConfiguration: true,
    }
    
    // Create the controller
    controller := vlan.NewVLANController(kubeClient, manager, config)
    
    // Add an event handler
    controller.AddEventHandler(func(event vlan.VLANEvent) {
        fmt.Printf("VLAN event: %s - %s\n", event.Type, event.Interface.Name)
    })
    
    // Start the controller
    ctx := context.Background()
    if err := controller.Start(ctx); err != nil {
        return err
    }
    
    return nil
}
```

## Architecture

The VLAN implementation follows these design principles:

1. **Kubernetes-native** - Uses CRDs to manage configuration and state
2. **Loosely coupled** - The manager and controller can be used independently
3. **Event-driven** - Provides callbacks for events
4. **Resilient** - Handles errors and retries operations with exponential backoff

## Testing

The package includes both unit tests and integration tests:

```bash
go test -v ./pkg/network/vlan/...
```

## Future Enhancements

- Support for QinQ (IEEE 802.1ad) VLANs
- Integration with network policies
- Support for hardware offloading
- Enhanced QoS capabilities
