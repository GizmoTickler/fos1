# VPN Package

This package provides VPN functionality for the router/firewall system.

## WireGuard Implementation

The WireGuard implementation includes:

- WireGuard interface configuration
- Peer management
- Key generation and management
- Configuration file generation

## Usage

```go
import (
    "context"
    "github.com/varuntirumala1/fos1/pkg/vpn"
)

func main() {
    // Create a new WireGuard service
    service := vpn.NewWireGuardService()
    
    // Generate keys
    privateKey, publicKey, err := vpn.GenerateKeys()
    if err != nil {
        log.Fatal(err)
    }
    
    // Create a WireGuard configuration
    config := &vpn.WireGuardConfig{
        InterfaceName: "wg0",
        PrivateKey:    privateKey,
        ListenPort:    51820,
        Address:       "10.10.10.1/24",
        PostUp: []string{
            "iptables -A FORWARD -i %i -j ACCEPT",
            "iptables -A FORWARD -o %i -j ACCEPT",
        },
        PostDown: []string{
            "iptables -D FORWARD -i %i -j ACCEPT",
            "iptables -D FORWARD -o %i -j ACCEPT",
        },
        Peers: []vpn.WireGuardPeer{
            {
                PublicKey:           "peer1-public-key",
                AllowedIPs:          []string{"10.10.10.2/32"},
                PersistentKeepalive: 25,
            },
        },
    }
    
    // Add the configuration to the service
    if err := service.AddInterface(config); err != nil {
        log.Fatal(err)
    }
    
    // Start the service
    ctx := context.Background()
    if err := service.Start(ctx); err != nil {
        log.Fatal(err)
    }
    
    // Generate a configuration file
    configFile, err := service.GenerateConfig("wg0")
    if err != nil {
        log.Fatal(err)
    }
    
    // Stop the service when done
    if err := service.Stop(ctx); err != nil {
        log.Fatal(err)
    }
}
```

## Integration with Kubernetes

This package can be used in a Kubernetes controller to manage WireGuard VPN configurations based on custom resources. The controller would:

1. Watch for WireGuard CRD changes
2. Generate configurations based on the CRD
3. Apply the configurations using this package
4. Report status back to the Kubernetes API

## Security Considerations

- Private keys should be stored securely (e.g., in Kubernetes secrets)
- Access to the VPN service should be restricted
- Regular rotation of keys is recommended