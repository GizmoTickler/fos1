# Migrating from EBPFNetworkPolicy to Native Cilium Policies

## Overview

This guide provides instructions for migrating from the deprecated `EBPFNetworkPolicy` custom resource to Cilium's native network policies (`CiliumNetworkPolicy` and `CiliumClusterwideNetworkPolicy`). The migration aims to standardize our approach, reduce maintenance overhead, and leverage Cilium's advanced eBPF capabilities.

## Why Migrate to Cilium's Native Policies?

- **Enhanced Security**: Cilium's identity-based security model provides more granular control.
- **Advanced Features**: Native L7 protocol awareness, DNS-based filtering, and hardware acceleration.
- **Better Performance**: Cilium's eBPF implementation is highly optimized and regularly updated.
- **Simplified Architecture**: Reduced maintenance by removing custom CRDs.
- **Industry Standard**: Cilium is a CNCF graduated project with broad community support.

## Migration Path

### 1. Identify Existing EBPFNetworkPolicy Resources

```bash
kubectl get ebpfnetworkpolicy --all-namespaces
```

### 2. Translate EBPFNetworkPolicy to CiliumNetworkPolicy

#### Basic Translation Mappings

| EBPFNetworkPolicy           | CiliumNetworkPolicy                 |
|-----------------------------|-------------------------------------|
| `spec.selector.podSelector` | `spec.endpointSelector`             |
| `spec.ingress[].ports`      | `spec.ingress[].toPorts.ports`      |
| `spec.ingress[].from`       | `spec.ingress[].fromEndpoints`      |
| `spec.egress[].ports`       | `spec.egress[].toPorts.ports`       |
| `spec.egress[].to.ipBlock`  | `spec.egress[].toCIDR`              |

### 3. Handle Hardware Acceleration Features

For EBPFNetworkPolicy resources using hardware acceleration:

1. Ensure hardware is compatible with Cilium's XDP acceleration
2. Update policies to use Cilium's XDP options:

```yaml
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: hardware-accelerated-policy
spec:
  # Your policy specifics here
  options:
    xdp: "on"  # Enables XDP acceleration on compatible hardware
```

### 4. Migrate BPF Templates

When migrating custom BPF templates used with EBPFNetworkPolicy:

1. **Identify Template Usage**:
   ```bash
   grep -r "template:" --include="*.yaml" /path/to/manifests/
   ```

2. **Convert To Cilium's BPF Programs**:
   - Replace custom templates with Cilium's native capabilities
   - For specialized templates not covered by Cilium natively:
     - Use Cilium's CNI chaining to integrate with custom eBPF programs
     - Consider Cilium's eBPF Library for programmatic integrations

### 5. Hardware Component Integration

Cilium offers several ways to integrate with hardware components:

#### a. SmartNIC Integration

```yaml
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: smartnic-offload-policy
spec:
  description: "Policy with SmartNIC offloading"
  nodeSelector:
    matchLabels:
      smartnic: "enabled"
  # Policy specifications
  options:
    # Enable offloading to compatible SmartNICs
    offload: "hardware"
```

#### b. DPDK Integration

For nodes using DPDK (Data Plane Development Kit):

```yaml
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: dpdk-optimized-policy
spec:
  description: "Policy optimized for DPDK environments"
  nodeSelector:
    matchLabels:
      dpdk: "enabled"
  # Policy specifications
```

#### c. XDP Hardware Offload

For network cards supporting XDP hardware offload:

```yaml
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: xdp-offload-policy
spec:
  # Policy specifications
  options:
    xdp: "on"
    # Enable hardware offload when available
    xdpOffload: "on"
```

### 6. Testing and Validation

1. Deploy both old and new policies in parallel (with the new ones having higher precedence)
2. Verify traffic flow and policy enforcement behavior
3. Monitor performance metrics to ensure hardware acceleration is working
4. Check Cilium agent logs for any hardware integration issues

### 7. Common Migration Challenges

#### Challenge: Custom eBPF Maps

If you were using custom eBPF maps with EBPFNetworkPolicy:

- Use Cilium's BPF maps for standard use cases
- For custom data structures, use Cilium's generic maps API
- Consider implementing a Cilium CNI plugin for specialized needs

#### Challenge: Hardware-Specific Optimizations

For hardware-specific optimizations:

- Review Cilium's supported hardware acceleration list
- Verify driver compatibility with your specific hardware
- Consider contributing hardware-specific enhancements to Cilium

## Examples

### Before: EBPFNetworkPolicy with Hardware Acceleration

```yaml
apiVersion: networking.fos1.io/v1alpha1
kind: EBPFNetworkPolicy
metadata:
  name: hardware-accelerated-policy
  namespace: default
spec:
  description: "Network policy with hardware acceleration"
  policyType: filtering
  hardwareAcceleration: 
    enabled: true
    xdpOffload: true
    offloadType: "smartnic"
  selector:
    podSelector:
      matchLabels:
        app: secure-workload
  ingress:
    - ports:
        - protocol: TCP
          port: 443
      action: allow
```

### After: CiliumNetworkPolicy with Hardware Acceleration

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: hardware-accelerated-policy
  namespace: default
spec:
  description: "Network policy with hardware acceleration"
  endpointSelector:
    matchLabels:
      app: secure-workload
  ingress:
    - toPorts:
        - ports:
            - port: "443"
              protocol: TCP
  options:
    xdp: "on"
```

## Timeline and Support

- EBPFNetworkPolicy CRD is now deprecated
- Support for EBPFNetworkPolicy will be maintained for 6 months
- All users are encouraged to migrate to native Cilium policies as soon as possible
- The migration team is available for assistance at `migration-support@fos1.io`
