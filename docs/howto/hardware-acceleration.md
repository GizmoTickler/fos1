# FOS1 Hardware Acceleration with Cilium

This guide explains how to leverage hardware acceleration features in FOS1 when using Cilium for network policy enforcement.

## Overview

FOS1 provides seamless integration with Cilium's network policies while adding specialized hardware acceleration capabilities. This approach combines the power of Cilium's identity-based security model with optimized performance through hardware offloading.

## Supported Hardware Acceleration Types

FOS1 supports several types of hardware acceleration:

1. **XDP Acceleration** - Uses eXpress Data Path for high-speed packet processing
2. **XDP Hardware Offload** - Offloads XDP programs directly to compatible NICs
3. **SmartNIC Integration** - Utilizes programmable network cards for packet processing
4. **DPDK Integration** - Uses Data Plane Development Kit for user-space networking

## Compatible Hardware

The following hardware is compatible with FOS1's acceleration features:

### XDP-compatible NICs
* Netronome Agilio CX
* NVIDIA BlueField DPU (1st and 2nd gen)
* Intel E800 Series
* Intel Columbiaville (Ice Lake)
* Broadcom NetXtreme E-Series

### SmartNICs
* NVIDIA BlueField-2 DPU
* Pensando Elba
* Intel FPGA PAC N3000
* Napatech SmartNIC
* Netronome Agilio LX/CX/FX

### DPDK-compatible platforms
* Intel x86 platforms with DPDK-compatible NICs
* ARM64 platforms with DPDK-compatible NICs

## Enabling Hardware Acceleration

### Using CiliumNetworkPolicy

To enable hardware acceleration in a namespace-scoped policy:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: accelerated-policy
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: web-server
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: client
  options:
    # Enable XDP acceleration
    xdp: "true"
    # Optional: enable hardware offload if compatible NIC is available
    xdpOffload: "true"
```

### Using CiliumClusterwideNetworkPolicy

For cluster-wide policies with hardware acceleration:

```yaml
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: cluster-accelerated-policy
spec:
  nodeSelector:
    matchLabels:
      networking.hardware: "smartnic"
  ingress:
    - fromEndpoints: []
  options:
    # Use SmartNIC acceleration
    smartNIC: "true"
    # Specify hardware type for optimized path
    hardwareType: "bluefield-2"
```

## Advanced Configuration Options

### SmartNIC-specific Options

When using SmartNICs, you can specify the hardware type to enable optimized code paths:

```yaml
options:
  smartNIC: "true"
  hardwareType: "bluefield-2"  # or "agilio-cx", "pensando", etc.
```

### DPDK Integration

For DPDK integration, specify the PCIe device address:

```yaml
options:
  dpdk: "0000:03:00.0"  # PCIe device address of the NIC
```

### Combining Acceleration Types

Multiple acceleration types can be combined when supported by your hardware:

```yaml
options:
  xdp: "true"
  xdpOffload: "true"
  smartNIC: "true"
```

## Performance Considerations

1. **Hardware matching** - Ensure your hardware matches the acceleration type
2. **Resource allocation** - Reserve appropriate CPU cores for DPDK and SmartNIC drivers
3. **Firmware updates** - Keep NIC firmware up to date for best performance
4. **PCIe bandwidth** - Consider PCIe lane allocation for maximum throughput
5. **NUMA alignment** - For best performance, ensure NICs and CPU cores are on the same NUMA node

## Monitoring

Monitor hardware acceleration status using the following commands:

```bash
# Get overall hardware acceleration status
kubectl -n kube-system exec -it $(kubectl -n kube-system get pods -l app=fos1-ebpf-controller -o name | head -1) -- ebpfctl hardware-status

# Get detailed metrics for hardware acceleration
kubectl -n kube-system exec -it $(kubectl -n kube-system get pods -l app=fos1-ebpf-controller -o name | head -1) -- ebpfctl metrics hardware
```

## Troubleshooting

### Common Issues

1. **Hardware offload not activating**
   - Check if the NIC firmware is up to date
   - Verify the NIC is supported for offload
   - Check kernel compatibility (5.10+ recommended)

2. **Performance not as expected**
   - Check NUMA alignment
   - Verify PCIe bandwidth is not saturated
   - Check for system CPU bottlenecks

3. **Policy not applying in hardware**
   - Check hardware compatibility with policy features
   - Some advanced policy features may fall back to software

### Logs

Check the controller logs for hardware acceleration messages:

```bash
kubectl logs -n kube-system -l app=fos1-ebpf-controller | grep "Hardware acceleration"
```

## Further Reading

- [Cilium Network Policy Reference](https://docs.cilium.io/en/stable/policy/)
- [XDP Hardware Offload Guide](/docs/advanced/xdp-offload.md)
- [SmartNIC Integration Guide](/docs/advanced/smartnic-integration.md)
- [DPDK Performance Tuning](/docs/advanced/dpdk-tuning.md)

## Support

For hardware-specific questions, please contact the FOS1 support team with the following information:
- Hardware specifications
- Kernel version
- FOS1 and Cilium versions
- Controller logs
- Hardware diagnostics output
