# Migration Guide: Moving from EBPFNetworkPolicy to Native Cilium Network Policies

## Overview

This guide outlines the process for migrating from the deprecated `EBPFNetworkPolicy` CRD to native Cilium Network Policies. As of March 2025, we are standardizing on Cilium's built-in network policy capabilities to simplify our architecture and leverage Cilium's advanced features.

## Why Migrate?

1. **Simplified Architecture**: Using native Cilium policies reduces complexity and maintenance overhead
2. **Enhanced Performance**: Native policies are directly processed by the Cilium datapath
3. **Advanced Features**: Access to Cilium's latest policy features (L7, DNS, identity-based, etc.)
4. **Better Integration**: Direct support from Cilium's observability stack (Hubble)
5. **Broader Community Support**: Benefit from upstream documentation, examples, and troubleshooting

## Policy Types

### Cilium Network Policies
- **CiliumNetworkPolicy (CNP)**: Namespace-scoped policies (equivalent to Kubernetes NetworkPolicy)
- **CiliumClusterwideNetworkPolicy (CCNP)**: Cluster-wide policies (no namespace restriction)

## Migration Steps

### 1. Mapping from EBPFNetworkPolicy to Cilium Policies

| EBPFNetworkPolicy Field | Cilium Policy Field | Notes |
|-------------------------|---------------------|-------|
| `spec.description` | `spec.description` | Direct mapping |
| `spec.selector.podSelector` | `spec.endpointSelector` | Cilium uses endpointSelector for pods |
| `spec.selector.namespaceSelector` | `spec.endpointSelector.matchExpressions` | Combine with endpointSelector |
| `spec.selector.nodeSelector` | Use CCNP and `spec.nodeSelector` | Only available in CCNP |
| `spec.policyType: "filtering"` | Use ingress/egress rules | Cilium has specific rule formats |
| `spec.policyType: "routing"` | Not directly supported | Use Cilium's routing features |
| `spec.policyType: "nat"` | Not directly supported | Use Cilium's NAT features |
| `spec.policyType: "qos"` | Not directly supported | Use Cilium's bandwidth manager |
| `spec.egress` | `spec.egress` | Similar format, see examples |
| `spec.ingress` | `spec.ingress` | Similar format, see examples |
| `spec.priority` | Use `spec.labels` | Order policies with labels |

### 2. Example Conversion

#### Original EBPFNetworkPolicy
```yaml
apiVersion: networking.fos1.io/v1alpha1
kind: EBPFNetworkPolicy
metadata:
  name: restrict-db-access
  namespace: app
spec:
  description: "Restrict database access"
  policyType: "filtering"
  selector:
    podSelector:
      matchLabels:
        app: database
  priority: 100
  ingress:
    - description: "Allow from app servers"
      from:
        - podSelector:
            matchLabels:
              app: api-server
      ports:
        - protocol: TCP
          port: 5432
      action: allow
```

#### Equivalent CiliumNetworkPolicy
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: restrict-db-access
  namespace: app
spec:
  description: "Restrict database access"
  endpointSelector:
    matchLabels:
      app: database
  labels:
    - "priority=100"
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: api-server
      toPorts:
        - ports:
            - port: "5432"
              protocol: TCP
```

### 3. Special Cases

#### QoS/Bandwidth Policies
For QoS policies, use Cilium's bandwidth management features directly:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: bandwidth-limit
  namespace: app
spec:
  endpointSelector:
    matchLabels:
      app: streaming
  egress:
    - toBandwidth:
        rate: "10M"
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
```

#### Advanced L7 Policies
Cilium supports advanced L7 policies that weren't available in EBPFNetworkPolicy:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: http-rule
  namespace: app
spec:
  endpointSelector:
    matchLabels:
      app: api
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: frontend
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
          rules:
            http:
              - method: "GET"
                path: "/api/v1/users"
```

## Testing Your Migration

1. Apply both the original EBPFNetworkPolicy and the new Cilium policy
2. Verify traffic flows as expected using Hubble observe
3. Remove the EBPFNetworkPolicy once confirmed
4. Check Hubble UI for policy visibility

## Timeline

- **March 2025**: EBPFNetworkPolicy marked as deprecated
- **June 2025**: Recommended completion of migrations
- **December 2025**: EBPFNetworkPolicy CRD will be removed

## Resources

- [Cilium Network Policy Documentation](https://docs.cilium.io/en/v1.17/policy/)
- [Kubernetes Network Policy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Network Policy Editor](https://editor.cilium.io/)

For assistance with complex migration cases, please open an issue on the repository.
