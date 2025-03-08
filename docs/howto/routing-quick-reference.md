# Routing Quick Reference Guide

This quick reference guide provides essential commands and examples for configuring routes, VRFs, and policy-based routing in the Cilium-based networking system.

## Route Management

### Create a Route

```yaml
# basic-route.yaml
apiVersion: networking.cilium.io/v1alpha1
kind: Route
metadata:
  name: example-route
  namespace: default
spec:
  destination: "10.0.0.0/24"
  gateway: "192.168.1.1"
```

Apply with:
```bash
kubectl apply -f basic-route.yaml
```

### List Routes

```bash
kubectl get routes -A
```

### Delete a Route

```bash
kubectl delete route example-route -n default
```

## VRF Management

### Create a VRF

```yaml
# vrf.yaml
apiVersion: networking.cilium.io/v1alpha1
kind: VRF
metadata:
  name: red
  namespace: default
spec:
  tables:
    - 100
  interfaces:
    - eth1
```

Apply with:
```bash
kubectl apply -f vrf.yaml
```

### Add a Route to a VRF

```yaml
# vrf-route.yaml
apiVersion: networking.cilium.io/v1alpha1
kind: Route
metadata:
  name: vrf-route
  namespace: default
spec:
  destination: "10.1.0.0/24"
  gateway: "192.168.1.2"
  vrf: "red"
  table: "100"
```

### List VRFs

```bash
kubectl get vrfs -A
```

### Delete a VRF

```bash
kubectl delete vrf red -n default
```

## Policy-Based Routing

### Create a Policy Rule

```yaml
# policy-rule.yaml
apiVersion: networking.cilium.io/v1alpha1
kind: PolicyRule
metadata:
  name: route-by-source
  namespace: default
spec:
  priority: 100
  table: 100
  sourceIP: "192.168.1.0/24"
```

Apply with:
```bash
kubectl apply -f policy-rule.yaml
```

### List Policy Rules

```bash
kubectl get policyrules -A
```

### Delete a Policy Rule

```bash
kubectl delete policyrule route-by-source -n default
```

## Cilium CLI Commands

### Check Route Status

```bash
cilium bpf routes list
```

### Verify VRF Configuration

```bash
cilium vrf list
cilium vrf routes <vrf-name>
```

### Debug Policy Rules

```bash
cilium policy-route list
cilium policy-route match --src 10.1.0.5 --dst 8.8.8.8
```

### View Routing Tables

```bash
cilium route table show <table-id>
```

## Common Troubleshooting

### Controller Logs

```bash
kubectl logs -n kube-system -l app=cilium -c cilium-agent
```

### Check Cilium Status

```bash
cilium status --verbose
```

### Enable Debug Logging

```bash
kubectl patch configmap cilium-config -n kube-system --type merge -p '{"data":{"debug":"true","debug-verbose":"vrf,routing"}}'
```

### Restart Components

```bash
kubectl rollout restart deployment/cilium-operator -n kube-system
kubectl rollout restart daemonset/cilium -n kube-system
```
