# Testing Cilium Controllers

This document provides guidance on testing the Cilium controllers and components for the Kubernetes-based router/firewall system.

## Unit Testing

### Prerequisites

- Go 1.18 or newer
- Access to a Kubernetes cluster (or minikube/kind for local testing)
- Cilium installed on the cluster

### Running Unit Tests

To run all the unit tests for the Cilium components:

```bash
cd /path/to/fos1
go test -v ./pkg/cilium/...
```

To run tests for a specific component:

```bash
# Test the NetworkController
go test -v ./pkg/cilium/network_controller_test.go ./pkg/cilium/network_controller.go ./pkg/cilium/types.go ./pkg/cilium/client.go

# Test the RouteSynchronizer
go test -v ./pkg/cilium/route_sync_test.go ./pkg/cilium/route_sync.go ./pkg/cilium/types.go ./pkg/cilium/client.go
```

## Integration Testing

### Controllers Integration Test

Create Custom Resources for testing each controller:

```yaml
# network_interface_test.yaml
apiVersion: "networking.fos1.io/v1"
kind: NetworkInterface
metadata:
  name: test-interface
spec:
  name: eth0
  type: physical
  address: "192.168.1.1/24"
  mtu: 1500
  vlan: 10
```

```yaml
# firewall_rule_test.yaml
apiVersion: "security.fos1.io/v1"
kind: FirewallRule
metadata:
  name: test-rule
spec:
  fromZone: "LAN"
  toZone: "WAN"
  protocol: "tcp"
  sourceIP: "192.168.1.0/24"
  destIP: "0.0.0.0/0"
  destPort: 80
  action: "allow"
```

```yaml
# route_test.yaml
apiVersion: "networking.fos1.io/v1"
kind: Route
metadata:
  name: test-route
spec:
  destination: "192.168.10.0/24"
  gateway: "192.168.1.254"
  interface: "eth0"
  metric: 100
  table: "main"
```

```yaml
# dpi_policy_test.yaml
apiVersion: "security.fos1.io/v1"
kind: DPIPolicy
metadata:
  name: test-dpi-policy
spec:
  application: "http"
  action: "allow"
  priority: 1
```

Apply these resources to your Kubernetes cluster:

```bash
kubectl apply -f network_interface_test.yaml
kubectl apply -f firewall_rule_test.yaml
kubectl apply -f route_test.yaml
kubectl apply -f dpi_policy_test.yaml
```

### Run the Controller Manager

```bash
cd /path/to/fos1
go run cmd/cilium-controller/main.go --kubeconfig=/path/to/kubeconfig
```

### Verify Operation

Verify the controllers are functioning correctly:

1. **Network Interface Controller**: Check if the network interface configuration was applied to Cilium
   ```bash
   # Check Cilium network policies
   kubectl get ciliumnetworkpolicies -A
   ```

2. **Firewall Controller**: Verify firewall rules were translated into Cilium network policies
   ```bash
   # Check Cilium network policies for firewall rules
   kubectl get ciliumnetworkpolicies -l app=firewall
   ```

3. **Routing Controller**: Check if routes were synchronized with Cilium
   ```bash
   # Check Cilium routes
   kubectl exec -n kube-system cilium-xxxx -- cilium bpf route list
   ```

4. **DPI Controller**: Verify DPI policies were applied
   ```bash
   # Check Cilium network policies for DPI
   kubectl get ciliumnetworkpolicies -l feature=dpi
   ```

## Debugging

### Logs

To check the logs of the Cilium controller:

```bash
# If running as a pod
kubectl logs -n kube-system cilium-controller-xxxx

# If running locally
go run cmd/cilium-controller/main.go --kubeconfig=/path/to/kubeconfig -v=4
```

### Cilium Status

Check the status of Cilium:

```bash
kubectl exec -n kube-system cilium-xxxx -- cilium status
```

### Controller Status

Check the status of each controller:

```bash
# If using a metrics endpoint
curl http://localhost:8080/metrics | grep controller_
```

## Performance Testing

To test the performance of the controllers:

1. Create a large number of resources (e.g., 1000 firewall rules)
2. Measure the time it takes for the controllers to process them
3. Monitor the memory and CPU usage of the controller manager

```bash
# Create 1000 firewall rules
for i in {1..1000}; do
  cat <<EOF | kubectl apply -f -
apiVersion: "security.fos1.io/v1"
kind: FirewallRule
metadata:
  name: test-rule-$i
spec:
  fromZone: "LAN"
  toZone: "WAN"
  protocol: "tcp"
  sourceIP: "192.168.1.0/24"
  destIP: "0.0.0.0/0"
  destPort: $((8000 + $i))
  action: "allow"
EOF
done
```

## Troubleshooting Common Issues

1. **Controller not processing resources**: Check RBAC permissions
2. **Cilium policies not applied**: Verify Cilium API endpoint is correct
3. **High resource usage**: Adjust the controller's worker count for better performance
4. **Route synchronization issues**: Check that the kernel routes are correctly detected

## Next Steps

After testing the base functionality, consider:

1. Adding more extensive test cases
2. Creating automated integration tests
3. Setting up continuous integration for the controllers
4. Implementing metrics collection for monitoring
