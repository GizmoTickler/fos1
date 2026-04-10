# ADR-0001: Cilium-First Control-Plane Contract

## Status
Accepted

## Context

The repository contains real kernel-native implementations for parts of routing, VLAN, DHCP, DNS, and WireGuard, while higher-level Cilium abstractions still include placeholder or partially implemented flows. This creates ambiguity for implementers: some paths are real but unused, while some controller paths appear active but do not enforce behavior.

For v1, the project will use a **Cilium-first control plane**. That means Cilium is the authoritative enforcement and synchronization layer for routing, NAT, policy, and traffic decisions exposed through the Kubernetes CRDs. Kernel-native helpers may remain as implementation details where needed, but controllers must not rely on them as alternate active paths unless they are explicitly routed through the Cilium contract defined here.

## Decision

### Authoritative v1 control-plane responsibilities

1. **Routing**
   - Cilium owns route synchronization for CRD-driven route state.
   - Kernel route helpers may be used only as discovery or low-level support code.
   - Routing reconciliation must be idempotent and statusful.

2. **NAT**
   - Cilium owns SNAT/DNAT/NAT66/NAT64 and port-forwarding enforcement.
   - No controller may report NAT success unless the Cilium enforcement path has applied it.

3. **Policy enforcement**
   - Firewall and security policy objects must resolve to Cilium-enforced behavior.
   - Placeholder policy translation or log-only success paths are not acceptable in active controllers.

4. **VLAN / inter-VLAN behavior**
   - VLAN creation and host-level interface state remain kernel responsibilities.
   - VLAN routing and policy decisions must be expressed through the Cilium control-plane contract.

5. **DPI-driven response**
   - DPI engines may emit events and recommendations.
   - Enforcement actions must be translated into Cilium policy changes.

## Contract Rules

### 1. One active enforcement path per feature

Each feature must have a single authoritative enforcement path in v1:

- Routing -> Cilium
- NAT -> Cilium
- Network/security policy -> Cilium
- DPI response -> Cilium policy actions

If a kernel-native helper is used, it must be explicitly described as an internal support function, not a second active control path.

### 2. Controllers must reflect applied state

Controllers must:

- validate input
- apply desired state
- surface failures
- report observed/applied status

Controllers must not mark a resource successful when the backend only logged a request or returned a placeholder value.

### 3. Placeholder success paths are deprecated

Any implementation that returns success without making a real backend change is considered deprecated for v1 controller paths.

Examples of deprecated patterns:

- dummy synchronizers
- placeholder route diffing
- log-only NAT application
- simulated policy updates
- stub controller status values

### 4. Legacy helpers may remain, but only behind the contract

Existing kernel-native helpers may remain in the repository if they are:

- used by the Cilium-first control plane as internal support code, or
- isolated as legacy/experimental paths with no active controller dependency

They must not silently bypass the Cilium contract.

## Implementation Mapping

### Active paths

- `pkg/cilium/*`
- `pkg/controllers/*` where the controller reconciles into Cilium behavior
- `pkg/security/dpi/*` when emitting events that become Cilium policy actions

### Internal support paths

- `pkg/network/interfaces/*`
- `pkg/network/routing/*`
- `pkg/network/nat/*`
- `pkg/hardware/ebpf/*`
- `pkg/network/ebpf/*`

These packages may provide discovery, validation, translation, or low-level host support, but they do not define the authoritative v1 control-plane contract.

### Legacy or placeholder paths to eliminate from active flows

- dummy route synchronization
- log-only NAT methods
- placeholder policy application
- simulated controller status values
- no-op service integration paths

## Consequences

### Positive

- Implementers get a single authoritative path per feature.
- Controllers can be made idempotent and testable.
- Ticket sequencing becomes clearer.
- Status reporting can be evaluated against one observed backend.

### Tradeoffs

- Some real kernel-native work will be relegated to support code instead of active control-plane ownership.
- Existing docs and controllers need cleanup to match the contract.
- Several placeholder paths will need removal or explicit deprecation.

## Acceptance Criteria For Downstream Tickets

Downstream implementation tickets should be considered complete only when:

1. the controller uses the Cilium-first active path defined here,
2. placeholder success behavior is removed from the active flow,
3. status reflects applied state,
4. tests verify success and failure behavior,
5. any legacy helper code used is clearly marked as support-only.

## Related Tickets

- Ticket 2: Implement real Cilium route operations
- Ticket 3: Replace placeholder route synchronization
- Ticket 6: Implement real Cilium NAT core
- Ticket 8: Make NAT controller statusful and idempotent
- Ticket 17: Wire DPI events into real Cilium policy responses
