# RBAC Minimum-Privilege Baseline

**Sprint 30 / Ticket 42** — RBAC ClusterRoles Minimum-Privilege Baseline.

This document is the authoritative catalog of every in-cluster identity shipped
by FOS1, the `ClusterRole` (or `Role`) bound to it, and the API verbs each role
is permitted. It is verified by `scripts/ci/prove-no-cluster-admin.sh`, which
runs in the Validate Manifests workflow.

## Policy

1. **No controller uses `cluster-admin`.** Every ServiceAccount is bound to a
   named, scoped ClusterRole. The CI gate enforces this.
2. **Exception annotation.** If an emergency binding to `cluster-admin` is
   introduced (e.g., a one-shot bootstrap), the `ClusterRoleBinding` must carry
   `metadata.annotations.fos1.io/rbac-exception` with a concrete reason
   describing scope and end-of-life. The annotation is the only mechanism that
   keeps the CI gate green; no wildcards, no exceptions outside the annotation.
3. **Principle of least privilege.** Verbs default to `get,list,watch` unless
   the controller source code demonstrates a mutating path. Ownership over a
   CRD (e.g., status updates) is enumerated as `update,patch` on
   `<resource>/status` and does not imply broader access.
4. **Vendor baselines.** Where an upstream component (Cilium) ships its own
   required ClusterRole, we keep the vendor-documented set rather than trimming
   it; this is called out in the table.

## Baseline State

- `cluster-admin` bindings: **0** in `manifests/` and `test-manifests/`.
- Total `ClusterRoleBinding` objects audited: **13**.
- Each binding targets a controller-specific ClusterRole (see table below).

## Per-Controller Baseline

The table lists the live rules shipped in `manifests/base/**`. Source: grepped
directly from the manifests referenced in the last column as of Sprint 30.

| Controller | ServiceAccount / NS | API Group | Resources | Verbs | Manifest |
|---|---|---|---|---|---|
| cert-manager controller | `certificate-controller` / `cert-manager` | `cert-manager.io` | `certificates`, `issuers`, `clusterissuers`, `certificaterequests` | `get,list,watch,create,update,patch,delete` | `manifests/base/cert-manager/certificate-controller.yaml` |
|  |  | `cert-manager.io` | `*/status` for the above | `get,update,patch` |  |
|  |  | `""` | `secrets`, `events`, `configmaps` | `get,list,watch,create,update,patch,delete` |  |
| Cilium agent (base) | `cilium` / `network` | `networking.k8s.io` | `networkpolicies` | `get,list,watch,create,update,patch,delete` | `manifests/base/network/cilium.yaml` |
|  |  | `""` | `pods`, `namespaces`, `nodes`, `services`, `endpoints` | `get,list,watch` |  |
|  |  | `cilium.io` | `cilium{networkpolicies,clusterwidenetworkpolicies,endpoints,nodes,identities}` + `/status` | `*` (vendor baseline) |  |
| Cilium agent (extended) | `cilium` / `kube-system` | `cilium.io` | CNP / CCNP / endpoints / nodes / identities + `/status` | `*` (vendor baseline) | `manifests/base/cilium/cilium.yaml` |
|  |  | `networking.k8s.io` | `networkpolicies` | `get,list,watch` |  |
|  |  | `""` | `pods,nodes,namespaces,endpoints,services` | `get,list,watch` |  |
|  |  | `""` | `nodes/status` | `patch,update` |  |
|  |  | `""` | `nodes/proxy` | `get` |  |
|  |  | `networking.fos1.io` | `networkinterfaces`, `routes` + `/status` | `get,list,watch,create,update,patch,delete` |  |
|  |  | `networking.fos1.io` | `vlans` + `/status` | `get,list,watch,update,patch` |  |
|  |  | `security.fos1.io` | `firewallrules`, `dpipolicies` + `/status` | `get,list,watch,create,update,patch,delete` |  |
|  |  | `dns.fos1.io` | `dnszones`, `dnsclients`, `ptrzones`, `dnsfilterlist` + `/status` | `get,list,watch` |  |
|  |  | `dhcp.fos1.io` | `dhcpv4services`, `dhcpv6services` + `/status` | `get,list,watch` |  |
| DHCP controller | `dhcp-controller` / `network` | `network.fos.io` | `dhcpv4services`, `dhcpv6services`, `vlans` | `get,list,watch` | `manifests/base/dhcp/dhcp-controller.yaml` |
|  |  | `""` | `configmaps`, `events` | `get,list,watch,create,update,patch` |  |
| FRR router | `frr-router` / `network` | `""` | `nodes`, `services`, `endpoints`, `pods` | `get,list,watch` | `manifests/base/frr/deployment.yaml` |
|  |  | `networking.fos1.io` | `bgpconfigs`, `ospfconfigs`, `routes` | `get,list,watch,update,patch` |  |
| NTP controller (network ns) | `ntp-controller` / `network` | `ntp.fos1.io` | `ntpservices` | `get,list,watch,update,patch` | `manifests/base/ntp/ntp-controller.yaml` |
|  |  | `ntp.fos1.io` | `ntpservices/status` | `update,patch` |  |
|  |  | `""` | `configmaps,pods,services,persistentvolumeclaims` | `get,list,watch,create,update,patch,delete` |  |
|  |  | `apps` | `daemonsets` | `get,list,watch,create,update,patch,delete` |  |
|  |  | `network.fos.io` | `vlans` | `get,list,watch` |  |
| NTP controller (kube-system) | `ntp-controller` / `kube-system` | `""` | `pods,services,configmaps,secrets,events` | `get,list,watch,create,update,patch,delete` | `manifests/base/ntp/rbac.yaml` |
|  |  | `apps` | `deployments,daemonsets` | `get,list,watch,create,update,patch,delete` |  |
|  |  | `ntp.fos1.io` | `ntpservices` + `/status` | `get,list,watch,create,update,patch,delete` / `get,update,patch` |  |
|  |  | `network.fos1.io` | `vlans` | `get,list,watch` |  |
|  |  | `dhcp.fos1.io` | `dhcpv4services`, `dhcpv6services` | `get,list,watch,update,patch` |  |
|  |  | `dns.fos1.io` | `dnszones`, `dnsrecords` | `get,list,watch,create,update,patch,delete` |  |
| Auth controller | `auth-controller` / `security` | `security.fos1.io` | `authproviders`, `authconfigs` | `get,list,watch,create,update,patch,delete` | `manifests/base/security/auth/auth-controller.yaml` |
|  |  | `security.fos1.io` | `*/status` for the above | `get,update,patch` |  |
|  |  | `""` | `configmaps,services,pods,events` | `get,list,watch,create,update,patch,delete` |  |
|  |  | `apps` | `deployments` | `get,list,watch,create,update,patch,delete` |  |
| IDS controller | `ids-controller` / `security` | `security.fos1.io` | `suricatainstances`, `zeekinstances`, `eventcorrelations` | `get,list,watch,create,update,patch,delete` | `manifests/base/security/ids/ids-controller.yaml` |
|  |  | `security.fos1.io` | `*/status` for the above | `get,update,patch` |  |
|  |  | `""` | `configmaps,services,pods,events` | `get,list,watch,create,update,patch,delete` |  |
|  |  | `apps` | `deployments` | `get,list,watch,create,update,patch,delete` |  |
| DPI manager | `dpi-manager` / `security` | `""` | `pods,services,endpoints,namespaces` | `get,list,watch` | `manifests/base/security/dpi-manager.yaml` |
|  |  | `cilium.io` | `ciliumnetworkpolicies`, `ciliumclusterwidenetworkpolicies` | `get,list,watch,create,update,patch,delete` |  |
|  |  | `security.fos1.io` | `dpiprofiles`, `dpiflows` | `get,list,watch,create,update,patch,delete` |  |
| WireGuard controller | `wireguard-controller` / `network` | `vpn.fos1.io` | `wireguardvpns` | `get,list,watch,update,patch` | `manifests/base/vpn/wireguard-controller.yaml` |
|  |  | `vpn.fos1.io` | `wireguardvpns/status` | `update,patch` |  |
|  |  | `""` | `configmaps,secrets,services,pods,events` | `get,list,watch,create,update,patch,delete` |  |
|  |  | `apps` | `daemonsets` | `get,list,watch,create,update,patch,delete` |  |
|  |  | `network.fos1.io` | `vlans`, `networkinterfaces` | `get,list,watch` |  |
| WireGuard daemon | `wireguard-daemon` / `network` | `""` | `nodes` | `get,list,watch` | `manifests/base/vpn/wireguard-daemon.yaml` |
|  |  | `""` | `events` | `create,patch` |  |
| Fluentd (monitoring) | `fluentd` / `monitoring` | `""` | `pods`, `namespaces` | `get,list,watch` | `manifests/base/monitoring/fluentd.yaml` |

## CRD-Centric Controllers — Expected Verb Shape

The table above reflects what is shipped. For future controllers, use these
starting points — grounded in the controller source — rather than copying the
broadest existing role:

- **FilterPolicy controller** (`pkg/security/policy/controller.go`):
  `get,list,watch,update` on `FilterPolicy`; `create,update,delete` on
  `CiliumNetworkPolicy` (namespace-scoped where possible, cluster-scoped only
  for `CiliumClusterwideNetworkPolicy`).
- **NAT controller**: `get,list,watch,update` on the NAT CRD; `create,update,delete`
  on `CiliumNetworkPolicy`.
- **DPI manager** (already shipped): `get,list,watch` on `DPIProfile`/`DPIFlow`
  plus Cilium policy CRUD.
- **Event correlator**: `get,list,watch` on `EventCorrelation`; status update
  via `update,patch` on `EventCorrelation/status`.

Controllers should **not** grant blanket CRUD on `pods`, `configmaps`, or
`secrets` cluster-wide. When a managed workload needs a ConfigMap (e.g., DHCP,
NTP), prefer:

1. A `Role`+`RoleBinding` in the target namespace, or
2. A `ClusterRole` with `resourceNames:` constraints when the name set is known
   statically.

The current baseline still uses cluster-wide `configmaps` in several roles; this
is called out in the caveats below and is tracked as a future tightening pass.

## CI Enforcement

`scripts/ci/prove-no-cluster-admin.sh`:

- Scans every `*.yaml`/`*.yml` under `manifests/` and (when present)
  `test-manifests/`.
- Splits multi-document YAML on `---`, identifies `ClusterRoleBinding`, checks
  `roleRef.name`.
- Fails (exit 1) on any binding to `cluster-admin` that lacks
  `metadata.annotations.fos1.io/rbac-exception: "<reason>"`.
- Logs allowed exceptions as `NOTE:` lines so reviewers see them in the job
  output.

The check is wired into `.github/workflows/validate-manifests.yml` as the first
step after checkout.

### Running locally

```bash
bash scripts/ci/prove-no-cluster-admin.sh
```

Add an extra directory (e.g., a downstream overlay) via:

```bash
EXTRA_SCAN_DIRS="$PWD/my-overlay" bash scripts/ci/prove-no-cluster-admin.sh
```

## Caveats / Known Gaps

1. **Two ClusterRoles named `ntp-controller`** exist — one bound in `network`,
   one in `kube-system`. Kubernetes treats them as separate RBAC objects
   because each lives in its own binding, but naming collision risks exist if
   both are ever loaded into the same cluster via `kustomize build`. A future
   pass should consolidate these.
2. **Broad `configmaps`/`secrets` verbs** are granted cluster-wide to several
   controllers (`ntp-controller`, `auth-controller`, `ids-controller`,
   `wireguard-controller`). Tightening to `resourceNames:` or namespaced
   `Role`+`RoleBinding` is a follow-up.
3. **Cilium wildcard on `cilium.io`** is vendor-standard. We accept it; it is
   not a `cluster-admin` binding.
4. **`test-manifests/`** does not exist in-tree today. The CI script scans it
   when it appears without further changes.

## References

- Plan: `docs/superpowers/plans/2026-04-21-sprint-30-ticket-42-rbac-baseline.md`
- CI script: `scripts/ci/prove-no-cluster-admin.sh`
- Workflow: `.github/workflows/validate-manifests.yml`
