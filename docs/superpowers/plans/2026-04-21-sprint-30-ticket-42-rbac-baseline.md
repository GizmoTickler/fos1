# Sprint 30 / Ticket 42: RBAC ClusterRoles Minimum-Privilege Baseline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Author minimum-privilege `ClusterRole`s for every controller currently using `cluster-admin` or loose RBAC. Add a CI check that fails if any `ClusterRoleBinding` references `cluster-admin`. Optionally wire `kube-rbac-proxy` sidecars for `:metrics` endpoints.

**Tech Stack:** Kubernetes RBAC, YAML, shell/Go validator, kustomize.

**Independence:** Self-contained; parallelizable with most Sprint 30 work.

---

## Context

- **Status.md** §Security Hardening lists RBAC + TLS as open.
- Current controllers likely bind to `cluster-admin` in dev-ops manifests. A grep over `manifests/` + `test-manifests/` will show the baseline.

---

## File Map

- Audit and modify: `manifests/base/*/rbac.yaml` per controller (create where missing).
- Create: `scripts/ci/prove-no-cluster-admin.sh` — grep over manifests, fail if any `ClusterRoleBinding` references `cluster-admin`.
- Modify: `.github/workflows/validate-manifests.yml` — new step invoking the script.
- Create: `docs/design/rbac-baseline.md` — per-controller verb/resource table.
- Modify: `Status.md` — new row: "RBAC minimum-privilege baseline — Complete".

---

## Task 1: Audit

- [ ] `grep -rn 'cluster-admin' manifests/ test-manifests/` — record each hit.
- [ ] `grep -rn 'ClusterRoleBinding' manifests/ test-manifests/` — verify each binding's subject + role.
- [ ] Enumerate each controller's actual API verbs needed:
  - FilterPolicy controller: `get,list,watch,update` on `FilterPolicy`; `create,update,delete` on `CiliumNetworkPolicy`
  - NAT controller: similar pattern
  - DPI manager: `get,list,watch` on `DPIProfile`/`DPIPolicy`
  - ...etc. for every controller

## Task 2: Write ClusterRoles

- [ ] For each controller, author a minimum `ClusterRole` + `ClusterRoleBinding` to its ServiceAccount.
- [ ] Remove `cluster-admin` bindings; replace with controller-specific bindings.
- [ ] Cover namespace-scoped needs via `Role`/`RoleBinding` where appropriate.

## Task 3: CI Check

- [ ] `scripts/ci/prove-no-cluster-admin.sh`:
  - fail if any `ClusterRoleBinding` in `manifests/`/`test-manifests/` has `roleRef.name: cluster-admin`
  - allow an override via a documented annotation `fos1.io/rbac-exception: <reason>` for explicit cases (monitoring admin during bootstrap, etc.)
- [ ] Wire into `.github/workflows/validate-manifests.yml`.

## Task 4: Optional kube-rbac-proxy For Metrics

- [ ] Decide: sidecar vs. in-process auth for `:metrics` endpoints.
- [ ] If sidecar: add to `dpi-manager`, `ntp-controller`, and API server Deployments.

## Task 5: Docs

- [ ] `docs/design/rbac-baseline.md` — table of controller → verbs → resources → namespace scope.
- [ ] Status.md + project-tracker.md updates.

---

## Verification

- [ ] `kubectl auth can-i` against each controller's SA reports only required verbs
- [ ] CI script fails intentionally when a test manifest is added with `cluster-admin`, passes on the current tree
- [ ] `make verify-mainline` unaffected

## Out Of Scope

- OIDC integration for cluster operators
- Pod Security Standards
- Network policies at controller pod level (different concern)

## Suggested Branch

`sprint-30/ticket-42-rbac-baseline`
