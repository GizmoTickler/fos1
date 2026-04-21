# Sprint 29 / Ticket 33: Translate `FilterPolicy` / `FirewallRule` CRDs Into Real Cilium Network Policies

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current stub `FilterPolicy` controller with a real translator + apply path that produces concrete `CiliumNetworkPolicy` (or `CiliumClusterwideNetworkPolicy`) objects through the existing Cilium client. Make the controller idempotent and statusful in the same shape as the NAT controller. Remove or explicitly mark `FirewallRule` / nftables as non-goals per ADR-0001 (Cilium-first).

**Architecture:** `FilterPolicy` is the authoritative CRD; `FirewallRule` has no Go types and is schema-documentation only. Follow the NAT controller pattern for status management. Reuse the existing `CiliumPolicyTranslator` in `pkg/security/policy/translator.go` — it already converts FilterPolicy specs to Cilium objects; the gap is that nothing applies them.

**Tech Stack:** Go, controller-runtime, Kubernetes API types, Cilium CRDs, Ginkgo/table-driven tests.

---

## Context (Grounded In Current Code)

### FilterPolicy types (real)
- `pkg/security/policy/types.go:13-27` — `FilterPolicy` CRD Go types with `Spec{Selectors, Actions, Scope, Priority, Enabled, Inheritance}` and `Status{Applied, LastApplied, CiliumPolicies, MatchCount, Error}`.
- `manifests/examples/policy/filter-policy-example.yaml:1-254` — example manifests: `FilterPolicy`, `FilterZone`, `FilterPolicyGroup`.

### FirewallRule types (documentation only — non-goal)
- `pkg/security/firewall/crd.go:1-138` — YAML schema only, marked DEPRECATED. **Plan: leave it deprecated, no Go types, no enforcement. Explicitly mark as non-goal in docs.**
- `pkg/cilium/controllers/firewall_controller.go:29-92` — incomplete scaffolding. **Plan: delete or gate behind an explicit `FIREWALL_RULE_ENABLED=false` that fails loudly.**

### Controllers
- `pkg/security/policy/controller.go:17-44, :110-147` — stub `Start()` / handlers. Creates `CiliumPolicyTranslator` but never applies output.
- Working tests showing state transitions: `pkg/security/policy/controller_test.go:103-152` — mock client captures applied/deleted policies.

### Reference pattern (NAT controller)
- `pkg/controllers/nat_controller.go:33-89` — reconcile shape
- `pkg/controllers/nat_controller.go:82` — `specHash := config.SpecHash()` idempotency
- `pkg/network/nat/types.go:11-29` — condition types: `Applied`, `Degraded`, `Invalid`, `Removed`
- manager returns `ApplyResult{Applied: bool}` at `pkg/network/nat/manager.go:63`

### Cilium client (available)
- `pkg/cilium/client.go:26-46`:
  - `ApplyNetworkPolicy(ctx, *CiliumPolicy) error` — takes structured type, converts to YAML, applies via `kubectl apply`
  - `DeleteNetworkPolicy(ctx, policyName string) error`

### Translator (real, needs a wired caller)
- `pkg/security/policy/translator.go` — `CiliumPolicyTranslator` already converts FilterPolicy → Cilium objects
- `pkg/security/policy/translator_test.go` — covered

---

## File Map

- Modify: `pkg/security/policy/types.go`
  - extend `FilterPolicyStatus` with `LastAppliedHash`, `Conditions` (reusing the NAT condition type set)
  - regenerate any deepcopy if applicable
- Modify: `pkg/security/policy/controller.go`
  - real reconcile: extract → translate → call `ciliumClient.ApplyNetworkPolicy`
  - spec-hash idempotency (skip if hash unchanged)
  - statusful conditions on `Applied` / `Degraded` / `Invalid` / `Removed`
  - real add / update / delete / disabled paths that call `DeleteNetworkPolicy` on removal
  - keep the existing fake-informer-free handler entry points so the existing test shape applies
- Modify: `pkg/security/policy/controller_test.go`
  - extend the existing add/update/delete tests with assertions on new status conditions and the idempotent-no-op case
- Modify: `pkg/security/policy/translator.go`
  - only if translator outputs need a deterministic name scheme (see Task 2); otherwise leave alone
- Create: `pkg/security/policy/reconciler_test.go` (optional, if controller_test.go gets too long)
  - table-driven cases: idempotent no-op, update with new rules, disable, delete
- Modify: `manifests/examples/policy/filter-policy-example.yaml`
  - only if examples need updating to match any new status surface; otherwise leave alone
- Modify: `docs/design/policy-based-filtering.md`
  - document the new apply path, the idempotency contract, the condition set
- Modify: `docs/design/implementation_caveats.md`
  - add a bullet explicitly listing `FirewallRule` and nftables as non-goals per ADR-0001
- Delete or gate: `pkg/cilium/controllers/firewall_controller.go`
  - either delete entirely (preferred) or fail-fast at startup with a clear "not supported" error
- Modify: `Status.md`
  - update FilterPolicy row from "Partial / Type definitions" to "Complete with Cilium translation and statusful reconciliation"
  - remove nftables aspirational language; cite ADR-0001

---

## Task 1: Extend Status Surface And Wire The Apply Path

**Files:**
- Modify: `pkg/security/policy/types.go`
- Modify: `pkg/security/policy/controller.go`

- [ ] **Step 1:** Add `LastAppliedHash string` and `Conditions []PolicyCondition` to `FilterPolicyStatus`. Define `PolicyCondition` matching the shape at `pkg/network/nat/types.go:11-29`: types `Applied`, `Degraded`, `Invalid`, `Removed`, plus `Status`, `Reason`, `Message`, `LastTransitionTime`. Reuse the NAT condition helpers if they're factored into a shared package; otherwise duplicate briefly.
- [ ] **Step 2:** Implement `specHash(spec *FilterPolicySpec) string` using SHA-256 of a canonical JSON encoding, matching the NAT controller's `SpecHash()` idiom.
- [ ] **Step 3:** In `controller.go`, replace the stub reconcile with:
  ```
  compute hash → compare to status.LastAppliedHash
    if equal → condition Applied=True, return (no-op)
    else →
      translator.Translate(policy) → []*cilium.CiliumPolicy
      for each policy:
        ciliumClient.ApplyNetworkPolicy(ctx, p)
        append p.Name to status.CiliumPolicies
      on any err → condition Degraded=True with reason; persist partial list
      on all-ok → condition Applied=True, store hash, record LastApplied
  ```
- [ ] **Step 4:** Delete path: `ciliumClient.DeleteNetworkPolicy(ctx, name)` for every name in previous `status.CiliumPolicies`; set condition `Removed=True`.
- [ ] **Step 5:** Disabled path: same as delete, but condition stays `Applied=False, Reason=Disabled`.
- [ ] **Step 6:** Validation failures from translator → condition `Invalid=True` with the translator error; no retry.

---

## Task 2: Deterministic Policy Naming

**Files:**
- Modify: `pkg/security/policy/translator.go` (only if current naming isn't deterministic)

- [ ] **Step 1:** Inspect `translator.go` to see how output Cilium policy names are formed. They must be:
  - deterministic given the same input
  - safe across multiple FilterPolicy CRs (include a prefix derived from the source FilterPolicy name/namespace)
  - stable across controller restarts
- [ ] **Step 2:** If names are non-deterministic (e.g. timestamp-based), change to `fos1-filter-<namespace>-<name>-<ruleIndex>` or similar. Update translator tests.

---

## Task 3: Expand Controller Tests

**Files:**
- Modify: `pkg/security/policy/controller_test.go`

Reference pattern (existing, good): `controller_test.go:103-152` (add → update → disable with mock client tracking applied/deleted).

- [ ] **Step 1:** Add `TestFilterPolicyControllerIdempotentNoop`: apply once, apply same spec again, assert client.applied grew by 1 (not 2) and status.LastAppliedHash unchanged.
- [ ] **Step 2:** Add `TestFilterPolicyControllerConditionsAppliedAndRemoved`: full lifecycle asserting the condition slice transitions.
- [ ] **Step 3:** Add `TestFilterPolicyControllerDegradedOnCiliumApplyError`: mock client returns error on one of N policies; assert condition=Degraded and status.CiliumPolicies reflects the partial-success set.
- [ ] **Step 4:** Add `TestFilterPolicyControllerRejectsInvalidSpec`: unreachable selector combo; assert condition=Invalid and no Cilium apply calls.

---

## Task 4: Remove / Gate The FirewallRule Path

**Files:**
- Delete: `pkg/cilium/controllers/firewall_controller.go`
- Delete: `pkg/security/firewall/crd.go` (or retain with a top-of-file `// DEPRECATED — removed per ADR-0001` if any external reference would break)
- Modify: `docs/design/implementation_caveats.md`
- Modify: `docs/design/policy-based-filtering.md`

- [ ] **Step 1:** Grep for any other references to `FirewallRule` / `firewall_controller` / `nftables`. Delete or comment.
- [ ] **Step 2:** In `implementation_caveats.md`, add: "FirewallRule CRD and nftables backend are non-goals per ADR-0001 (Cilium-first). FilterPolicy is the authoritative policy surface."
- [ ] **Step 3:** In `policy-based-filtering.md`, rewrite any nftables / iptables architecture sections to describe the Cilium translation path.

---

## Task 5: Docs + Status Truth-Up

**Files:**
- Modify: `Status.md`
- Modify: `docs/project-tracker.md`
- Modify: `docs/design/policy-based-filtering.md`

- [ ] **Step 1:** `Status.md`: update FilterPolicy row to "Complete — statusful Cilium translation with add/update/delete/disable lifecycle". Remove nftables from the table or explicitly mark non-goal.
- [ ] **Step 2:** `project-tracker.md`: mirror the update.
- [ ] **Step 3:** `policy-based-filtering.md`: add §"Cilium-First Enforcement" describing the translator + apply path, the condition set, and the deterministic naming scheme.

---

## Verification

- [ ] `make verify-mainline` passes
- [ ] `go test ./pkg/security/policy/...` passes with all new tests
- [ ] `grep -r "FirewallRule\|nftables" docs/ pkg/` returns only the explicit non-goal language
- [ ] Example FilterPolicy manifest apply → Cilium network policy created (verified manually in Kind; optional harness step if bandwidth permits)

---

## Out Of Scope

- Any nftables backend
- `FirewallRule` Go types or controller
- Runtime policy enforcement observability (that's dashboards/alerts — Ticket 32)
- Performance under large numbers of FilterPolicies (follow-up if needed)

---

## Suggested Branch Name

`sprint-29/ticket-33-filterpolicy-cilium-enforcement`
