# Sprint 30 / Ticket 45: QoS Enforcement Via Cilium Bandwidth Manager

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Decide between Cilium Bandwidth Manager (preferred per ADR-0001) and the Ticket 39 TC loader for QoS enforcement. Wire `QoSProfile` CRs into the chosen backend. Update `Status.md` QoS row from stub to real.

**Architecture:** Cilium Bandwidth Manager annotates pods with `kubernetes.io/egress-bandwidth`. Map `QoSProfile` → pod annotations via a mutating webhook or direct patch. Falls through to Ticket 39's TC loader for VLAN-scoped QoS where pod annotations don't apply.

**Tech Stack:** Go, Cilium Bandwidth Manager, Kubernetes admission webhooks, kustomize.

**Prerequisite:** Ticket 39 preferred; can also run independently if you commit to bandwidth-manager-only for v0.

---

## Context

- **Status.md** §QoS: "QoS Implementation (partial - QoS manager requires tc/ip commands, no unit tests)".
- `pkg/controllers/qos_controller.go` reconciles `QoSProfile` CRs but the apply side is stub.
- Ticket 39 introduces TC-bpf shaping which is orthogonal (NIC egress) to Bandwidth Manager (pod egress).

---

## File Map

- Modify: `pkg/controllers/qos_controller.go` — real apply path via Bandwidth Manager.
- Modify: `pkg/security/qos/manager.go` — remove stubs; delegate to controller.
- Create: `pkg/security/qos/bandwidth_manager.go` — translator from `QoSProfile` → pod annotations.
- Create: `pkg/security/qos/bandwidth_manager_test.go`
- Modify: `manifests/base/cilium/` — enable Bandwidth Manager in Cilium config if not already.
- Create: `manifests/examples/qos/qosprofile-example.yaml`
- Modify: `docs/design/policy-based-filtering.md` or a dedicated `docs/design/qos.md` describing the decision.
- Modify: `Status.md` — QoS row updated.

---

## Task 1: Decision And Doc

- [ ] Confirm Cilium Bandwidth Manager is available in the target Cilium version (1.14+).
- [ ] Write `docs/design/qos.md` explaining: v1 scope (egress rate limiting per pod); non-goals (classful shaping, ingress shaping, per-VLAN tagging → Ticket 39 territory).

## Task 2: Translator

- [ ] `bandwidth_manager.go`:
  - input: `QoSProfile.Spec` → selector + egress rate limit
  - output: list of pod annotations to apply via label selector match
- [ ] Idempotent: compares desired vs. current annotations before PATCH.

## Task 3: Controller Wiring

- [ ] `qos_controller.go` reconcile: translate, apply annotations, update status with count of matched pods.

## Task 4: Example + Harness

- [ ] `qosprofile-example.yaml` — rate-limit pods with label `app: noisy` to 10Mbps egress.
- [ ] CI harness: apply the example, deploy a test pod matching the selector, verify annotations land. Traffic-generation proof is optional for v0.

---

## Verification

- [ ] `make verify-mainline` green
- [ ] `go test ./pkg/security/qos/...` passes
- [ ] Example QoSProfile applies annotations to matching pods in Kind
- [ ] Status.md QoS row updated

## Out Of Scope

- Classful HTB shaping
- Ingress shaping
- Multi-NIC queue mapping (Ticket 39 / Ticket 35 territory)

## Suggested Branch

`sprint-30/ticket-45-qos-enforcement`
