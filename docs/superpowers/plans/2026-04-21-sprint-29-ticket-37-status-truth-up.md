# Sprint 29 / Ticket 37: Truth-Up Status Docs After Sprint 29 Lands

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconcile every status claim in `Status.md`, `docs/project-tracker.md`, `docs/implementation-plan.md`, and `docs/observability-architecture.md` against what Sprint 29 actually landed. No status claim may survive this ticket without pointing at a merged test, manifest, or harness step.

**Architecture:** This is the closing ticket of Sprint 29. Same truth-up pattern used after tickets 20 and 27. Runs after 29-36 have merged.

**Tech Stack:** Markdown, code citations.

**Prerequisite:** Tickets 29-36 merged to `main`.

---

## Context

Tickets 29-36 together change:
- **Ticket 29** — event-correlator runtime proven E2E; docs move from "controller-only" to "round-trip proven"
- **Ticket 30** — Elasticsearch retention/rollover proven under accelerated policy; `14d` production target stays a target
- **Ticket 31** — natural-traffic DPI proof lands; canary-only language must update
- **Ticket 32** — dashboard/alert queries validated against live series; owned-vs-target split documented
- **Ticket 33** — FilterPolicy reconciles to real Cilium policies; nftables explicitly removed
- **Ticket 34** — SAML/RADIUS/certificate auth removed from the factory, CRD, docs
- **Ticket 35** — NIC + capture report real capabilities / explicit unsupported; eBPF capture labelled non-goal
- **Ticket 36** — thin-package coverage raised; test matrix updated

The risk this ticket guards against: a status claim that described Sprint 29 work before it landed, now points at the wrong shape of reality.

---

## File Map

- Modify: `Status.md`
- Modify: `docs/project-tracker.md`
- Modify: `docs/implementation-plan.md`
- Modify: `docs/observability-architecture.md`
- Modify: `docs/design/implementation_caveats.md`
- Modify: `docs/design/implementation_backlog.md`
- Modify: `README.md` / `DPI-FRAMEWORK-README.md` (only if they make status claims that now drift)

---

## Task 1: Sweep For Stale Claims

**Files:** all doc files listed above

- [ ] **Step 1:** Read each doc end-to-end.
- [ ] **Step 2:** For every factual claim about implementation state, match it to one of:
  - (a) a merged test — cite path:line
  - (b) a merged manifest — cite path
  - (c) a merged CI harness step — cite script path + step name
  - (d) an explicit non-goal — cite ADR or caveats doc
- [ ] **Step 3:** Any claim that cannot be matched to (a)-(d) is stale. Either update or delete.

---

## Task 2: `Status.md` Concrete Updates

**Files:**
- Modify: `Status.md`

- [ ] **Step 1:** Production-readiness score: rerun the math. Tickets 29-36 closing moves it from ~55% toward ~65% if the new non-goals are counted honestly (removed SAML/RADIUS/cert, nftables, eBPF-capture).
- [ ] **Step 2:** Update the Component Status Matrix rows for:
  - Event Correlation: "Complete (E2E proof in Kind harness)"
  - FilterPolicy / FirewallRule: "FilterPolicy Complete via Cilium translation; FirewallRule removed per ADR-0001"
  - Auth: remove SAML/RADIUS/cert; annotate the row with the 2026-04-21 removal
  - NIC / Capture: "Real reporting with explicit unsupported paths (matches ticket-26 offload pattern)"
- [ ] **Step 3:** Update §Testing Status coverage numbers from ~30-35% to the new measured number.
- [ ] **Step 4:** Update §Critical Implementation Gaps — remove items fixed in Sprint 29; keep eBPF compile/load, HA/clustering, REST/gRPC API as the remaining critical gaps.
- [ ] **Step 5:** Update §Production Readiness Assessment — update estimated effort-to-production based on Sprint 29's reduction of the gap list.

---

## Task 3: `docs/project-tracker.md` And `docs/implementation-plan.md` Updates

**Files:**
- Modify: `docs/project-tracker.md`
- Modify: `docs/implementation-plan.md`

- [ ] **Step 1:** Mark Tickets 29-37 as complete in `implementation-plan.md` §Current Ticket Status.
- [ ] **Step 2:** Move the Sprint 29 open list into the completed list.
- [ ] **Step 3:** Draft the "Next Phase Workstreams" replacement based on the surviving gaps:
  - eBPF runtime: compile + load (not just management framework)
  - Management API (REST / gRPC)
  - HA / controller clustering
  - Performance testing baseline
- [ ] **Step 4:** In `project-tracker.md`, update every per-feature row affected by Sprint 29.

---

## Task 4: `docs/observability-architecture.md` Updates

**Files:**
- Modify: `docs/observability-architecture.md`

- [ ] **Step 1:** Replace "Event Correlation / controller-only" language with the runtime-proven language from Ticket 29.
- [ ] **Step 2:** Add §"CI Accelerated ILM Proof" for Ticket 30.
- [ ] **Step 3:** Add §"Natural-Traffic DPI Proof" for Ticket 31.
- [ ] **Step 4:** Add §"Dashboard And Alert Query Validation" for Ticket 32.
- [ ] **Step 5:** Ensure each verified claim points at a specific CI script / harness step.

---

## Task 5: `docs/design/implementation_backlog.md` Updates

**Files:**
- Modify: `docs/design/implementation_backlog.md`

- [ ] **Step 1:** Mark Tickets 29-37 status as `completed`.
- [ ] **Step 2:** Open a new "Post-Sprint 29 Sprint" section (placeholder — leave ticket definitions for a future planning session unless the user asks to fill in now).
- [ ] **Step 3:** Carry forward remaining gaps as open items:
  - eBPF compilation + loading
  - Management API (REST / gRPC)
  - HA / clustering
  - Performance baseline
  - Threat-intelligence ingestion
  - SAML / RADIUS (if ever wanted — reintroduce under the proper 3-layer pattern)

---

## Verification

- [ ] Every Sprint 29 ticket marked complete across all four status docs
- [ ] No doc makes an implementation claim unsupported by a merged test, manifest, or harness step
- [ ] Remaining gaps after Sprint 29 are listed explicitly in `implementation-plan.md` and `implementation_backlog.md`
- [ ] `Status.md` production-readiness number is recomputed, not left stale
- [ ] No broken references to removed code (FirewallRule, nftables, SAMLAuthConfig, etc.)

---

## Out Of Scope

- Scoping the next sprint — that's a separate planning session
- Rewriting unrelated architecture docs
- Adding new features

---

## Suggested Branch Name

`sprint-29/ticket-37-status-truth-up`
