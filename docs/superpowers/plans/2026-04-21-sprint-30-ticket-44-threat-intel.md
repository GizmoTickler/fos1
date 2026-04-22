# Sprint 30 / Ticket 44: Threat-Intelligence Feed Ingestion v0

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Ingest one public blocklist feed into a new `ThreatFeed` CRD with periodic refresh. Translate entries into `CiliumPolicy` deny rules via the existing Ticket 17 DPI-event pipeline or a direct translator. Expire entries per feed max-age. Sprint 29 non-goal; delivered in Sprint 30.

**Architecture:** Recommend **abuse.ch URLhaus** CSV for simplicity (open, no key). MISP can come later. Controller polls feed URL on a schedule, parses, produces indicator records, translates to Cilium policies with TTL.

**Tech Stack:** Go, Kubernetes CRD, `net/http`, CSV parser, CiliumPolicy types.

**Independence:** Self-contained.

---

## Context

- **Status.md** §Threat Intelligence: "Framework defined but no data sources."
- `docs/design/threat-intelligence-system.md` exists as architecture-only.
- Ticket 17 already landed the DPI-event → Cilium policy pipeline with TTL.

---

## File Map

- Create: `pkg/apis/security/v1alpha1/threatfeed_types.go` — `ThreatFeed` CRD.
- Create: `pkg/security/threatintel/`:
  - `manager.go` — fetch loop, parse, dedupe, TTL tracking
  - `urlhaus.go` — URLhaus CSV fetcher and parser
  - `translator.go` — `Indicator` → `CiliumPolicy`
  - `controller.go` — reconciles `ThreatFeed` CRs
  - tests for each
- Create: `cmd/threatintel-controller/main.go`
- Create: `manifests/base/threatintel/` — Deployment, Service, RBAC, CRD, kustomization
- Create: `manifests/examples/security/threatfeed-urlhaus.yaml` — example CR
- Modify: `docs/design/threat-intelligence-system.md` — describe v0 scope (URLhaus only); list MISP and STIX as non-goals
- Modify: `Status.md` — §Threat Intelligence: "v0 — URLhaus ingestion; other feeds non-goal"

---

## Task 1: CRD Types

- [ ] `ThreatFeed.Spec`:
  - `URL string` — feed source
  - `Format string` — "urlhaus-csv" for now
  - `RefreshInterval metav1.Duration`
  - `MaxAge metav1.Duration` — how long each entry stays enforced after ingestion
  - `Enabled bool`
- [ ] `ThreatFeed.Status`:
  - `LastFetchTime metav1.Time`
  - `LastFetchError string`
  - `EntryCount int32`
  - `ActiveIndicators int32`
  - `Conditions []ThreatFeedCondition` — same shape as FilterPolicy/NAT

## Task 2: Fetcher And Parser

- [ ] `urlhaus.go`:
  - HTTP GET with 30s timeout
  - CSV parse: skip comment lines, extract `url,url_status,date_added,threat`
  - return `[]Indicator{URL, Threat, DateAdded}`
- [ ] Respect `Cache-Control` / ETag on re-fetch (optional v0; nice-to-have).

## Task 3: Translator

- [ ] Extract domain from URL → CiliumPolicy `toFQDNs` deny rule.
- [ ] Deterministic naming: `fos1-threatintel-<feed-name>-<indicator-hash>`.
- [ ] Apply via existing Cilium client; delete on TTL expiry.

## Task 4: Controller

- [ ] Periodic reconcile driven by `ThreatFeed.Spec.RefreshInterval`.
- [ ] On each cycle: fetch, diff vs. previous, apply new, delete expired.
- [ ] Status reflects fetch success + active indicator count.

## Task 5: Harness Proof

- [ ] Add CI harness step that serves a canned URLhaus CSV via a test pod's nginx, points a `ThreatFeed` at it, and asserts Cilium policies appear.

---

## Verification

- [ ] `make verify-mainline` green
- [ ] Unit tests cover fetcher error handling, translator output shape, controller reconcile semantics
- [ ] CI harness proves end-to-end fetch → translate → apply

## Out Of Scope

- MISP integration
- STIX/TAXII
- Confidence scoring
- Feed authentication

## Suggested Branch

`sprint-30/ticket-44-threat-intel-v0`
