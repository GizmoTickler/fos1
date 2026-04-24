# Sprint 31 / Ticket 53: MISP Threat-Intelligence Feed (Second Feed Type)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Extend `pkg/security/threatintel/` (Sprint 30 Ticket 44) with a MISP feed type. Authenticated fetch using an API key loaded from a Kubernetes Secret. Parse MISP's JSON event schema and translate into the same `Indicator` shape URLhaus produces.

**Tech Stack:** Go `net/http`, `encoding/json`, Kubernetes Secrets.

**Prerequisite:** Ticket 44 merged (it is — Sprint 30).

---

## File Map

- Create: `pkg/security/threatintel/misp.go` — MISP API client, JSON parser, Indicator emitter
- Create: `pkg/security/threatintel/misp_test.go` — with a canned MISP JSON response
- Modify: `pkg/apis/security/v1alpha1/threatfeed_types.go` — extend `ThreatFeedSpec` with `AuthSecretRef *corev1.SecretReference`
- Modify: `pkg/security/threatintel/controller.go` — dispatch on `Format` to URLhaus or MISP fetcher, load API key from Secret when format requires auth
- Modify: `pkg/security/threatintel/manager.go` — no change expected (same `Fetcher` interface)
- Create: `manifests/examples/security/threatfeed-misp.yaml` — example with authoritative-looking MISP URL pointing at a test server
- Create: `manifests/examples/security/threatfeed-misp-auth-secret.yaml` — example Secret shape
- Modify: `docs/design/threat-intelligence-system.md` — MISP support, how authentication works
- Modify: `Status.md` threat-intel row: "URLhaus CSV + MISP JSON (v1)"

## MISP Event JSON Shape (Reference)

```json
{
  "response": [
    {
      "Event": {
        "id": "1234",
        "info": "Phishing campaign",
        "Attribute": [
          { "type": "url", "value": "http://evil.example.com/phish" },
          { "type": "ip-dst", "value": "1.2.3.4" },
          { "type": "domain", "value": "evil.example.com" }
        ]
      }
    }
  ]
}
```

Indicator mapping: `url` + `domain` → FQDN deny rule; `ip-dst` / `ip-src` → CIDR deny rule; everything else ignored in v0.

## Tasks

### Task 1: MISP Fetcher + Parser

- [ ] `misp.go`:
  - `type MISPFetcher struct { url, apiKey string; httpClient *http.Client }`
  - `func (f *MISPFetcher) Fetch(ctx context.Context) ([]Indicator, error)` — sends `Authorization: <apiKey>` + `Accept: application/json` to `<url>/events/restSearch`
  - parses events, flattens attributes, emits `Indicator{Value, Type: fqdn|cidr, Source: "misp", FirstSeen, LastSeen}`
  - skip attributes with unsupported types
  - rate-limit-aware: respect MISP's 429 with Retry-After
- [ ] Deduplicate across events (same URL in two events emits one indicator).

### Task 2: Controller Wiring

- [ ] `controller.go` dispatch in `reconcileOnce`:
  ```go
  switch spec.Format {
  case "urlhaus-csv": return c.fetchURLhaus(ctx, spec)
  case "misp-json":   return c.fetchMISP(ctx, spec)
  default:            return Invalid("unsupported format")
  }
  ```
- [ ] `fetchMISP` loads the Secret referenced by `spec.AuthSecretRef`, extracts the `apiKey` field, constructs a `MISPFetcher`.
- [ ] Missing Secret → condition `Invalid` with explicit message.
- [ ] Invalid Secret contents → condition `Invalid`.

### Task 3: Harness

- [ ] Extend `scripts/harness-threatintel.sh` OR add `scripts/harness-threatintel-misp.sh` that serves a canned MISP JSON response over `httptest.Server`-style fake and drives one reconcile cycle.

### Task 4: Tests

- [ ] `misp_test.go`:
  - `TestMISPFetch_Success` — canned server returns 3 events with 7 attributes; assert 7 indicators emitted
  - `TestMISPFetch_Unauthorized` — server returns 401; fetcher returns wrapped error
  - `TestMISPFetch_RateLimit` — server returns 429 + Retry-After; fetcher respects and retries once
  - `TestMISPFetch_MalformedJSON` — returns parse error

### Task 5: Docs + Status

- [ ] `docs/design/threat-intelligence-system.md` §v1 gains §MISP JSON Ingestion with auth model.
- [ ] `Status.md` + `docs/project-tracker.md` mirror.

## Verification

- [ ] `make verify-mainline` green
- [ ] `go test ./pkg/security/threatintel/...` passes
- [ ] One `ThreatFeed` CR with `format: misp-json` round-trips against the canned server

## Out Of Scope

- STIX/TAXII — Sprint 32+
- MISP event tagging / confidence filtering — ingest everything in v0
- Certificate-based MISP auth — API key only

## Suggested Branch

`sprint-31/ticket-53-misp-threat-feed`
