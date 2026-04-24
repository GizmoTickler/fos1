# Sprint 31 / Ticket 48: Write-Path REST API (POST / PUT / PATCH / DELETE For FilterPolicy)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Extend the Sprint 30 Ticket 41 read-only REST API with full CRUD over `/v1/filter-policies`. Enforce the Subject-CN allowlist on every write verb. Validate specs at the handler before calling the controller-runtime client.

**Architecture:** Same `cmd/api-server/` binary, same mTLS + allowlist middleware. Add handlers for POST/PUT/PATCH/DELETE. Validation happens in a new `pkg/api/validation.go` so the logic is shared with the CRD webhook pattern if one is ever added.

**Tech Stack:** Go `net/http`, `controller-runtime`, `k8s.io/apimachinery/pkg/api/errors`.

**Prerequisite:** Ticket 41 merged (it is — landed in Sprint 30).

---

## File Map

- Modify: `pkg/api/filterpolicy_handler.go`:
  - add `Create(w, r)`, `Replace(w, r)`, `Patch(w, r)`, `Delete(w, r)`
  - each uses the `controller-runtime` client's `Create/Update/Patch/Delete` methods
- Modify: `pkg/api/server.go` — route registration for the new verbs
- Create: `pkg/api/validation.go` — validate `FilterPolicy.Spec` shape, return 422 with a structured error body on failure
- Modify: `pkg/api/filterpolicy_handler_test.go` — extend with create/update/delete round-trip tests
- Modify: `pkg/api/testdata/openapi.json` — add every new verb + error-response schema
- Modify: `manifests/base/api/rbac.yaml` — grant `create, update, patch, delete` verbs on `filterpolicies.security.fos1.io` (Ticket 41 granted only `get, list, watch`)
- Modify: `docs/design/api-server.md` — describe CRUD semantics, validation error shape, content-type expectations (`application/json` for POST/PUT, `application/merge-patch+json` or `application/strategic-merge-patch+json` for PATCH)
- Modify: `Status.md` — API row from "read-only v0" to "CRUD v1 for FilterPolicy"

## Tasks

### Task 1: Handler Implementations

- [ ] `Create`: parse JSON body into `FilterPolicy`, validate, call `client.Create(ctx, &fp)`, return 201 with created object.
- [ ] `Replace` (PUT): reject if `metadata.resourceVersion` not set (require optimistic concurrency), parse body, validate, `client.Update`, return 200.
- [ ] `Patch`: support two content types:
  - `application/merge-patch+json` — JSON Merge Patch (RFC 7396)
  - `application/strategic-merge-patch+json` — Kubernetes strategic merge
  - reject unsupported content types with 415
- [ ] `Delete`: `client.Delete`, support `?propagationPolicy=Foreground|Background` query param, return 200.
- [ ] Every handler returns a Kubernetes-style `Status` envelope for errors (400/403/404/409/422/500).

### Task 2: Validation

- [ ] `pkg/api/validation.go`:
  - `ValidateFilterPolicy(fp *FilterPolicy) field.ErrorList`
  - reject empty selectors, unknown action types, conflicting ports, unreachable selector combos
  - reuse any validation helpers already in `pkg/security/policy/` — don't duplicate
- [ ] Handler converts `field.ErrorList` into a Kubernetes-style `Status` with `reason: Invalid` and HTTP 422.

### Task 3: Auth + Audit

- [ ] Every write verb passes through the Ticket 41 Subject-CN allowlist check; unauthorized subjects get 403 with CN echoed.
- [ ] Log every write at info level with: timestamp, subject CN, verb, resource, namespace, name, result code. Output matches Kubernetes audit log shape loosely for future audit-sink integration.

### Task 4: RBAC Update

- [ ] `manifests/base/api/rbac.yaml`:
  ```yaml
  - apiGroups: ["security.fos1.io"]
    resources: ["filterpolicies"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  ```
- [ ] Re-run `scripts/ci/prove-no-cluster-admin.sh` — should still be clean.

### Task 5: Tests + Docs

- [ ] Extend `pkg/api/filterpolicy_handler_test.go`:
  - `TestMTLSEndToEnd_Create` — 201 on valid body, 422 on invalid
  - `TestMTLSEndToEnd_UpdateWithConflict` — 409 when `resourceVersion` stale
  - `TestMTLSEndToEnd_DeleteForeground` — 200 + finalizer behavior
- [ ] OpenAPI spec covers every verb.
- [ ] `docs/design/api-server.md` gains a §CRUD Contract section.

## Verification

- [ ] `make verify-mainline` green
- [ ] `go test ./pkg/api/...` passes with new round-trip tests
- [ ] OpenAPI spec validates via `swagger-cli` or equivalent

## Out Of Scope

- Watch / streaming endpoints (Sprint 32 candidate)
- Other resource families (NAT, routing, DPI) — follow-ups
- Server-Side Apply
- OIDC / JWT auth — mTLS + CN allowlist remains the model

## Suggested Branch

`sprint-31/ticket-48-rest-api-write-path`
