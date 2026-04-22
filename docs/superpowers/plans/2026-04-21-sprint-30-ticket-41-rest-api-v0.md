# Sprint 30 / Ticket 41: Read-Only REST Management API (v0)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Expose one resource family read-only (`/v1/filter-policies`) over HTTPS with mTLS client-cert auth. Backed by the existing controller's informer cache. Ship `/healthz`, `/readyz`, `/openapi.json`. v0 is read-only; write paths explicitly deferred.

**Architecture:** New `cmd/api-server/` binary. Uses `net/http` + `sigs.k8s.io/controller-runtime` caching client (shared cache with main controller for efficiency). mTLS via cert-manager-issued CA already used for internal TLS.

**Tech Stack:** Go `net/http`, `sigs.k8s.io/controller-runtime`, `crypto/tls`, cert-manager.

**Independence:** Can run in parallel to other Sprint 30 tickets; only touches new files + one manifest tree.

---

## Context

- **Status.md** §Critical Gaps lists "No REST API exposed" as a production blocker.
- Cert-manager is already integrated (`pkg/security/certificates/`). CA bundle exists for internal TLS.
- Existing informer cache logic is in `pkg/controllers/`. Share it via controller-runtime manager.

---

## File Map

- Create: `cmd/api-server/main.go` — binary entrypoint; starts TLS server, registers handlers.
- Create: `pkg/api/`:
  - `server.go` — `type Server struct { Client client.Client; ... }` with `Run(ctx)`
  - `filterpolicy_handler.go` — `GET /v1/filter-policies` (list), `GET /v1/filter-policies/{ns}/{name}` (get)
  - `healthz_handler.go`, `readyz_handler.go`
  - `openapi.go` — serves `openapi.json` generated from a static spec file
  - `auth.go` — mTLS client-cert extraction + subject allowlist
- Create: `pkg/api/testdata/openapi.json` — minimal spec for v0 endpoints
- Create: `pkg/api/server_test.go`, `filterpolicy_handler_test.go`, `auth_test.go`
- Create: `manifests/base/api/`:
  - `deployment.yaml` — single-replica Deployment
  - `service.yaml` — ClusterIP :8443
  - `certificate.yaml` — cert-manager Certificate for server identity
  - `rbac.yaml` — ClusterRole granting `get,list,watch` on FilterPolicy only
  - `kustomization.yaml`
- Create: `manifests/examples/api/` — example client cert + curl invocation
- Create: `docs/design/api-server.md` — architecture, auth model, versioning, write-paths deferred
- Modify: `Status.md` — new row: "REST API v0 (read-only FilterPolicy) — Complete"

---

## Task 1: Server Scaffold And Handlers

- [ ] `pkg/api/server.go`: struct holding client, TLS config, logger; `Run(ctx)` binds mTLS listener.
- [ ] `filterpolicy_handler.go`: list paginated by continue-token; get returns 404 on missing, 403 on unauthorized subject.
- [ ] JSON responses follow Kubernetes API List/Item shapes but simplified — do NOT claim to be a full apiserver.
- [ ] `healthz_handler.go` returns 200 always; `readyz_handler.go` checks cache sync.

## Task 2: mTLS Auth

- [ ] Configure `tls.Config` with `ClientAuth: tls.RequireAndVerifyClientCert` and a CA pool loaded from a Secret or file path.
- [ ] Extract client subject CN; compare against an allowlist from a ConfigMap or env var.
- [ ] Unauthorized subjects return 403 with a machine-readable body.

## Task 3: OpenAPI And Docs

- [ ] Write static `openapi.json` covering the 4 endpoints (`GET /v1/filter-policies`, `GET /v1/filter-policies/{ns}/{name}`, `/healthz`, `/readyz`).
- [ ] `docs/design/api-server.md`: architecture, how to authenticate, how to list, what's deferred (write, watch, other resources).

## Task 4: Manifests

- [ ] Deployment, Service, Certificate, RBAC, Kustomization under `manifests/base/api/`.
- [ ] Example client-cert generation flow in `manifests/examples/api/`.

## Task 5: Tests

- [ ] Handler unit tests with fake client.
- [ ] Auth test: unauthorized subject returns 403; authorized subject passes.
- [ ] Optional integration test in `test/integration/` using envtest.

---

## Verification

- [ ] `make verify-mainline` green
- [ ] `go test ./pkg/api/... ./cmd/api-server/...` passes
- [ ] mTLS handshake rejects unauthorized subjects; authorized subjects can list/get
- [ ] `kubeconform` validates new manifests

## Out Of Scope

- Write operations (POST/PUT/PATCH/DELETE) — explicit non-goal for v0
- Watch endpoints / streaming
- Other resource families (NAT, routing, DPI) — follow-ups
- OAuth/OIDC auth — mTLS only for v0

## Suggested Branch

`sprint-30/ticket-41-rest-api-v0`
