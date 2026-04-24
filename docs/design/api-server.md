# fos1 REST Management API

## Status

- **Version:** v1 for FilterPolicy (Sprint 31 Ticket 48 added CRUD;
  Sprint 30 Ticket 41 shipped read-only v0).
- **Stability:** alpha. The wire shape may change between minor releases until
  v1 is frozen across every resource family. Do not build production
  automations against it without pinning the server image.
- **Source of truth:** [`pkg/api`](../../pkg/api) and
  [`cmd/api-server`](../../cmd/api-server).

## Goals

- Expose one resource family — `FilterPolicy` — over HTTPS with mTLS client-
  certificate authentication.
- Provide the full CRUD surface: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`,
  plus `/healthz`, `/readyz`, and `/openapi.json`.
- Reuse the existing controller-runtime informer cache where possible so the
  API does not add a second copy of every CR to memory.

## Non-goals

- Watch / streaming / long-polled list endpoints (Sprint 32 candidate).
- Additional resource families (NAT, routing, DPI, zones): each lands in its
  own ticket.
- Server-Side Apply (`application/apply-patch+yaml`) and JSON Patch
  (`application/json-patch+json`): deferred.
- OAuth / OIDC / token authentication. mTLS remains the single auth model.

## Architecture

```
 ┌──────────────────────┐       mTLS (TLS 1.2+)        ┌─────────────────────┐
 │ operator / CLI / CI  ├──────────────────────────────▶│ fos1-api-server     │
 │ (has client cert)    │     SAN: fos1-api-server.    │ Deployment (1 rep.) │
 └──────────────────────┘     security.svc          │                     │
                                                       │  net/http mux       │
                                                       │   ├── /v1/filter-…  │
                                                       │   ├── /healthz      │
                                                       │   ├── /readyz       │
                                                       │   └── /openapi.json │
                                                       │                     │
                                                       │  controller-runtime │
                                                       │  manager.GetClient()│
                                                       │         │           │
                                                       └─────────┼───────────┘
                                                                 │ informer
                                                                 ▼
                                                       ┌─────────────────────┐
                                                       │ kube-apiserver      │
                                                       │ FilterPolicy CRD    │
                                                       └─────────────────────┘
```

### Process model

The binary is a single-replica `Deployment`. It is acceptable to lose the
replica during a rollout because every endpoint is read-only — callers retry
with backoff and the controller-runtime cache rebuilds from the apiserver on
restart. A multi-replica rollout is viable once leader election is added; v0
intentionally defers that complexity.

### Shared cache

`ctrl.NewManager` constructs a cached client. The manager is started in a
goroutine and `mgr.GetCache().WaitForCacheSync` is invoked once at startup so
first-request latency is bounded. While the cache is syncing, `/readyz`
returns 503 so kube-proxy keeps traffic away.

## Authentication: mTLS

- `tls.Config.ClientAuth = tls.RequireAndVerifyClientCert`.
- `tls.Config.ClientCAs` is a `x509.CertPool` loaded from a PEM bundle on
  disk (`--client-ca`). The bundle is the **trust anchor**: a client whose
  certificate chain does not terminate in it is rejected at the TLS layer
  before any handler runs.
- Server identity is issued by cert-manager (`manifests/base/api/certificate.yaml`).
  The default `Issuer` in this repo is a placeholder — production
  overlays should swap it for a `ClusterIssuer` that chains to the cluster-
  wide CA.

### Caveat: trust anchor model

The trust anchor controls **who can authenticate**; the allowlist controls
**who can do anything**. These are distinct knobs:

| Knob                          | Purpose                                      | Failure mode when misconfigured         |
| ----------------------------- | -------------------------------------------- | --------------------------------------- |
| `ClientCAs`                   | Reject handshakes from unknown CAs.          | Over-scoped CA → any holder of a cert signed by it can open TCP and hit `/healthz`/`/readyz`/`/openapi.json`. |
| `--allowlist` / allowlist CM  | Reject data-plane calls from untrusted CNs. | Misspelled CN → legitimate client sees 403. |

The public routes (`/healthz`, `/readyz`, `/openapi.json`) skip the
allowlist by design so probes and schema discovery can succeed even when the
allowlist is empty. Dataplane routes (`/v1/filter-policies*`) always consult
the allowlist.

## Authorization: subject allowlist

- Inputs: a `ConfigMap` mounted as a file (`--allowlist-file`) or a comma-
  separated string (`--allowlist`). File wins when both are set.
- Format: one Subject CN per line, UTF-8. Lines starting with `#` and blank
  lines are ignored.
- Caveat: the allowlist is **parsed once at startup**. Live reload on file
  change is not implemented in v0. Operators must roll the Deployment to
  reload.

### Why CN-only?

SANs, URIs, and custom OIDs carry more structure than CNs, but v0 picks CN
because cert-manager templates default to `commonName` and operators are
already comfortable setting it per-workload. Richer subject matching lands in
a follow-up that addresses service-account chaining and SPIFFE IDs.

## Wire format

Responses are JSON. Both list and get shapes mirror the Kubernetes API but
are **not** intended to be consumed by `kubectl`. Clients should use the
OpenAPI document at `/openapi.json` to generate bindings.

### `GET /v1/filter-policies`

Query parameters:

| Name       | Shape  | Default | Purpose                                           |
| ---------- | ------ | ------- | ------------------------------------------------- |
| `namespace`| string | all     | Restrict to a single namespace.                   |
| `limit`    | int    | 100     | Page size (server caps at 500).                   |
| `continue` | string | —       | Opaque token from a prior response.               |

Response body:

```json
{
  "apiVersion": "fos1.io/v1",
  "kind": "FilterPolicyList",
  "metadata": { "resourceVersion": "1234", "continue": "" },
  "items": [ { "kind": "FilterPolicy", ... } ]
}
```

### `GET /v1/filter-policies/{namespace}/{name}`

Returns the `FilterPolicy` object or 404 with a `Status` envelope.

### `Status` envelope (all error responses)

```json
{
  "kind": "Status",
  "status": "Failure",
  "code": 403,
  "reason": "Forbidden",
  "message": "subject not in allowlist",
  "subject": "example-operator"
}
```

The `subject` field is only present for 403 responses so clients can log
which identity was denied.

## CRUD Contract

Sprint 31 Ticket 48 added the write verbs. The contract below documents
the expected headers, bodies, and status codes across the full surface.

### Routes

| Method   | Path                                             | Purpose               |
| -------- | ------------------------------------------------ | --------------------- |
| `GET`    | `/v1/filter-policies`                            | List                  |
| `POST`   | `/v1/filter-policies`                            | Create                |
| `GET`    | `/v1/filter-policies/{namespace}/{name}`         | Get                   |
| `PUT`    | `/v1/filter-policies/{namespace}/{name}`         | Replace               |
| `PATCH`  | `/v1/filter-policies/{namespace}/{name}`         | Patch (merge variants)|
| `DELETE` | `/v1/filter-policies/{namespace}/{name}`         | Delete                |

### Content types

| Verb     | Accepted `Content-Type`                                                                   |
| -------- | ----------------------------------------------------------------------------------------- |
| `POST`   | `application/json`                                                                        |
| `PUT`    | `application/json`                                                                        |
| `PATCH`  | `application/merge-patch+json` **or** `application/strategic-merge-patch+json`            |
| `DELETE` | (no body)                                                                                 |

`application/json-patch+json` (RFC 6902) is **not** supported and returns
415 with an `Accept-Patch` header advertising the two accepted types.
`application/apply-patch+yaml` (Server-Side Apply) is deferred.

### Validation

Every write verb runs `api.ValidateFilterPolicy` before contacting the
apiserver. The rules are intentionally conservative — they reject
unambiguously malformed specs but tolerate selector shapes the translator
would silently ignore:

- `spec.scope` must be one of `zone`, `namespace`, `cluster`,
  `interface`, `global`.
- `spec.priority` must be non-negative.
- `spec.actions` must be non-empty and every `type` must be one of
  `allow`, `accept`, `deny`, `drop`, `reject`, or `log`.
- `spec.selectors` must populate at least one of `sources`,
  `destinations`, `applications`, or `ports` (an empty-selector policy
  applying to every flow is almost always an authoring mistake — operators
  who really want match-all should set `scope: global`).
- Every `PortSelector.Protocol` must be `tcp`, `udp`, `icmp`, `any`, or
  empty; every port must be in `1..65535`.

Validation failures produce HTTP 422 with `reason: Invalid` and a
`details.causes` array carrying one entry per field-level error:

```json
{
  "kind": "Status",
  "status": "Failure",
  "code": 422,
  "reason": "Invalid",
  "message": "FilterPolicy spec is invalid: ...",
  "details": {
    "group": "security.fos1.io",
    "kind": "FilterPolicy",
    "causes": [
      { "reason": "FieldValueRequired", "message": "...", "field": "spec.actions" },
      { "reason": "FieldValueNotSupported", "message": "...", "field": "spec.scope" }
    ]
  }
}
```

### Optimistic concurrency (PUT vs. PATCH)

- **`PUT` requires `metadata.resourceVersion`.** A body without it is a
  **400** (client authoring error), not a 409. Callers are expected to
  GET the object first, mutate the returned body, and PUT it back. The
  apiserver returns 409 if the supplied resourceVersion is stale.
- **`PATCH` does not require `metadata.resourceVersion`.** Callers who
  want strict optimistic concurrency can include it in the patch body —
  the merged object is then forwarded to the apiserver, which will 409 on
  a stale version. Operators who are comfortable with last-write-wins can
  omit it.
- **`POST` must NOT include `metadata.resourceVersion`.** A body that
  pre-populates it is a 400.

Rationale: PATCH is meant to let callers evolve a field without the
GET-then-PUT dance; making resourceVersion mandatory on PATCH would
defeat that purpose. PUT, by contrast, is a full replace — the caller
has all of the spec, so they should also hold the resourceVersion.

### Strategic vs. JSON Merge Patch dispatch

The FilterPolicy Go type carries **no `patchStrategy` struct tags**, so
strategic merge patch has no extra information beyond plain JSON merge
patch and collapses to list-replacement semantics. The handler still
routes strategic merge patches through
`k8s.io/apimachinery/pkg/util/strategicpatch` so that directives like
`$patch: replace` work as documented, and so that once we add struct tags
the existing callers keep working unchanged.

Practical guidance:

- For simple mutations (rename a field, flip a boolean), either content
  type gives identical results.
- For list edits, prefer `application/merge-patch+json` and send the
  full desired list (the current behaviour under either content type).
- `application/strategic-merge-patch+json` is accepted for forward
  compatibility. When FilterPolicy gains patch-strategy tags in a later
  ticket, callers already on this content type benefit without change.

### Delete semantics

`DELETE /v1/filter-policies/{namespace}/{name}?propagationPolicy=...`
accepts `Foreground`, `Background`, and `Orphan`. The query parameter is
optional; when omitted the server delegates to the controller-runtime
default (Background). Any other value is a 400.

Successful deletions return a `Status` envelope with `status: Success`
and `code: 200`. When the target resource has finalizers, deletion is
accepted but not immediate — operators should re-GET to observe the
actual lifecycle state.

### Audit logging

Every write verb logs a structured line via klog at info level:

```
"api write" subject="operator-foo" verb="create" \
    resource="filterpolicies.security.fos1.io" \
    namespace="security" name="block-ssh" \
    code=201 durationMs=7
```

The shape is intentionally close to a Kubernetes audit event so a later
audit-sink integration can relay the same line to Elasticsearch / Loki
without a translator. The `subject` field is the mTLS client-cert
Common Name extracted by the auth middleware.

### RBAC

`manifests/base/api/rbac.yaml` grants the ServiceAccount
`security/fos1-api-server` the following on
`filterpolicies.security.fos1.io`:

```
verbs: [get, list, watch, create, update, patch, delete]
```

Ticket 41 granted only read verbs; Ticket 48 added the writes. No other
resource family is granted — the scope check at
`scripts/ci/prove-no-cluster-admin.sh` stays clean.

## Operations

### Deploy

```
kubectl apply -k manifests/base/api
kubectl -n security patch configmap fos1-api-server-allowlist \
  --type merge -p '{"data":{"allowlist":"example-operator\n"}}'
kubectl -n security rollout restart deployment fos1-api-server
```

### Issue a client cert

See [manifests/examples/api/client-certificate.yaml](../../manifests/examples/api/client-certificate.yaml).

### curl a live server

```
curl --cacert ca.crt --cert client.crt --key client.key \
     https://fos1-api-server.security.svc.cluster.local:8443/v1/filter-policies
```

## Deferred work

1. ~~Write operations (POST/PUT/PATCH/DELETE)~~ — shipped in Sprint 31 Ticket 48
   for FilterPolicy.
2. Additional resource families: NAT, routing, zones, DPI.
3. Watch / streaming: server-sent events or chunked JSON streams.
4. Server-Side Apply (`application/apply-patch+yaml`) and RFC 6902 JSON Patch
   (`application/json-patch+json`) content types on the PATCH endpoint.
5. Richer auth: SPIFFE ID, service-account JWT, OIDC.
6. Multi-replica with leader election for controller-backed validations.
7. Live allowlist reload via fsnotify.
