# fos1 REST Management API (v0)

## Status

- **Version:** v0 (read-only)
- **Stability:** alpha. The wire shape may change between minor releases until
  v1. Do not build production automations against it without pinning the
  server image.
- **Source of truth:** [`pkg/api`](../../pkg/api) and
  [`cmd/api-server`](../../cmd/api-server).

## Goals

- Expose one resource family — `FilterPolicy` — over HTTPS with mTLS client-
  certificate authentication.
- Ship the three endpoints operators need to build first-class tooling:
  `/v1/filter-policies` (list), `/v1/filter-policies/{namespace}/{name}` (get),
  `/openapi.json` (schema), plus `/healthz` and `/readyz`.
- Reuse the existing controller-runtime informer cache where possible so the
  API does not add a second copy of every CR to memory.

## Non-goals (v0)

- Write operations: `POST`, `PUT`, `PATCH`, and `DELETE` are deliberately
  absent. Enabling them requires a follow-up ticket with RBAC review.
- Watch / streaming / long-polled list endpoints.
- Additional resource families (NAT, routing, DPI, zones): each lands in its
  own ticket.
- OAuth / OIDC / token authentication. mTLS is the single auth model for v0.

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

1. Write operations (POST/PUT/PATCH/DELETE) under the existing RBAC contract.
2. Additional resource families: NAT, routing, zones, DPI.
3. Watch / streaming: server-sent events or chunked JSON streams.
4. Richer auth: SPIFFE ID, service-account JWT, OIDC.
5. Multi-replica with leader election for controller-backed validations.
6. Live allowlist reload via fsnotify.
