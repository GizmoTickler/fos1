# Sprint 32 — mTLS Mesh + External-Daemon TLS (In Progress)

**Window:** TBD
**State:** In progress (Tickets 56-57 implemented locally)
**Production-readiness target:** ~82–87% → ~85–90%

## Goal

Sprint 31 introduced internal TLS via the `fos1-internal-ca` ClusterIssuer for owned controllers, but only the API server enforced client certs. Tickets 56-57 have started the Sprint 32 closeout by moving the shared TLS helper and currently-owned HTTP listeners to mutual TLS with deny-by-default Subject-CN allowlists, then rekeying Prometheus with a client certificate so owned metrics scrapes can pass through that mTLS baseline. External daemons (FRR, Suricata, Kea, Zeek, chrony) are still reached over plaintext loopback sockets until Tickets 58-62 land.

## Baseline

Main HEAD when this sprint opens: TBD (`34de009` at planning time). `make verify-mainline` 43/43 packages pass.

## Proposed tickets (56–64)

| # | Theme | Key deliverable | Priority |
|---|---|---|---|
| 56 | mTLS controller-to-controller mesh | In progress. `pkg/security/certificates.LoadMutualTLSConfig` now reuses the Ticket 49 SecretWatcher material for server certs, client certs, RootCAs, ClientCAs, and rotation. Non-API owned listeners wrap handlers with Subject-CN allowlists, and `scripts/ci/prove-mtls-mesh.sh` proves valid cert / no cert / unknown CN behavior | P0 |
| 57 | Prometheus rekey for fos1-internal-ca | Implemented locally. `prometheus-client-tls` gives Prometheus Subject CN `prometheus`; dedicated DPI/NTP pod-SD jobs trust `fos1-internal-ca`, present the client cert, and verify each target with its service DNS name. The Kind proof still asserts ready pod counts map to healthy `up=1` samples | P0 |
| 58 | FRR vtysh-over-TLS or sidecar TLS terminator | Today the FRR client opens vtysh on a plaintext UNIX socket. Either land FRR's native TLS support if available, or front the daemon with a stunnel/sidecar TLS terminator. Document the choice in an ADR | P1 |
| 59 | Suricata Unix socket auth + TLS over TCP fallback | Per-instance shared-secret auth on the Suricata socket; TLS on the TCP variant for off-node controllers. Sprint 31 Ticket 49 SecretWatcher pattern | P1 |
| 60 | Kea control-channel TLS | Kea supports HTTPS on the control channel — wire the DHCP controller to the TLS variant with cert-manager-issued certs | P1 |
| 61 | Zeek Broker TLS | Zeek Broker supports TLS — wire the IDS controller's broker client to the TLS variant. Document fallback behavior on broker version mismatch | P1 |
| 62 | chrony chronyc-over-Unix authenticated mode | `chronyc` Unix socket has command authentication via `cmdallow` + key file. Wire the NTP controller through the authenticated path | P2 |
| 63 | Leader-transition metrics export | Add `leader_transitions_total{controller="<name>"}` to `pkg/leaderelection`. Update dashboards/alerts. Closes the Ticket 47 caveat | P2 |
| 64 | Post-sprint truth-up | Same pattern as Tickets 37, 46, 55. Recompute production readiness and effort-to-production. Open Sprint 33 placeholder | P2 |

## Acceptance theme

After Sprint 32, no owned listener and no controller-to-daemon call carries cleartext credentials over the wire. The trust anchor for everything in-cluster is `fos1-internal-ca`. The trust anchor for daemons stays per-daemon (each emits its own cert via cert-manager), but every cert chains to `fos1-internal-ca`.

## Critical path (draft)

`56 → 57 → (58, 59, 60, 61, 62 in parallel) → 63 → 64`

## Out of scope

- Replacing `fos1-internal-ca` self-signed root with an enterprise PKI / KMS-backed signer — operator overlay concern, not platform code
- SPIFFE / SPIRE — too deep an architectural change without an ADR
- mTLS for Kubernetes API access — that is governed by kubelet, kube-proxy, and the cluster's existing cert chains, not `fos1-internal-ca`
