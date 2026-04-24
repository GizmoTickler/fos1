# Sprint 31 / Ticket 49: Inter-Controller TLS And Secrets Management Baseline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Every owned controller exposes its HTTP endpoints over TLS. cert-manager-issued server certs rotate with a SecretWatcher-triggered reload. Secrets model is documented.

**Architecture:** One `ClusterIssuer` named `fos1-internal-ca` mints per-controller `Certificate` objects. Each controller mounts a Secret containing `tls.crt` + `tls.key` + `ca.crt` and loads them at startup; SecretWatcher (from Sprint 29 Ticket 15's NTS consumer pattern) triggers graceful reload on renewal.

**Tech Stack:** Go, cert-manager, Kubernetes Secrets, `crypto/tls`.

**Prerequisite:** Ticket 47 merged first (leader election adds controller-main touch points).

---

## File Map

- Create: `pkg/security/certificates/internal_ca.go` — helper to construct `fos1-internal-ca` ClusterIssuer manifest
- Modify: `pkg/security/certificates/watcher.go` (already exists from Ticket 15) — extend to a generic `WatchMultiple` for controllers that load multiple secrets
- Modify every controller `main.go` — load server cert from mount path, install SecretWatcher, reload `tls.Config` on renewal
- Create: `manifests/base/certificates/cluster-issuer-internal.yaml` — the `fos1-internal-ca` ClusterIssuer (self-signed root, valid 10y) plus a `Certificate` for the root CA
- Create/modify: `manifests/base/*/certificate.yaml` — per-controller Certificate referencing `fos1-internal-ca`, dnsNames `<svc>.<ns>.svc`
- Modify: `manifests/base/*/deployment.yaml` — mount the TLS Secret at `/var/run/secrets/fos1.io/tls/`
- Create: `docs/design/internal-tls-secrets.md` — trust anchor, rotation, compromise response
- Modify: `docs/design/implementation_caveats.md` — close "internal TLS missing" caveat; document rotation + kill-switch model
- Modify: `Status.md` — §Security Posture gets new row: "Internal TLS via fos1-internal-ca with cert-manager rotation"

## Tasks

### Task 1: ClusterIssuer + Root CA

- [ ] `manifests/base/certificates/cluster-issuer-internal.yaml`:
  - self-signed `ClusterIssuer` named `fos1-internal-ca-root`
  - `Certificate` for the root CA (10y validity, key size 4096, usages `[digital signature, key encipherment, cert sign, crl sign]`)
  - second `ClusterIssuer` named `fos1-internal-ca` that uses the root CA as its `caRef`
- [ ] Include in the base kustomization; ensure it renders before any controller Certificate.

### Task 2: Per-Controller Certificates

- [ ] For each controller that exposes HTTP (API server, dpi-manager, ntp-controller, threatintel-controller, correlator, ...), create:
  ```yaml
  apiVersion: cert-manager.io/v1
  kind: Certificate
  metadata:
    name: <controller>-tls
    namespace: <ns>
  spec:
    secretName: <controller>-tls
    dnsNames:
      - <controller>.<ns>.svc
      - <controller>.<ns>.svc.cluster.local
    issuerRef:
      kind: ClusterIssuer
      name: fos1-internal-ca
    duration: 2160h    # 90d
    renewBefore: 360h  # 15d
  ```

### Task 3: Controller TLS Loading + Reload

- [ ] Extract a `pkg/security/certificates/tlsconfig.go` helper:
  ```go
  func LoadTLSConfig(certDir string) (*tls.Config, error)
  func WatchAndReload(ctx context.Context, certDir string, onReload func(*tls.Config)) error
  ```
- [ ] Every controller main wires this into its HTTP server bootstrap.
- [ ] API server (Ticket 41) migrates from its current mTLS scaffold to the shared helper without behavior change.

### Task 4: Rotation Proof

- [ ] New script `scripts/ci/prove-cert-rotation.sh`:
  - force-renew a Certificate via `cmctl renew <cert>`
  - assert the controller pod's `/healthz` stays 200 during rotation (no restart)
  - assert the pod's served cert NotBefore advanced
- [ ] Wire into `.github/workflows/test-bootstrap.yml`.

### Task 5: Docs + Status

- [ ] `docs/design/internal-tls-secrets.md`:
  - trust anchor: `fos1-internal-ca` ClusterIssuer chained from a 10y self-signed root
  - per-controller server cert: 90d validity, renewed at 15d remaining
  - secrets model: `tls.crt`/`tls.key`/`ca.crt` in a Kubernetes Secret, mounted read-only at `/var/run/secrets/fos1.io/tls/`
  - compromise response: delete the Secret + cert-manager re-issues on the next reconcile; rotate the root CA by generating a new one and updating the ClusterIssuer `caRef`
- [ ] `Status.md` + `docs/project-tracker.md`: mirror.

## Verification

- [ ] `make verify-mainline` green
- [ ] `kubeconform` validates new Certificate and ClusterIssuer manifests
- [ ] Rotation proof passes in Kind
- [ ] Every owned controller's HTTP listener is TLS-only after this ticket

## Out Of Scope

- mTLS for controller-to-controller (this ticket is server TLS; clients remain the existing Kubernetes API clients which use their own kubelet TLS)
- External-daemon TLS (FRR, Suricata, Kea) — Sprint 32
- HSM / KMS integration
- SPIFFE / SPIRE

## Suggested Branch

`sprint-31/ticket-49-internal-tls-secrets`
