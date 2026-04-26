# Inter-Controller TLS And Secrets Management Baseline

> Sprint 31 / Ticket 49 design.
> Status: implemented.
> Owners: security, platform.

## Goal

Every owned fos1 controller exposes its HTTP endpoints over TLS, served from
a per-controller server certificate minted by an in-cluster CA. Renewals
happen with cert-manager rotation; the controller swaps its in-memory
certificate via fsnotify on the mount path, with no pod restart and no
listener bounce.

This is the baseline. mTLS for controller-to-controller calls and TLS for
external daemons (FRR, Suricata, Kea) are explicit follow-ups (see
[Out Of Scope](#out-of-scope)).

## Trust anchor

The PKI is two-tier:

```
fos1-internal-ca-root  (selfSigned ClusterIssuer)
      |
      +-- Certificate fos1-internal-ca-root  (10y, RSA-4096, isCA=true)
                  |
                  v
            Secret cert-manager/fos1-internal-ca-root
                  ^
                  |  caRef
            ClusterIssuer fos1-internal-ca   (CA-typed)
                  |
                  v
            per-controller Certificates  (90d / renew 15d, ECDSA-P256)
                  |
                  v
            Secret <controller>-tls   (kubernetes.io/tls)
```

Both `ClusterIssuer` objects and the root `Certificate` live in
`manifests/base/certificates/cluster-issuer-internal.yaml`. They are listed
first in `manifests/base/kustomization.yaml` so the chain exists before any
consumer reconciles.

The split between the self-signed root and the day-to-day CA is deliberate:

- The root key sits in a single Secret in the `cert-manager` namespace and
  is rotated only by an explicit operator action (see
  [Rotation](#rotation)).
- The CA-typed `fos1-internal-ca` issuer reads the root Secret and signs
  every per-controller leaf cert. It can be re-pointed at a new root
  without invalidating in-flight controller certs.

## Per-controller certificates

Each controller's manifest tree carries its own `Certificate` object, named
`<controller>-tls`, in the controller's namespace. Common spec:

| Field | Value |
|---|---|
| `duration` | `2160h` (90d) |
| `renewBefore` | `360h` (15d) |
| `privateKey.algorithm` | `ECDSA` |
| `privateKey.size` | `256` |
| `privateKey.rotationPolicy` | `Always` |
| `usages` | `server auth`, `digital signature`, `key encipherment` |
| `dnsNames` | `<svc>.<ns>.svc`, `<svc>.<ns>.svc.cluster.local` |
| `issuerRef` | `fos1-internal-ca` ClusterIssuer |

ECDSA P-256 is the default because handshakes are cheap (every Prometheus
scrape, every kubelet probe) and no controller has a reason for RSA today.
Overlays can override to RSA via a kustomize patch.

## Secrets model

cert-manager writes each controller cert into a `kubernetes.io/tls`
Secret. The Secret carries three keys:

| Key | Content |
|---|---|
| `tls.crt` | PEM-encoded server certificate chain |
| `tls.key` | PEM-encoded private key |
| `ca.crt` | PEM-encoded CA bundle (the `fos1-internal-ca` chain) |

Every owned Deployment mounts the Secret at `/var/run/secrets/fos1.io/tls/`
read-only. The path is hard-coded in `pkg/security/certificates`
(`DefaultTLSMountPath`); manifests reference the same constant by string.

```yaml
volumes:
  - name: tls
    secret:
      secretName: <controller>-tls
      optional: true   # tolerate first-boot before cert-manager reconciles
volumeMounts:
  - name: tls
    mountPath: /var/run/secrets/fos1.io/tls
    readOnly: true
```

`optional: true` lets the pod start before cert-manager has signed the
cert; kubelet picks up the mount lazily once the Secret exists, which the
TLS reloader detects.

## Loading + reloading at runtime

The shared loader lives in `pkg/security/certificates/tlsconfig.go`:

```go
cfg, reloader, err := certificates.LoadTLSConfig(certDir)
// install cfg on the http.Server
go reloader.WatchAndReload(ctx, onReload, cfg, errCh)
```

`LoadTLSConfig` returns a `*tls.Config` that:

- Sets `MinVersion = TLS 1.2`. Older versions are not negotiated.
- Wires `GetCertificate` so the active cert pointer is read under an
  `RLock` on every handshake. A reload swaps the pointer atomically; an
  in-flight handshake either sees the old or the new cert, never a torn
  view.

`WatchAndReload` watches the mount directory with `fsnotify`. kubelet's
Secret rollover replaces the `..data` symlink atomically; the directory
rename event always fires, even though individual file watches do not.
Multiple events fire within milliseconds during a rollover; a 100ms
debounce coalesces them to a single reload.

If `fsnotify` cannot be initialized (inotify watch limit, FS that does not
support it), the watcher falls back to polling at 30s cadence. Renewals
happen 15 days before expiry on a 90 day cert, so even a 30s polling delay
is far inside the safety margin.

## Controllers wired up by this ticket

| Controller | Cert object | Mount | TLS now? |
|---|---|---|---|
| `fos1-api-server` (security/api) | `fos1-api-server-tls` | yes | yes (mTLS) |
| `dpi-manager` | `dpi-manager-tls` | yes | yes |
| `ntp-controller` | `ntp-controller-tls` | yes | yes |
| `event-correlator` | (per-instance via `EventCorrelation`) | optional | flag-gated |
| `ids-controller` | `ids-controller-tls` | yes | mounted, listener pending |
| `threatintel-controller` | `threatintel-controller-tls` | yes | mounted, listener pending |
| `wireguard-controller` | `wireguard-controller-tls` | future | mounted, listener pending |
| `certificate-controller` | `certificate-controller-tls` | future | mounted, listener pending |

For controllers in the "mounted, listener pending" row, the Secret is in
place so the TLS adoption commit can flip a single flag without a
manifests churn.

## Rotation

### Routine renewal

cert-manager issues a new leaf 15 days before expiry. The new key + cert
land in the same Secret; kubelet mirrors the change into the pod's mount
within seconds; the controller's fsnotify watcher reloads the in-memory
cert. No restart, no listener bounce, no externally-visible blip.

Tested by `scripts/ci/prove-cert-rotation.sh`: force a renewal via
`cmctl renew`, then assert the controller's `/healthz` stays 200 and the
served cert's `NotBefore` advances.

### Compromise response

If a leaf cert is compromised:

1. Delete the Secret backing the Certificate:
   ```
   kubectl delete secret <controller>-tls -n <ns>
   ```
2. cert-manager re-issues on the next reconcile (typically <30s).
3. The controller picks up the new material via fsnotify.

Because the leaf key is fresh on every issuance (`rotationPolicy: Always`
on the Certificate), the compromised key is no longer accepted by anyone
who trusts only the new chain — but anyone who already trusts
`fos1-internal-ca` will still trust the new leaf. To shorten the
revocation window to zero, rotate the root.

### Root rotation

If the root CA itself is compromised, every leaf signed by the
intermediate is implicitly revoked when the root is replaced. The path:

1. Provision a new root: bump the secret name in the
   `fos1-internal-ca-root` Certificate spec, or rename it (e.g.
   `fos1-internal-ca-root-2026-04`).
2. Update `fos1-internal-ca`'s `spec.ca.secretName` to point at the new
   Secret.
3. `cmctl renew --all` to re-issue every leaf under the new root.
4. Distribute the new `ca.crt` to any external client (Prometheus,
   external monitoring, operator kubeconfigs) that pinned the old chain.

Step 4 is the painful one and is why the root has a 10y validity: routine
ops should never need to touch it.

## Observability

- Every TLS reload emits a structured klog line: `certificates: TLS
  material reloaded from /var/run/secrets/fos1.io/tls`.
- cert-manager exports `certmanager_certificate_expiration_timestamp_seconds`
  out of the box; an alert fires at 7 days remaining (placeholder — wire up
  in a follow-up ticket against `manifests/base/monitoring/alert-rules.yaml`).
- The rotation proof script in CI is the load-bearing regression catch.

## Out of scope

This ticket is explicitly limited to **server TLS for owned controllers**.
The following are deferred:

- **mTLS for controller-to-controller calls.** Controllers today reach
  the Kubernetes API via their service-account token; that path keeps
  using kubelet's TLS. Direct controller-to-controller HTTP calls do not
  exist in the codebase yet.
- **External-daemon TLS.** Suricata's Unix socket, Zeek Broker, Kea's
  control socket, FRR's vtysh, chronyc — these still speak plaintext on
  in-pod sockets. Sprint 32 will wrap each in a sidecar or pin a
  loopback-only listener.
- **HSM / KMS integration.** The CA key is a PEM file in a Kubernetes
  Secret. Production deployments that require HSM-backed signing should
  replace the `fos1-internal-ca-root` issuer with an external one (Vault,
  cloud KMS) via an overlay.
- **SPIFFE / SPIRE.** Workload identities remain Kubernetes
  ServiceAccount + cert subject CN. SPIFFE ID issuance and SVID rotation
  is a strategic decision, not a sprint commitment.
- **Cilium-mesh mTLS.** Cilium's own mTLS feature is independent of this
  PKI and remains a separate operational decision.
- **Egress / external-CA trust.** When a controller reaches an
  Internet-hosted endpoint (e.g. a MISP feed), it uses the OS root CA
  bundle. `fos1-internal-ca` is a private trust domain only.

## Testing

| Layer | Test |
|---|---|
| Unit | `pkg/security/certificates/tlsconfig_test.go` — load, reload, missing-file errors, poll fallback |
| Unit (mTLS layering) | existing `pkg/api` tests still pass with the migrated builder |
| Manifest | `kubeconform` covers the new ClusterIssuer + Certificate objects |
| CI | `scripts/ci/prove-cert-rotation.sh` runs in `test-bootstrap.yml` |
