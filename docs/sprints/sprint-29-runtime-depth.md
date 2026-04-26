# Sprint 29 — Runtime Depth + Post-Baseline Hardening

**Window:** 2026-04-21 → 2026-04-22
**State:** Complete
**Production readiness:** ~55% → ~60–65%
**Effort-to-production:** 6–10 months → 4–7 months

## Goal

Move the project from "the owned baseline exists" to "the owned baseline is exercised end-to-end" — and close out the advertised-but-unshipped surfaces (FilterPolicy enforcement, auth providers, NIC/capture reporting) that were inflating the apparent feature surface.

## Baseline

Main HEAD when the sprint opened: `805349e` (post-ops-sprint drift commit).

`make verify-mainline` was enforced in CI; the Kind harness already proved the DPI/NTP pod-annotation scrape path and a deterministic Suricata canary into Elasticsearch with `fos1-log-retention-14d` ILM/template attachment. Sprint 29 broadened that proof and closed the cleanup work that the ops sprint had left dangling.

## Tickets

| # | Theme | Key deliverable | Status | Commits |
|---|---|---|---|---|
| 29 | Event-correlator E2E proof | `scripts/ci/prove-event-correlation-e2e.sh` — canary → file source → correlator → file sink + `/ready` HTTP 200 | ✅ | feat `b06a45e`, merge `31b5140` |
| 30 | Elasticsearch ILM rollover + delete proof | `scripts/ci/prove-es-retention-rollover.sh` against the CI-only `fos1-ci-accelerated` policy | ✅ | feat `729300e`, merge `12d4d47` |
| 31 | Natural-traffic DPI proof | Suricata sid `9000001` → eve.json → Elasticsearch → Prometheus `sum(dpi_events_total)` advance | ✅ | feat `bb9b0cc`, merge `4c9895c` |
| 32 | Dashboard/alert PromQL validator | `tools/prometheus-query-validator/` runs in Kind, fails CI on non-allowlisted empty/error expressions | ✅ | merge `0929de8` |
| 33 | FilterPolicy → Cilium translator | `pkg/security/policy/controller.go` reconciles FilterPolicy → CiliumNetworkPolicy with spec-hash idempotency and Applied/Degraded/Invalid/Removed conditions. `FirewallRule` CRD, nftables-based translator/zone manager, and `pkg/security/firewall/` package removed per ADR-0001 | ✅ | feat `244128c`, merge `9ad19b7` |
| 34 | Auth surface finalization | SAML / RADIUS / certificate auth provider stubs removed from manager factory, CRD enum, manifests, docs. Auth scoped to local/LDAP/OAuth | ✅ | feat `ac4f32e`, merge `92088b8` |
| 35 | NIC + capture capability reporting | Real ethtool/tcpdump on Linux; explicit `ErrNICStatisticsNotSupported`, `ErrTCPDumpNotAvailable`, `ErrNICUnsupportedPlatform` sentinels off-Linux. eBPF-based capture marked non-goal | ✅ | feat `497f286`, merge `83211d4` |
| 36 | Reconciliation coverage on thin packages | `pkg/traffic` 51.4%, `pkg/hardware/wan` 57.6%, `pkg/network/ebpf` 93.2%, `pkg/security/policy` 51.1% | ✅ | feats `c31caf8`, `3714873`, `d2ec037`; merge `e5dcb3f` |
| 37 | Post-sprint truth-up | Reconciled `Status.md`, `docs/project-tracker.md`, `docs/implementation-plan.md`, `docs/observability-architecture.md` against landed artifacts | ✅ | feat `b937840`, merge `fd131de` |

## Verification

By the close of Sprint 29 the Kind harness proved:

- DPI manager `:8080/metrics` and NTP controller `:9559/metrics` pod-annotation scraping
- Single deterministic Suricata canary into `fos1-security-*` plus ILM/template attachment
- Accelerated ILM rollover + delete actually fire (Ticket 30) — distinct from the production `14d`/`30Gi` envelope
- Event-correlator round-trip via the file-source/file-sink contract (Ticket 29)
- Natural-traffic DPI via repo-owned Suricata rule sid 9000001 (Ticket 31)
- Dashboard/alert PromQL queries return live series or are explicitly allowlisted as target architecture (Ticket 32)

`make verify-mainline`: 37/37 test packages pass.

## Production-readiness delta

From ~55% → ~60–65%. Sprint 29 closed the "advertised but unshipped" surfaces (FilterPolicy enforcement, auth providers, NIC/capture reporting) and added meaningful observability proof depth. The formal removal of SAML/RADIUS/cert auth providers, nftables, and eBPF-based packet capture legitimately reduced the scope against which "ready" is measured.

Estimated effort-to-production revised from 6–10 months to 4–7 months.

## Caveats forwarded to Sprint 30

| From ticket | Caveat | Forwarded to |
|---|---|---|
| 33 | `FilterPolicy.Status.Conditions` mutate the in-memory cache but do not persist via the CRD `/status` subresource | Sprint 30 Ticket 40 |
| 33 | `FilterPolicySpec` future fields must be added to `canonicalizeSpec()` or spec-hash idempotency silently regresses | Documented |
| 33 | `pkg/security/firewall/` removal is a backward-compat break for clusters with `FirewallRule` CRs applied | Documented |
| 34 | `docs/design/cilium-implementation.md` and `docs/howto/security-configuration.md` retained historical `FirewallRule` YAML | Cleaned in commit `4c9ea97` |
| 35 | eBPF-based packet capture is now an explicit non-goal — capture path is `tcpdump` shim only | Permanent |
| 37 | Performance baseline is unscoped — no benchmarks exist | Sprint 30 Ticket 43 |

## Plan corrections

- **Ticket 33.** Plan claimed the controller was a stub and the translator was unused. Reality: the controller already wired the translator and called `ApplyNetworkPolicy`; what was missing was spec-hash idempotency, conditions, the Degraded-vs-all-or-nothing contract, and deterministic naming. Refactor in place rather than greenfield rewrite. Plan also missed that `pkg/security/firewall/` was a full nftables implementation, not just schema-only — cascaded removals to `pkg/deprecated/firewall/`, `zone_manager.go`, manifests.
- **Ticket 34.** Plan referenced `ADR-0001` as if absent; the file existed at `docs/design/adr-0001-cilium-first-control-plane-contract.md` (139 lines, 9 April).
- **Ticket 35.** Plan said "rename `manager.go` → `manager_linux.go`"; in practice this is a delete + add at git's level. Two abstractions needed (not one): `captureExec` for `LookPath`/`Command`, plus `captureProcess` for the Start → Signal/Kill → Wait lifecycle. First fake had a 1-buffered error channel and deadlocked inside Docker; fix was a `sync.Once`-guarded closed `done` channel.
- **Ticket 36.** `pkg/security/policy/` was scoped out — Ticket 33 already shipped reconciliation tests there. Coverage rows added to `docs/design/test_matrix.md` for traffic / wan / ebpf.
