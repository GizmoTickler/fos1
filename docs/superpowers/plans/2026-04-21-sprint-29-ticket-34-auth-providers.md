# Sprint 29 / Ticket 34: Decide And Converge On SAML / RADIUS / Certificate Auth Providers

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the SAML / RADIUS / certificate auth provider stubs from the factory, CRD, examples, and docs so the repo stops advertising capability it does not ship. No `<type> provider not implemented` string may remain in the active manager factory path.

**Architecture:** Clean removal (Option B). Rationale verified:
- no skeleton code exists under `pkg/security/auth/providers/` for SAML, RADIUS, or certificate
- no example manifests exist for these types
- tests at `pkg/security/auth/manager_test.go:223-269` currently assert they fail with "not supported" — those tests document the gap, not the feature
- CRD `AuthProviderSpec.Type` is `string` without enum validation; removing the config structs is safe because nothing references them

If SAML / RADIUS is later wanted, it can be reintroduced properly via the established LDAP/OAuth 3-layer pattern.

**Tech Stack:** Go, Kubernetes API types, Go unit tests.

**Independence:** This ticket is fully self-contained — no dependency on other Sprint 29 tickets.

---

## Context (Grounded In Current Code)

### Unimplemented factory methods
- `pkg/security/auth/manager.go:790-791` — `NewSAMLProvider` returns `"SAML provider is not yet supported: no implementation available"`
- `pkg/security/auth/manager.go:796-797` — `NewRADIUSProvider` same pattern
- `pkg/security/auth/manager.go:802-803` — `NewCertificateProvider` same pattern

### Dispatch site
- `pkg/security/auth/manager.go:555-570` — `AddProvider()` switch statement dispatches to these factories

### Working-provider pattern (LDAP reference)
- `pkg/security/auth/providers/ldap.go:89-148` — constructor
- `pkg/security/auth/providers/factory.go:10-17` — `init()` registers via `auth.RegisterProviderConstructor("ldap", ...)`
- `pkg/security/auth/providers/factory.go:90-120` — `NewLDAPProviderFromInfo` adapter
- `pkg/security/auth/manager.go:744-762` — `NewLDAPProvider` validates and delegates

### CRD surface
- `pkg/apis/security/v1alpha1/auth_types.go:20-54` — `AuthProviderSpec`
  - `Type: string` at line 23 — no enum, no validation
  - `SAML *SAMLAuthConfig` at line 41
  - `RADIUS *RADIUSAuthConfig` at line 44
  - `Certificate *CertificateAuthConfig` at line 47
- `pkg/apis/security/v1alpha1/auth_types.go:164-195` — `SAMLAuthConfig`
- `pkg/apis/security/v1alpha1/auth_types.go:197-216` — `RADIUSAuthConfig`
- `pkg/apis/security/v1alpha1/auth_types.go:218-231` — `CertificateAuthConfig`

### Tests asserting current "not supported" behavior
- `pkg/security/auth/manager_test.go:223-237` — `TestNewSAMLProvider_NotSupported`
- `pkg/security/auth/manager_test.go:239-253` — `TestNewRADIUSProvider_NotSupported`
- `pkg/security/auth/manager_test.go:255-269` — `TestNewCertificateProvider_NotSupported`

### Example manifests
- `manifests/examples/security/auth/` — only `local-provider.yaml`, `ldap-provider.yaml`, `oauth-provider.yaml`. **No SAML, RADIUS, or certificate examples exist.** Nothing to remove here.

---

## File Map

- Modify: `pkg/security/auth/manager.go`
  - delete `NewSAMLProvider`, `NewRADIUSProvider`, `NewCertificateProvider` (lines ~788-804)
  - remove SAML/RADIUS/certificate cases from `AddProvider` switch (lines ~562-568)
  - add a default case that returns a clear error naming the supported types
- Modify: `pkg/apis/security/v1alpha1/auth_types.go`
  - remove `SAML`, `RADIUS`, `Certificate` fields from `AuthProviderSpec` (lines ~41, 44, 47)
  - remove `SAMLAuthConfig` (lines 164-195), `RADIUSAuthConfig` (197-216), `CertificateAuthConfig` (218-231)
- Modify: `pkg/security/auth/manager_test.go`
  - delete `TestNewSAMLProvider_NotSupported`, `TestNewRADIUSProvider_NotSupported`, `TestNewCertificateProvider_NotSupported` (lines 223-269)
  - add a replacement `TestAddProviderRejectsUnsupportedType` that exercises the new default case with "saml", "radius", "certificate", and a bogus type
- Modify: `manifests/base/security/ids/crds/` or wherever the `AuthProvider` CRD OpenAPI schema lives
  - remove `SAML`, `RADIUS`, `Certificate` entries from the schema (regenerate if using `controller-gen`)
- Modify: `Status.md`
  - update auth row: "Local, LDAP, OAuth supported; SAML/RADIUS/certificate are non-goals (removed 2026-04-21)"
- Modify: `docs/project-tracker.md`
  - mirror
- Modify: `docs/design/security-orchestration-system.md`
  - remove SAML/RADIUS/certificate architecture claims or move to a "non-goals" subsection
- Verify: `manifests/examples/security/auth/` — confirm no stale references
- Verify: any other caller (`grep -r 'SAMLAuthConfig\|RADIUSAuthConfig\|CertificateAuthConfig\|NewSAMLProvider\|NewRADIUSProvider\|NewCertificateProvider' --include='*.go' --include='*.yaml' --include='*.md'`)

---

## Task 1: Audit Every Reference Before Deleting

**Files:** entire repo

- [ ] **Step 1:** Run:
  ```
  grep -rn 'SAMLAuthConfig\|RADIUSAuthConfig\|CertificateAuthConfig' --include='*.go' --include='*.yaml'
  grep -rn 'NewSAMLProvider\|NewRADIUSProvider\|NewCertificateProvider' --include='*.go'
  grep -rn '"saml"\|"radius"\|"certificate"' pkg/security/auth/
  grep -rn 'SAML\|RADIUS\|certificate auth' docs/
  ```
- [ ] **Step 2:** Record every hit in a scratchpad. Classify each: (a) factory/type we're removing, (b) doc reference that must change, (c) unrelated coincidental match (e.g. a comment about x.509 server certificates for TLS — leave alone).
- [ ] **Step 3:** Confirm `manifests/examples/security/auth/` has no stale SAML/RADIUS/certificate example.

---

## Task 2: Remove The Factory Paths And The "Not Supported" Error Strings

**Files:**
- Modify: `pkg/security/auth/manager.go`

- [ ] **Step 1:** Delete the three factory functions `NewSAMLProvider`, `NewRADIUSProvider`, `NewCertificateProvider` at lines ~788-804.
- [ ] **Step 2:** In `AddProvider()` (around line 555), remove the switch cases for `"saml"`, `"radius"`, `"certificate"`.
- [ ] **Step 3:** Ensure the switch has a `default` clause that returns `fmt.Errorf("unsupported auth provider type %q: supported types are local, ldap, oauth", providerType)`.
- [ ] **Step 4:** Check for any dead imports introduced by the removal (e.g. unused `crypto/x509` that was only referenced by the cert-provider factory) and remove them.

---

## Task 3: Remove The CRD Config Structs

**Files:**
- Modify: `pkg/apis/security/v1alpha1/auth_types.go`

- [ ] **Step 1:** Delete the three fields `SAML *SAMLAuthConfig`, `RADIUS *RADIUSAuthConfig`, `Certificate *CertificateAuthConfig` from `AuthProviderSpec` (lines ~41, 44, 47).
- [ ] **Step 2:** Delete the three config type definitions (lines ~164-231).
- [ ] **Step 3:** If the repo uses `controller-gen` for deepcopy / CRD schema generation, regenerate: `make generate` or `controller-gen object paths=./pkg/apis/...`.
- [ ] **Step 4:** Update the generated CRD YAML under `manifests/base/security/ids/crds/` (or wherever the auth CRDs live) — ensure the removed config shapes are gone from the OpenAPI schema.

---

## Task 4: Update Tests

**Files:**
- Modify: `pkg/security/auth/manager_test.go`

- [ ] **Step 1:** Delete `TestNewSAMLProvider_NotSupported`, `TestNewRADIUSProvider_NotSupported`, `TestNewCertificateProvider_NotSupported` (lines 223-269).
- [ ] **Step 2:** Add `TestAddProviderRejectsUnsupportedType` that:
  ```
  for _, tpe := range []string{"saml", "radius", "certificate", "notarealtype"} {
    err := mgr.AddProvider(&ProviderInfo{Type: tpe, Name: "t"})
    assert.ErrorContains(t, err, "unsupported auth provider type")
    assert.ErrorContains(t, err, "local, ldap, oauth")
  }
  ```
- [ ] **Step 3:** Run `go test ./pkg/security/auth/...` and confirm passing.

---

## Task 5: Docs Truth-Up

**Files:**
- Modify: `Status.md`
- Modify: `docs/project-tracker.md`
- Modify: `docs/design/security-orchestration-system.md`

- [ ] **Step 1:** In `Status.md`, update the auth provider row to list only Local/LDAP/OAuth and mark SAML/RADIUS/certificate as removed non-goals (with date).
- [ ] **Step 2:** In `project-tracker.md`, mirror the update.
- [ ] **Step 3:** In `security-orchestration-system.md`, either delete the SAML/RADIUS/cert architecture subsections or move them under a clearly labelled "Non-Goals" section with: "This repository is Cilium-first and intentionally scopes auth to local/LDAP/OAuth. SAML/RADIUS/cert support was removed on 2026-04-21 because no implementation shipped."

---

## Verification

- [ ] `make verify-mainline` passes
- [ ] `grep -rn '"saml"\|"radius"\|"certificate" provider not implemented' pkg/` returns nothing
- [ ] `grep -rn 'SAMLAuthConfig\|RADIUSAuthConfig\|CertificateAuthConfig' --include='*.go'` returns nothing
- [ ] `grep -rn 'NewSAMLProvider\|NewRADIUSProvider\|NewCertificateProvider' --include='*.go'` returns nothing
- [ ] `go test ./pkg/security/auth/...` passes
- [ ] `go test ./pkg/apis/...` passes (deepcopy regenerated)
- [ ] Status/tracker docs reflect the new provider set

---

## Out Of Scope

- Actually implementing SAML / RADIUS / cert auth (future ticket if needed)
- Rework of local / LDAP / OAuth providers
- Any change to `pkg/security/auth/providers/factory.go` beyond import cleanup

---

## Suggested Branch Name

`sprint-29/ticket-34-auth-provider-closeout`
