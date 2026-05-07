# ADR-0002: FRR vtysh TLS Sidecar

## Status

Accepted.

## Context

Sprint 32 Ticket 58 closes the external-daemon TLS caveat for FRR. The
existing FRR client shells out to `vtysh`, which is a local frontend to the FRR
daemons and their integrated configuration flow. FRR documentation describes
`vtysh` as the combined shell for daemon configuration and, in older stable
docs, calls out its Unix-socket access model and `frrvty` group boundary. It
does not expose a TLS-native remote management endpoint that maps cleanly to
the controller's existing `vtysh -c` command contract.

## Decision

Use a repo-owned sidecar TLS terminator rather than FRR-native TLS for Ticket
58.

The sidecar runs in the FRR pod, mounts `/var/run/frr`, executes the local
`vtysh` binary, and exposes only a small HTTPS JSON endpoint:

```text
POST /vtysh
{"command":"show version"}
```

The HTTPS endpoint uses cert-manager material from `fos1-internal-ca`.
Controller callers use a client certificate whose Subject CN is explicitly
allowlisted by the sidecar. The Kubernetes Service exposes `vtysh-tls:9443`;
the old plaintext vtysh Service port is removed.

## Consequences

- FRR daemon sockets stay pod-local and are no longer the cross-pod control
  plane boundary.
- The Go FRR client can continue using the same `ExecuteVtyshCommand` API while
  selecting `exec` or `https` transport from config / env.
- The sidecar remains responsible for command execution only; it does not parse
  or authorize individual FRR commands. Authorization is coarse-grained by
  client certificate Subject CN, matching the Sprint 32 mTLS mesh pattern.
- Native FRR TLS can be revisited later if FRR ships a stable TLS management
  endpoint that preserves the same command semantics.
