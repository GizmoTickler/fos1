#!/usr/bin/env bash
# prove-suricata-command-auth-tls.sh
#
# Sprint 32 / Ticket 59 — Suricata command auth + TLS fallback proof.
#
# This local proof keeps a real Suricata daemon out of the test path and proves
# the repo-owned security boundary:
#   1. The Suricata client can present mTLS material to the HTTPS fallback.
#   2. The command sidecar rejects requests missing the shared-secret header.
#   3. The command sidecar forwards authenticated requests to the native
#      Suricata Unix socket after Suricata's version negotiation.
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
GO_BIN="${GO_BIN:-go}"
GOCACHE="${GOCACHE:-/tmp/fos1-gocache}"
export GOCACHE

echo "[${SCRIPT_NAME}] proving Suricata client auth/TLS transports"
"${GO_BIN}" test ./pkg/security/ids/suricata \
  -run 'TestExecuteAuthenticatesUnixSocketBeforeCommand|TestExecuteRejectsUnauthenticatedUnixSocketCommand|TestExecuteUsesMutualTLSEndpoint' \
  -count=1

echo "[${SCRIPT_NAME}] proving suricata-command-sidecar auth gateway"
"${GO_BIN}" test ./cmd/suricata-command-sidecar -count=1

echo "[${SCRIPT_NAME}] PASS: Suricata command auth/TLS proof passed"
