#!/usr/bin/env bash
# prove-frr-vtysh-tls.sh
#
# Sprint 32 / Ticket 58 — FRR vtysh mTLS sidecar proof.
#
# This local proof keeps FRR itself out of the test path and instead verifies
# the repo-owned security boundary:
#   1. The FRR client reaches /vtysh over mTLS and sends the command as JSON.
#   2. The sidecar executes vtysh locally and returns stdout over HTTPS JSON.
#   3. Missing client certificates are rejected before command execution.
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
GO_BIN="${GO_BIN:-go}"
GOCACHE="${GOCACHE:-/tmp/fos1-gocache}"
export GOCACHE

echo "[${SCRIPT_NAME}] proving FRR client mTLS transport"
"${GO_BIN}" test ./pkg/network/routing/frr \
  -run 'TestExecuteVtyshCommandUsesMutualTLSEndpoint|TestExecuteVtyshCommandRequiresClientCertificateForTLSEndpoint' \
  -count=1

echo "[${SCRIPT_NAME}] proving frr-vtysh-sidecar command endpoint"
"${GO_BIN}" test ./cmd/frr-vtysh-sidecar -count=1

echo "[${SCRIPT_NAME}] PASS: FRR vtysh mTLS sidecar proof passed"
