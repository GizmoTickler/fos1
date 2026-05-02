#!/usr/bin/env bash
# prove-mtls-mesh.sh
#
# Sprint 32 / Ticket 56 — controller-to-controller mTLS proof.
#
# This proof intentionally stays local and deterministic: it exercises the
# shared fos1-internal-ca mTLS helper with generated ephemeral certificates,
# then checks a real owned listener wrapper. The core round trip asserts:
#   1. A client cert signed by the mounted CA and present in the Subject-CN
#      allowlist succeeds.
#   2. A TLS client without a client cert fails the handshake.
#   3. A valid cert with an unknown Subject CN reaches HTTP and receives 403.
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
GO_BIN="${GO_BIN:-go}"
GOCACHE="${GOCACHE:-/tmp/fos1-gocache}"
export GOCACHE

echo "[${SCRIPT_NAME}] proving shared mTLS handshake + allowlist behavior"
"${GO_BIN}" test ./pkg/security/certificates \
  -run 'TestMutualTLSHTTPRoundTripEnforcesHandshakeAndAllowlist|TestLoadMutualTLSConfigUsesMountedMaterialForBothSides|TestRequireAllowedPeerSubjectDenyByDefault' \
  -count=1

echo "[${SCRIPT_NAME}] proving owned metrics listener wraps handlers with Subject-CN allowlist"
"${GO_BIN}" test ./pkg/kubernetes \
  -run TestTLSMetricsServerWrapsHandlerWithPeerSubjectAllowlist \
  -count=1

echo "[${SCRIPT_NAME}] PASS: mTLS mesh helper and owned-listener allowlist proof passed"
