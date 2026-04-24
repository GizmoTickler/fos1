#!/usr/bin/env bash
#
# harness-threatintel.sh — Sprint-30 Ticket-44 CI harness wrapper.
#
# Runs the build-tagged threat-intelligence end-to-end test that proves
# fetch → translate → apply → expire against a canned URLhaus CSV served
# from an in-process HTTP test server (the in-cluster nginx equivalent).
#
# The harness is intentionally hermetic — it does NOT hit abuse.ch and does
# NOT require a running Kubernetes cluster. Run it in CI as:
#
#   ./scripts/harness-threatintel.sh
#
# For a live in-cluster harness, see manifests/examples/security/
# threatfeed-urlhaus.yaml which points the ThreatFeed at an nginx pod that
# serves the canned CSV under /urlhaus.csv.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[harness] running threatintel URLhaus end-to-end proof"
go test -tags=harness -count=1 -run TestHarness_EndToEnd -v ./pkg/security/threatintel/...

echo "[harness] running threatintel MISP end-to-end proof (Sprint 31 Ticket 53)"
go test -tags=harness -count=1 -run TestHarness_MISPEndToEnd -v ./pkg/security/threatintel/...

echo "[harness] OK"
