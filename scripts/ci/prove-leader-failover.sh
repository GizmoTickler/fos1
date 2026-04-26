#!/usr/bin/env bash
# prove-leader-failover.sh
#
# Sprint 31 / Ticket 47 — leader-election failover proof.
#
# Targets the ids-controller Deployment because:
#   - It's already deployed in the test-bootstrap CI harness (after the
#     "Deploy IDS controller for event correlation proof" step).
#   - It's a Deployment (not a DaemonSet, like dpi-manager) and so two
#     replicas are scheduled with podAntiAffinity = preferred.
#   - Its main wires the pkg/leaderelection helper, which writes its
#     holderIdentity to the Lease coordination.k8s.io/v1 object named
#     ids-controller.fos1.io in the security namespace.
#
# The proof:
#   1. Read the current holderIdentity from the lease.
#   2. Force-delete that pod with --grace-period=0.
#   3. Poll the lease holderIdentity at 2s cadence up to 60s.
#   4. Assert the new holder is a different pod and is Ready.
#
# RTO target: ≤ 30s. We allow up to 60s in the script to keep CI noise
# low; any handover that takes longer than 30s should be investigated.
#
# Exit codes:
#   0 - failover detected within the timeout
#   1 - no failover within the timeout, or new holder not Ready
#   2 - script usage / environment error
set -euo pipefail

SCRIPT_NAME=$(basename "$0")
NAMESPACE="${LEADER_FAILOVER_NAMESPACE:-security}"
DEPLOYMENT="${LEADER_FAILOVER_DEPLOYMENT:-ids-controller}"
LEASE_NAME="${LEADER_FAILOVER_LEASE:-${DEPLOYMENT}.fos1.io}"
TIMEOUT_SECONDS="${LEADER_FAILOVER_TIMEOUT:-60}"
POLL_INTERVAL="${LEADER_FAILOVER_POLL_INTERVAL:-2}"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "[${SCRIPT_NAME}] FAIL: kubectl not on PATH" >&2
  exit 2
fi

echo "[${SCRIPT_NAME}] target deployment=${DEPLOYMENT} namespace=${NAMESPACE} lease=${LEASE_NAME}"

# Wait for the deployment to have at least 1 ready replica before the test.
echo "[${SCRIPT_NAME}] waiting for ${DEPLOYMENT} to have ready replicas"
kubectl rollout status "deployment/${DEPLOYMENT}" -n "${NAMESPACE}" --timeout=120s

# Poll until the lease has a holderIdentity. Lease creation happens only
# after the first replica wins election (typically within a few seconds).
deadline=$(( $(date +%s) + 60 ))
initial_holder=""
while [[ "$(date +%s)" -lt "${deadline}" ]]; do
  initial_holder="$(kubectl get lease "${LEASE_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || true)"
  if [[ -n "${initial_holder}" ]]; then
    break
  fi
  sleep "${POLL_INTERVAL}"
done

if [[ -z "${initial_holder}" ]]; then
  echo "[${SCRIPT_NAME}] FAIL: lease ${LEASE_NAME} never acquired a holderIdentity" >&2
  kubectl get lease -n "${NAMESPACE}" || true
  kubectl get pods -n "${NAMESPACE}" -l "app=${DEPLOYMENT}" -o wide || true
  exit 1
fi

echo "[${SCRIPT_NAME}] initial leader: ${initial_holder}"

# The pod_name we kill is whatever string the lease records as
# holderIdentity. By convention from pkg/leaderelection.IdentityFromEnv()
# this is POD_NAME, which the Deployment provides via the downward API.
if ! kubectl get pod "${initial_holder}" -n "${NAMESPACE}" >/dev/null 2>&1; then
  echo "[${SCRIPT_NAME}] FAIL: lease holderIdentity=${initial_holder} does not match a pod in namespace ${NAMESPACE}" >&2
  echo "[${SCRIPT_NAME}]        verify the Deployment sets POD_NAME via downward API" >&2
  kubectl get pods -n "${NAMESPACE}" -l "app=${DEPLOYMENT}" -o wide || true
  exit 1
fi

echo "[${SCRIPT_NAME}] killing leader pod ${initial_holder} (force, grace=0)"
kubectl delete pod "${initial_holder}" -n "${NAMESPACE}" \
  --grace-period=0 --force --wait=false

echo "[${SCRIPT_NAME}] polling lease holderIdentity for handover (timeout=${TIMEOUT_SECONDS}s)"
start_ts=$(date +%s)
new_holder=""
elapsed=0
while [[ "${elapsed}" -lt "${TIMEOUT_SECONDS}" ]]; do
  current="$(kubectl get lease "${LEASE_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || true)"
  if [[ -n "${current}" && "${current}" != "${initial_holder}" ]]; then
    new_holder="${current}"
    break
  fi
  sleep "${POLL_INTERVAL}"
  elapsed=$(( $(date +%s) - start_ts ))
done

if [[ -z "${new_holder}" ]]; then
  echo "[${SCRIPT_NAME}] FAIL: no handover detected within ${TIMEOUT_SECONDS}s — lease still held by ${initial_holder}" >&2
  kubectl get lease "${LEASE_NAME}" -n "${NAMESPACE}" -o yaml || true
  kubectl get pods -n "${NAMESPACE}" -l "app=${DEPLOYMENT}" -o wide || true
  exit 1
fi

handover_seconds=$(( $(date +%s) - start_ts ))
echo "[${SCRIPT_NAME}] handover observed: ${initial_holder} -> ${new_holder} (${handover_seconds}s elapsed)"

# Assert the new holder pod is Ready. If the surviving replica was already
# Ready before the test, this should be true immediately.
ready="$(kubectl get pod "${new_holder}" -n "${NAMESPACE}" \
  -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}' 2>/dev/null || true)"
if [[ "${ready}" != "True" ]]; then
  echo "[${SCRIPT_NAME}] FAIL: new leader pod ${new_holder} is not Ready (status=${ready:-<missing>})" >&2
  kubectl describe pod "${new_holder}" -n "${NAMESPACE}" || true
  exit 1
fi

if [[ "${handover_seconds}" -gt 30 ]]; then
  echo "[${SCRIPT_NAME}] WARN: handover took ${handover_seconds}s (> 30s RTO target)"
fi

echo "[${SCRIPT_NAME}] PASS: lease ${LEASE_NAME} failover ${initial_holder} -> ${new_holder} in ${handover_seconds}s"
exit 0
