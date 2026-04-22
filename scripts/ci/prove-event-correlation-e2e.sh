#!/usr/bin/env bash
#
# Sprint 29 / Ticket 29: deterministic end-to-end proof for the
# repository-owned event correlator runtime.
#
# Flow:
#   1. apply manifests/examples/security/ids/event-correlation-e2e.yaml
#   2. wait for the reconciled Deployment to become ready
#   3. kubectl exec into the correlator pod and append a single canary
#      JSON line to the configured spec.source.path
#   4. poll spec.sink.path inside the same pod for the correlated record
#      carrying the known canary_id
#   5. kubectl exec curl http://127.0.0.1:8080/ready and assert HTTP 200
#
# The manifest is cleaned up on exit via a trap so the Kind cluster is
# left in the same shape regardless of outcome.

set -Eeuo pipefail

E2E_MANIFEST="${E2E_MANIFEST:-manifests/examples/security/ids/event-correlation-e2e.yaml}"
E2E_NAMESPACE="${E2E_NAMESPACE:-security}"
E2E_NAME="${E2E_NAME:-correlation-e2e}"
E2E_DEPLOY_TIMEOUT="${E2E_DEPLOY_TIMEOUT:-240s}"
E2E_SOURCE_PATH="${E2E_SOURCE_PATH:-/var/run/fos1/events/e2e-events.jsonl}"
E2E_SINK_PATH="${E2E_SINK_PATH:-/var/log/correlator/e2e-correlated.json}"
E2E_CANARY_ID="${E2E_CANARY_ID:-SPRINT29-TICKET29-CANARY}"
E2E_RULE_NAME="${E2E_RULE_NAME:-canary-round-trip}"
E2E_READY_ATTEMPTS="${E2E_READY_ATTEMPTS:-30}"
E2E_SINK_ATTEMPTS="${E2E_SINK_ATTEMPTS:-30}"
E2E_SLEEP_SECONDS="${E2E_SLEEP_SECONDS:-2}"

pod_name=""
manifest_applied="false"

cleanup() {
  if [[ "${manifest_applied}" == "true" ]]; then
    kubectl delete -f "${E2E_MANIFEST}" --ignore-not-found=true \
      --wait=false >/dev/null 2>&1 || true
  fi
}

print_diagnostics() {
  local exit_code="$1"

  if ((exit_code == 0)); then
    return
  fi

  set +e

  echo "Event correlation E2E proof failed; collecting diagnostics..." >&2

  echo "--- EventCorrelation CR ---" >&2
  kubectl get eventcorrelation "${E2E_NAME}" -n "${E2E_NAMESPACE}" \
    -o yaml >&2 || true
  echo >&2

  echo "--- Pods in ${E2E_NAMESPACE} with label app=${E2E_NAME} ---" >&2
  kubectl get pods -n "${E2E_NAMESPACE}" -l "app=${E2E_NAME}" -o wide >&2 || true
  echo >&2

  if [[ -n "${pod_name}" ]]; then
    echo "--- describe pod ${pod_name} ---" >&2
    kubectl describe pod "${pod_name}" -n "${E2E_NAMESPACE}" >&2 || true
    echo >&2

    echo "--- last 100 log lines from ${pod_name} ---" >&2
    kubectl logs -n "${E2E_NAMESPACE}" "${pod_name}" --all-containers \
      --tail=100 >&2 || true
    echo >&2

    echo "--- tail of ${E2E_SOURCE_PATH} inside pod ---" >&2
    kubectl exec -n "${E2E_NAMESPACE}" "${pod_name}" -- \
      sh -c "tail -n 10 '${E2E_SOURCE_PATH}' 2>/dev/null || \
        echo 'source file not present'" >&2 || true
    echo >&2

    echo "--- tail of ${E2E_SINK_PATH} inside pod ---" >&2
    kubectl exec -n "${E2E_NAMESPACE}" "${pod_name}" -- \
      sh -c "tail -n 10 '${E2E_SINK_PATH}' 2>/dev/null || \
        echo 'sink file not present'" >&2 || true
    echo >&2
  fi
}

trap cleanup EXIT
trap 'print_diagnostics "$?"' ERR

apply_manifest() {
  echo "Applying E2E manifest ${E2E_MANIFEST}"
  kubectl apply -f "${E2E_MANIFEST}"
  manifest_applied="true"
}

maybe_override_correlator_image() {
  # When E2E_CORRELATOR_IMAGE_OVERRIDE is set, patch the controller-owned
  # Deployment to use the locally loaded image and disable registry
  # pulls. This is the bridge between the controller (which hard-codes
  # fos1/event-correlator:latest) and a Kind cluster that has only the
  # CI-built image available.
  if [[ -z "${E2E_CORRELATOR_IMAGE_OVERRIDE:-}" ]]; then
    return 0
  fi

  local attempt
  for attempt in $(seq 1 "${E2E_READY_ATTEMPTS}"); do
    if kubectl get deployment "${E2E_NAME}" -n "${E2E_NAMESPACE}" \
      >/dev/null 2>&1; then
      break
    fi
    sleep "${E2E_SLEEP_SECONDS}"
  done

  if ! kubectl get deployment "${E2E_NAME}" -n "${E2E_NAMESPACE}" \
    >/dev/null 2>&1; then
    echo "deployment/${E2E_NAME} was never reconciled by the IDS controller." >&2
    return 1
  fi

  echo "Overriding correlator image to ${E2E_CORRELATOR_IMAGE_OVERRIDE}"
  kubectl set image "deployment/${E2E_NAME}" -n "${E2E_NAMESPACE}" \
    "correlator=${E2E_CORRELATOR_IMAGE_OVERRIDE}" >/dev/null
  kubectl patch "deployment/${E2E_NAME}" -n "${E2E_NAMESPACE}" \
    --type=json \
    -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}]' \
    >/dev/null
}

wait_for_deployment() {
  echo "Waiting for deployment/${E2E_NAME} in ${E2E_NAMESPACE} to reconcile"
  local attempt
  for attempt in $(seq 1 "${E2E_READY_ATTEMPTS}"); do
    if kubectl get deployment "${E2E_NAME}" -n "${E2E_NAMESPACE}" \
      >/dev/null 2>&1; then
      break
    fi
    sleep "${E2E_SLEEP_SECONDS}"
  done

  if ! kubectl get deployment "${E2E_NAME}" -n "${E2E_NAMESPACE}" \
    >/dev/null 2>&1; then
    echo "deployment/${E2E_NAME} was not reconciled in ${E2E_NAMESPACE}." >&2
    return 1
  fi

  kubectl rollout status "deployment/${E2E_NAME}" -n "${E2E_NAMESPACE}" \
    --timeout="${E2E_DEPLOY_TIMEOUT}"
}

resolve_pod_name() {
  local attempt
  for attempt in $(seq 1 "${E2E_READY_ATTEMPTS}"); do
    pod_name="$(
      kubectl get pods -n "${E2E_NAMESPACE}" -l "app=${E2E_NAME}" \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
    )"
    if [[ -n "${pod_name}" ]]; then
      echo "Resolved correlator pod: ${pod_name}"
      return 0
    fi
    sleep "${E2E_SLEEP_SECONDS}"
  done

  echo "No Running pod found with label app=${E2E_NAME} in ${E2E_NAMESPACE}." >&2
  return 1
}

inject_canary_event() {
  local timestamp
  local canary_json

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  canary_json="$(
    printf '{"timestamp":"%s","canary_id":"%s","proof":"sprint-29-ticket-29"}' \
      "${timestamp}" "${E2E_CANARY_ID}"
  )"

  echo "Injecting canary event into ${E2E_SOURCE_PATH} on pod ${pod_name}"
  # We control both the shell command and the embedded JSON; the canary_id
  # and source path are locally generated constants, not user input.
  kubectl exec -n "${E2E_NAMESPACE}" "${pod_name}" -- \
    sh -c "mkdir -p \"\$(dirname '${E2E_SOURCE_PATH}')\" && \
      printf '%s\n' '${canary_json}' >> '${E2E_SOURCE_PATH}'"
}

poll_sink_for_canary() {
  local attempt
  local sink_output

  echo "Polling ${E2E_SINK_PATH} for correlated canary=${E2E_CANARY_ID}"
  for attempt in $(seq 1 "${E2E_SINK_ATTEMPTS}"); do
    sink_output="$(
      kubectl exec -n "${E2E_NAMESPACE}" "${pod_name}" -- \
        sh -c "cat '${E2E_SINK_PATH}' 2>/dev/null || true"
    )"
    if [[ -n "${sink_output}" ]] && assert_sink_contains_canary "${sink_output}"; then
      echo "Observed correlated record for canary=${E2E_CANARY_ID}"
      return 0
    fi
    sleep "${E2E_SLEEP_SECONDS}"
  done

  echo "Timed out waiting for canary=${E2E_CANARY_ID} in ${E2E_SINK_PATH}." >&2
  return 1
}

assert_sink_contains_canary() {
  local sink_output="$1"

  SINK_INPUT="${sink_output}" CANARY_ID="${E2E_CANARY_ID}" \
    RULE_NAME="${E2E_RULE_NAME}" python3 - <<'PY'
import json
import os
import sys

sink_input = os.environ["SINK_INPUT"]
canary_id = os.environ["CANARY_ID"]
rule_name = os.environ["RULE_NAME"]

matched = False
for line in sink_input.splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        continue

    rule = record.get("rule", {}) or {}
    if rule.get("name") != rule_name:
        continue

    for event in record.get("events", []) or []:
        if event.get("canary_id") == canary_id:
            matched = True
            break

    if matched:
        break

sys.exit(0 if matched else 1)
PY
}

assert_ready_endpoint() {
  echo "Calling http://127.0.0.1:8080/ready inside ${pod_name}"
  local attempt
  local status

  for attempt in $(seq 1 "${E2E_READY_ATTEMPTS}"); do
    status="$(
      kubectl exec -n "${E2E_NAMESPACE}" "${pod_name}" -- \
        sh -c "curl -fsS -o /dev/null -w '%{http_code}' \
          http://127.0.0.1:8080/ready" 2>/dev/null || true
    )"
    if [[ "${status}" == "200" ]]; then
      echo "/ready returned 200"
      return 0
    fi
    sleep "${E2E_SLEEP_SECONDS}"
  done

  echo "/ready did not return 200 after ${E2E_READY_ATTEMPTS} attempts" \
    "(last status: ${status:-unknown})" >&2
  return 1
}

main() {
  echo "Starting event correlation E2E proof"

  apply_manifest
  maybe_override_correlator_image
  wait_for_deployment
  resolve_pod_name
  inject_canary_event
  poll_sink_for_canary
  assert_ready_endpoint

  echo "Event correlation E2E proof summary:"
  echo "  eventcorrelation=${E2E_NAMESPACE}/${E2E_NAME}"
  echo "  pod=${pod_name}"
  echo "  canary_id=${E2E_CANARY_ID}"
  echo "  source_path=${E2E_SOURCE_PATH}"
  echo "  sink_path=${E2E_SINK_PATH}"
  echo "  ready_endpoint=http://127.0.0.1:8080/ready -> 200"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
