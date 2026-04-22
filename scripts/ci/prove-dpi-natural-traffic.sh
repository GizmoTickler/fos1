#!/usr/bin/env bash

# prove-dpi-natural-traffic.sh
#
# Sprint 29 / Ticket 31: prove the Suricata sensor actually participates
# in the DPI pipeline by driving a real HTTP payload through a test pod,
# observing the matching eve.json event, confirming Elasticsearch indexes
# it under fos1-security-*, and confirming the DPI manager's Prometheus
# dpi_events_total counter has advanced.
#
# This is intentionally distinct from prove-security-log-pipeline.sh, which
# seeds a hand-written JSON line directly into the Suricata eve.json host
# path. That canary proves log-ingestion only. This harness proves the
# full sensor -> log -> index -> metric path under real traffic.
#
# Assertions (all must pass, in order):
#   1. Suricata eve.json on its host node contains at least one event with
#      alert.signature_id == 9000001 after the curl runs
#   2. Elasticsearch fos1-security-* has at least one hit for
#      alert.signature_id == 9000001
#   3. Prometheus dpi_events_total{event_type=~"alert|suricata",...} has
#      advanced past the pre-traffic baseline
#
# See:
#   * manifests/base/security/suricata.yaml
#   * manifests/base/security/suricata/rules/fos1-canary.rules
#   * pkg/kubernetes/metrics_server.go (dpi_events_total)
#   * docs/observability-architecture.md "Natural-Traffic DPI Proof"
#   * docs/design/policy-based-filtering.md "Reserved Suricata SIDs"

set -Eeuo pipefail

CANARY_HEADER_NAME="${CANARY_HEADER_NAME:-X-FOS1-Canary}"
CANARY_HEADER_VALUE="${CANARY_HEADER_VALUE:-A1B2C3D4}"
CANARY_SID="${CANARY_SID:-9000001}"

SECURITY_NAMESPACE="${SECURITY_NAMESPACE:-security}"
MONITORING_NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"

SURICATA_SELECTOR="${SURICATA_SELECTOR:-app=suricata}"
SURICATA_LOG_PATH="${SURICATA_LOG_PATH:-/var/log/fos1/suricata/eve.json}"

DPI_SELECTOR="${DPI_SELECTOR:-app=dpi-manager}"

ELASTICSEARCH_SERVICE="${ELASTICSEARCH_SERVICE:-elasticsearch}"
ELASTICSEARCH_LOCAL_PORT="${ELASTICSEARCH_LOCAL_PORT:-19201}"
ELASTICSEARCH_URL="http://127.0.0.1:${ELASTICSEARCH_LOCAL_PORT}"
EXPECTED_SECURITY_INDEX_PREFIX="${EXPECTED_SECURITY_INDEX_PREFIX:-fos1-security-}"

PROMETHEUS_SERVICE="${PROMETHEUS_SERVICE:-prometheus}"
PROMETHEUS_LOCAL_PORT="${PROMETHEUS_LOCAL_PORT:-19091}"
PROMETHEUS_URL="http://127.0.0.1:${PROMETHEUS_LOCAL_PORT}"

CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.10.1}"
# The default target is a DNS name resolvable inside the cluster. Override
# with TARGET_URL when the inspection path changes. The request must cross
# the interface Suricata watches; see the live-Kind caveat in the plan.
TARGET_URL="${TARGET_URL:-http://elasticsearch.${MONITORING_NAMESPACE}.svc.cluster.local:9200/}"
TEST_POD_NAME="${TEST_POD_NAME:-fos1-canary-curl-$(date -u +%Y%m%d%H%M%S)-$$}"
TEST_POD_NAMESPACE="${TEST_POD_NAMESPACE:-${SECURITY_NAMESPACE}}"

SURICATA_POLL_ATTEMPTS="${SURICATA_POLL_ATTEMPTS:-30}"   # 30 * 2s = 60s
SURICATA_POLL_SLEEP_SECONDS="${SURICATA_POLL_SLEEP_SECONDS:-2}"
ELASTICSEARCH_POLL_ATTEMPTS="${ELASTICSEARCH_POLL_ATTEMPTS:-18}"   # 18 * 5s = 90s
ELASTICSEARCH_POLL_SLEEP_SECONDS="${ELASTICSEARCH_POLL_SLEEP_SECONDS:-5}"
PROMETHEUS_POLL_ATTEMPTS="${PROMETHEUS_POLL_ATTEMPTS:-24}"          # 24 * 5s = 120s
PROMETHEUS_POLL_SLEEP_SECONDS="${PROMETHEUS_POLL_SLEEP_SECONDS:-5}"

es_port_forward_pid=""
prom_port_forward_pid=""
suricata_node=""
baseline_counter=""

cleanup() {
  local exit_code="$?"

  if [[ -n "${es_port_forward_pid}" ]] && kill -0 "${es_port_forward_pid}" >/dev/null 2>&1; then
    kill "${es_port_forward_pid}" >/dev/null 2>&1 || true
    wait "${es_port_forward_pid}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${prom_port_forward_pid}" ]] && kill -0 "${prom_port_forward_pid}" >/dev/null 2>&1; then
    kill "${prom_port_forward_pid}" >/dev/null 2>&1 || true
    wait "${prom_port_forward_pid}" >/dev/null 2>&1 || true
  fi

  kubectl delete pod "${TEST_POD_NAME}" \
    -n "${TEST_POD_NAMESPACE}" \
    --ignore-not-found=true \
    --grace-period=0 --force >/dev/null 2>&1 || true

  exit "${exit_code}"
}

print_diagnostics() {
  local exit_code="$1"

  if ((exit_code == 0)); then
    return
  fi

  set +e

  echo "Natural-traffic DPI proof failed; collecting diagnostics..." >&2
  echo "--- Suricata pods ---" >&2
  kubectl get pods -n "${SECURITY_NAMESPACE}" -l "${SURICATA_SELECTOR}" -o wide >&2 || true
  echo >&2

  if [[ -n "${suricata_node}" ]]; then
    echo "--- Tail ${SURICATA_LOG_PATH} on node ${suricata_node} ---" >&2
    docker exec "${suricata_node}" sh -c "tail -n 20 '${SURICATA_LOG_PATH}' 2>/dev/null || true" >&2 || true
    echo >&2
  fi

  echo "--- DPI manager pods ---" >&2
  kubectl get pods -n "${SECURITY_NAMESPACE}" -l "${DPI_SELECTOR}" -o wide >&2 || true
  echo >&2

  echo "--- Test pod status (if present) ---" >&2
  kubectl get pod "${TEST_POD_NAME}" -n "${TEST_POD_NAMESPACE}" -o wide >&2 || true
  kubectl logs "${TEST_POD_NAME}" -n "${TEST_POD_NAMESPACE}" --tail=40 >&2 || true
  echo >&2
}

trap cleanup EXIT
trap 'print_diagnostics "$?"' ERR

start_port_forward() {
  local service="$1"
  local namespace="$2"
  local local_port="$3"
  local remote_port="$4"
  local log_file="$5"
  local pid_var="$6"

  kubectl port-forward -n "${namespace}" "service/${service}" \
    "${local_port}:${remote_port}" >"${log_file}" 2>&1 &
  printf -v "${pid_var}" '%s' "$!"
}

wait_for_http() {
  local url="$1"
  local probe_path="$2"
  local attempts="$3"
  local sleep_seconds="$4"
  local attempt

  for attempt in $(seq 1 "${attempts}"); do
    if curl -fsS "${url}${probe_path}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done

  echo "Endpoint ${url}${probe_path} did not become reachable." >&2
  return 1
}

discover_suricata_node() {
  suricata_node="$(
    kubectl get pods -n "${SECURITY_NAMESPACE}" -l "${SURICATA_SELECTOR}" \
      -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' \
    | sed '/^$/d' | sort -u | head -n 1
  )"

  if [[ -z "${suricata_node}" ]]; then
    echo "No Suricata pods found in namespace ${SECURITY_NAMESPACE}." >&2
    return 1
  fi

  echo "Suricata pod landed on node: ${suricata_node}"
}

capture_dpi_counter_baseline() {
  # Read dpi_events_total from the live Prometheus time series as the
  # baseline. We use sum() to collapse labels so the value is stable even
  # if new label combinations appear after the traffic.
  local response
  response="$(
    curl -fsS --get \
      --data-urlencode 'query=sum(dpi_events_total)' \
      "${PROMETHEUS_URL}/api/v1/query"
  )"

  baseline_counter="$(
    JSON_INPUT="${response}" python3 - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_INPUT"])
if data.get("status") != "success":
    print("0")
    raise SystemExit(0)

result = data.get("data", {}).get("result", [])
if not result:
    print("0")
    raise SystemExit(0)

value = result[0].get("value", [None, "0"])[1]
try:
    print(float(value))
except (TypeError, ValueError):
    print("0")
PY
  )"

  echo "DPI metric baseline: sum(dpi_events_total) = ${baseline_counter}"
}

drive_canary_traffic() {
  # Schedule the test pod on the Suricata node so the curl actually
  # crosses the inspection path (hostNetwork=true Suricata is listening
  # on that node's eth0). nodeSelector + kubernetes.io/hostname is the
  # standard mechanism. We use a Pod (not a Job) so we can easily stream
  # logs and rely on restartPolicy=Never.
  echo "Launching curl test pod ${TEST_POD_NAME} on node ${suricata_node}"
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: ${TEST_POD_NAME}
  namespace: ${TEST_POD_NAMESPACE}
  labels:
    app: fos1-canary-curl
    fos1.io/purpose: natural-traffic-dpi-canary
spec:
  restartPolicy: Never
  nodeSelector:
    kubernetes.io/hostname: ${suricata_node}
  hostNetwork: true
  tolerations:
  - operator: Exists
  containers:
  - name: curl
    image: ${CURL_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - >-
      for i in 1 2 3 4 5; do
        curl -sS -o /dev/null -w 'attempt=%{http_code}\n' --max-time 5
        -H '${CANARY_HEADER_NAME}: ${CANARY_HEADER_VALUE}'
        '${TARGET_URL}' || true;
        sleep 1;
      done
EOF

  # Wait for the pod to finish so we know traffic has actually left.
  kubectl wait --for=condition=Ready pod/"${TEST_POD_NAME}" \
    -n "${TEST_POD_NAMESPACE}" --timeout=60s >/dev/null 2>&1 || true

  local attempt
  for attempt in $(seq 1 30); do
    local phase
    phase="$(kubectl get pod "${TEST_POD_NAME}" -n "${TEST_POD_NAMESPACE}" \
      -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    case "${phase}" in
      Succeeded|Failed)
        echo "Canary curl pod completed (phase=${phase})"
        kubectl logs "${TEST_POD_NAME}" -n "${TEST_POD_NAMESPACE}" --tail=20 || true
        return 0
        ;;
    esac
    sleep 2
  done

  echo "Canary curl pod did not reach a terminal phase; continuing to poll downstream signals." >&2
}

poll_suricata_eve_for_sid() {
  # Use docker exec against the Kind node to read eve.json. Each line is
  # a JSON object; we grep for the canary signature ID and also parse
  # the JSON to confirm it is an alert event (not e.g. a flow record
  # that coincidentally matches the string).
  local attempt
  for attempt in $(seq 1 "${SURICATA_POLL_ATTEMPTS}"); do
    if docker exec "${suricata_node}" sh -c \
         "grep -F '\"signature_id\":${CANARY_SID}' '${SURICATA_LOG_PATH}' 2>/dev/null | head -n 5" \
         | python3 - "${CANARY_SID}" <<'PY' >/dev/null
import json
import sys

sid = int(sys.argv[1])
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if event.get("event_type") != "alert":
        continue
    alert = event.get("alert", {}) or {}
    if alert.get("signature_id") == sid:
        raise SystemExit(0)
raise SystemExit(1)
PY
    then
      echo "Suricata eve.json on ${suricata_node} contains an alert with signature_id=${CANARY_SID}"
      return 0
    fi

    sleep "${SURICATA_POLL_SLEEP_SECONDS}"
  done

  echo "Timed out waiting for Suricata eve.json to emit signature_id=${CANARY_SID}." >&2
  return 1
}

poll_elasticsearch_for_sid() {
  local attempt
  local response

  for attempt in $(seq 1 "${ELASTICSEARCH_POLL_ATTEMPTS}"); do
    response="$(
      curl -fsS --get \
        --data-urlencode "q=alert.signature_id:${CANARY_SID}" \
        "${ELASTICSEARCH_URL}/${EXPECTED_SECURITY_INDEX_PREFIX}*/_search?allow_no_indices=true&ignore_unavailable=true&size=1" \
      || echo '{}'
    )"

    if JSON_INPUT="${response}" python3 - "${EXPECTED_SECURITY_INDEX_PREFIX}" <<'PY' >/dev/null
import json
import os
import sys

prefix = sys.argv[1]
data = json.loads(os.environ.get("JSON_INPUT") or "{}")
hits = data.get("hits", {}).get("hits", [])
if not hits:
    raise SystemExit(1)

hit = hits[0]
index = hit.get("_index", "")
if not index.startswith(prefix):
    raise SystemExit(1)

source = hit.get("_source", {}) or {}
if source.get("security_sensor") != "suricata":
    raise SystemExit(1)
PY
    then
      echo "Elasticsearch ${EXPECTED_SECURITY_INDEX_PREFIX}* indexed a Suricata alert with signature_id=${CANARY_SID}"
      return 0
    fi

    sleep "${ELASTICSEARCH_POLL_SLEEP_SECONDS}"
  done

  echo "Timed out waiting for Elasticsearch hit on alert.signature_id=${CANARY_SID}." >&2
  return 1
}

poll_prometheus_counter_advanced() {
  # The repo-owned DPI exporter is pkg/kubernetes/metrics_server.go; the
  # counter it exposes is dpi_events_total{event_type,application,category}.
  # We assert sum(dpi_events_total) has increased past the pre-traffic
  # baseline. We do NOT pin a specific label set because the exact
  # event_type/application/category that advances depends on the DPI
  # manager wiring under which connector ingested the alert.
  local attempt
  local response
  local current

  for attempt in $(seq 1 "${PROMETHEUS_POLL_ATTEMPTS}"); do
    response="$(
      curl -fsS --get \
        --data-urlencode 'query=sum(dpi_events_total)' \
        "${PROMETHEUS_URL}/api/v1/query"
    )"

    current="$(
      JSON_INPUT="${response}" python3 - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_INPUT"])
if data.get("status") != "success":
    print("0")
    raise SystemExit(0)

result = data.get("data", {}).get("result", [])
if not result:
    print("0")
    raise SystemExit(0)

value = result[0].get("value", [None, "0"])[1]
try:
    print(float(value))
except (TypeError, ValueError):
    print("0")
PY
    )"

    if python3 - "${baseline_counter}" "${current}" <<'PY'
import sys

baseline = float(sys.argv[1])
current = float(sys.argv[2])
raise SystemExit(0 if current > baseline else 1)
PY
    then
      echo "DPI counter advanced: sum(dpi_events_total) ${baseline_counter} -> ${current}"
      return 0
    fi

    sleep "${PROMETHEUS_POLL_SLEEP_SECONDS}"
  done

  echo "Timed out waiting for sum(dpi_events_total) to advance past ${baseline_counter}." >&2
  return 1
}

main() {
  echo "Starting natural-traffic DPI proof (sid=${CANARY_SID})"

  discover_suricata_node

  start_port_forward "${ELASTICSEARCH_SERVICE}" "${MONITORING_NAMESPACE}" \
    "${ELASTICSEARCH_LOCAL_PORT}" 9200 \
    /tmp/fos1-natural-traffic-es-portforward.log es_port_forward_pid
  wait_for_http "${ELASTICSEARCH_URL}" "/_cluster/health?wait_for_status=yellow&timeout=5s" 30 2

  start_port_forward "${PROMETHEUS_SERVICE}" "${MONITORING_NAMESPACE}" \
    "${PROMETHEUS_LOCAL_PORT}" 9090 \
    /tmp/fos1-natural-traffic-prom-portforward.log prom_port_forward_pid
  wait_for_http "${PROMETHEUS_URL}" "/-/ready" 30 2

  capture_dpi_counter_baseline

  drive_canary_traffic

  echo "Polling Suricata eve.json on node ${suricata_node} for signature_id=${CANARY_SID}"
  poll_suricata_eve_for_sid

  echo "Polling Elasticsearch ${EXPECTED_SECURITY_INDEX_PREFIX}* for alert.signature_id=${CANARY_SID}"
  poll_elasticsearch_for_sid

  echo "Polling Prometheus for advance on sum(dpi_events_total)"
  poll_prometheus_counter_advanced

  echo "Natural-traffic DPI proof succeeded:"
  echo "  canary_sid=${CANARY_SID}"
  echo "  canary_header=${CANARY_HEADER_NAME}: ${CANARY_HEADER_VALUE}"
  echo "  suricata_node=${suricata_node}"
  echo "  eve_log=${SURICATA_LOG_PATH}"
  echo "  security_index_prefix=${EXPECTED_SECURITY_INDEX_PREFIX}"
  echo "  dpi_metric=sum(dpi_events_total) advanced past ${baseline_counter}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
