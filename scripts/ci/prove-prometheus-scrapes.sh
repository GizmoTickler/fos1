#!/usr/bin/env bash

set -Eeuo pipefail

MONITORING_NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
PROMETHEUS_SERVICE="${PROMETHEUS_SERVICE:-prometheus}"
PROMETHEUS_LOCAL_PORT="${PROMETHEUS_LOCAL_PORT:-19090}"
PROMETHEUS_URL="http://127.0.0.1:${PROMETHEUS_LOCAL_PORT}"
PROMETHEUS_WAIT_ATTEMPTS="${PROMETHEUS_WAIT_ATTEMPTS:-30}"
PROMETHEUS_WAIT_SLEEP_SECONDS="${PROMETHEUS_WAIT_SLEEP_SECONDS:-5}"

port_forward_pid=""

cleanup() {
  if [[ -n "${port_forward_pid}" ]] && kill -0 "${port_forward_pid}" >/dev/null 2>&1; then
    kill "${port_forward_pid}" >/dev/null 2>&1 || true
    wait "${port_forward_pid}" >/dev/null 2>&1 || true
  fi
}

print_diagnostics() {
  local exit_code="$1"

  if ((exit_code == 0)); then
    return
  fi

  set +e

  echo "Prometheus scrape proof failed; collecting diagnostics..." >&2
  kubectl get pods -A -o wide >&2 || true
  echo >&2

  if curl -fsS "${PROMETHEUS_URL}/-/ready" >/dev/null 2>&1; then
    echo "--- Prometheus active targets ---" >&2
    curl -fsS "${PROMETHEUS_URL}/api/v1/targets?state=active" >&2 || true
    echo >&2

    echo "--- Prometheus up query for dpi-manager ---" >&2
    curl -fsS --get \
      --data-urlencode 'query=up{kubernetes_namespace="security",app="dpi-manager"}' \
      "${PROMETHEUS_URL}/api/v1/query" >&2 || true
    echo >&2

    echo "--- Prometheus up query for ntp-controller ---" >&2
    curl -fsS --get \
      --data-urlencode 'query=up{kubernetes_namespace="network",app="ntp-controller"}' \
      "${PROMETHEUS_URL}/api/v1/query" >&2 || true
    echo >&2
  fi
}

trap cleanup EXIT
trap 'print_diagnostics "$?"' ERR

start_port_forward() {
  kubectl port-forward -n "${MONITORING_NAMESPACE}" "service/${PROMETHEUS_SERVICE}" \
    "${PROMETHEUS_LOCAL_PORT}:9090" >/tmp/fos1-prometheus-port-forward.log 2>&1 &
  port_forward_pid="$!"
}

wait_for_prometheus() {
  local attempt

  for attempt in $(seq 1 "${PROMETHEUS_WAIT_ATTEMPTS}"); do
    if curl -fsS "${PROMETHEUS_URL}/-/ready" >/dev/null 2>&1; then
      return 0
    fi

    sleep "${PROMETHEUS_WAIT_SLEEP_SECONDS}"
  done

  echo "Prometheus did not become reachable through port-forward." >&2
  return 1
}

get_ready_pod_names() {
  local namespace="$1"
  local selector="$2"
  local pods_json

  pods_json="$(kubectl get pods -n "${namespace}" -l "${selector}" -o json)"

  JSON_INPUT="${pods_json}" python3 - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_INPUT"])

for item in data.get("items", []):
    metadata = item.get("metadata", {})
    status = item.get("status", {})
    conditions = status.get("conditions", [])
    ready = any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in conditions
    )
    if metadata.get("deletionTimestamp") is not None:
        continue
    if status.get("phase") != "Running":
        continue
    if not ready:
        continue
    print(metadata.get("name", ""))
PY
}

assert_active_targets_json() {
  if (($# != 3)); then
    echo "usage: assert_active_targets_json <namespace> <app> <expected_pods_csv>" >&2
    return 1
  fi

  JSON_INPUT="${JSON_INPUT:?JSON_INPUT must be set}" python3 - "$1" "$2" "$3" <<'PY'
import json
import os
import sys

namespace = sys.argv[1]
app = sys.argv[2]
expected_pods = {pod for pod in sys.argv[3].split(",") if pod}
data = json.loads(os.environ["JSON_INPUT"])

targets = data.get("data", {}).get("activeTargets", [])
healthy_pods = set()

for target in targets:
    labels = target.get("labels", {})
    if target.get("scrapePool") != "kubernetes-pods":
        continue
    if target.get("health") != "up":
        continue
    if labels.get("kubernetes_namespace") != namespace:
        continue
    if labels.get("app") != app:
        continue
    pod_name = labels.get("kubernetes_pod_name")
    if pod_name:
      healthy_pods.add(pod_name)

missing = sorted(expected_pods - healthy_pods)
if missing:
    raise SystemExit(
        f"missing healthy Prometheus targets for {namespace}/{app}: {', '.join(missing)}"
    )
PY
}

assert_up_query_json() {
  if (($# != 3)); then
    echo "usage: assert_up_query_json <namespace> <app> <expected_pods_csv>" >&2
    return 1
  fi

  JSON_INPUT="${JSON_INPUT:?JSON_INPUT must be set}" python3 - "$1" "$2" "$3" <<'PY'
import json
import os
import sys

namespace = sys.argv[1]
app = sys.argv[2]
expected_pods = {pod for pod in sys.argv[3].split(",") if pod}
data = json.loads(os.environ["JSON_INPUT"])

if data.get("status") != "success":
    raise SystemExit("Prometheus query did not succeed")

results = data.get("data", {}).get("result", [])
up_pods = set()

for result in results:
    metric = result.get("metric", {})
    if metric.get("kubernetes_namespace") != namespace:
        continue
    if metric.get("app") != app:
        continue
    pod_name = metric.get("kubernetes_pod_name")
    value = result.get("value", [None, None])[1]
    if pod_name and value == "1":
        up_pods.add(pod_name)

missing = sorted(expected_pods - up_pods)
if missing:
    raise SystemExit(
        f"missing up=1 Prometheus samples for {namespace}/{app}: {', '.join(missing)}"
    )
PY
}

prove_scrape_path() {
  local namespace="$1"
  local app="$2"
  local selector="$3"
  local attempt
  local targets_json
  local query_json
  local pod_names=()
  local expected_pods_csv

  mapfile -t pod_names < <(get_ready_pod_names "${namespace}" "${selector}")

  if ((${#pod_names[@]} == 0)); then
    echo "No ready pods found for ${namespace}/${app} using selector ${selector}." >&2
    return 1
  fi

  expected_pods_csv="$(IFS=,; echo "${pod_names[*]}")"
  echo "Expecting Prometheus pod-scrape targets for ${namespace}/${app}: ${expected_pods_csv}"

  for attempt in $(seq 1 "${PROMETHEUS_WAIT_ATTEMPTS}"); do
    targets_json="$(curl -fsS "${PROMETHEUS_URL}/api/v1/targets?state=active")"
    query_json="$(
      curl -fsS --get \
        --data-urlencode "query=up{kubernetes_namespace=\"${namespace}\",app=\"${app}\"}" \
        "${PROMETHEUS_URL}/api/v1/query"
    )"

    if JSON_INPUT="${targets_json}" assert_active_targets_json "${namespace}" "${app}" "${expected_pods_csv}" \
      && JSON_INPUT="${query_json}" assert_up_query_json "${namespace}" "${app}" "${expected_pods_csv}"; then
      echo "Prometheus scrape proof succeeded for ${namespace}/${app}."
      return 0
    fi

    sleep "${PROMETHEUS_WAIT_SLEEP_SECONDS}"
  done

  echo "Timed out waiting for Prometheus to prove the scrape path for ${namespace}/${app}." >&2
  return 1
}

main() {
  echo "Starting Prometheus scrape proof"
  start_port_forward
  wait_for_prometheus

  prove_scrape_path security dpi-manager 'app=dpi-manager'
  prove_scrape_path network ntp-controller 'app=ntp-controller'

  echo "Prometheus scrape proof summary:"
  echo "  security/dpi-manager: pod annotation target discovered and up=1"
  echo "  network/ntp-controller: pod annotation target discovered and up=1"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
