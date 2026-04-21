#!/usr/bin/env bash

set -Eeuo pipefail

MONITORING_NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
FLUENTD_SELECTOR="${FLUENTD_SELECTOR:-app=fluentd}"
FLUENTD_NAMESPACE="${FLUENTD_NAMESPACE:-monitoring}"
ELASTICSEARCH_SERVICE="${ELASTICSEARCH_SERVICE:-elasticsearch}"
ELASTICSEARCH_LOCAL_PORT="${ELASTICSEARCH_LOCAL_PORT:-19200}"
ELASTICSEARCH_URL="http://127.0.0.1:${ELASTICSEARCH_LOCAL_PORT}"
ILM_POLICY_NAME="${ILM_POLICY_NAME:-fos1-log-retention-14d}"
INDEX_TEMPLATE_NAME="${INDEX_TEMPLATE_NAME:-fos1-log-retention-template}"
SURICATA_LOG_PATH="${SURICATA_LOG_PATH:-/var/log/fos1/suricata/eve.json}"
EXPECTED_SECURITY_INDEX_PREFIX="${EXPECTED_SECURITY_INDEX_PREFIX:-fos1-security-}"

port_forward_pid=""
seeded_nodes=()
canary_id="ticket3-suricata-canary-$(date -u +%Y%m%d%H%M%S)-$$"
template_index="${EXPECTED_SECURITY_INDEX_PREFIX}template-canary-$(date -u +%Y%m%d%H%M%S)"
canary_timestamp="$(date -u +"%Y-%m-%dT%H:%M:%S.000+0000")"

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

  echo "Security log proof failed; collecting diagnostics..." >&2
  kubectl get pods -n "${MONITORING_NAMESPACE}" -o wide >&2 || true
  echo >&2

  if ((${#seeded_nodes[@]} > 0)); then
    for node in "${seeded_nodes[@]}"; do
      echo "--- Tail ${SURICATA_LOG_PATH} on node ${node} ---" >&2
      docker exec "${node}" sh -c "tail -n 5 '${SURICATA_LOG_PATH}'" >&2 || true
      echo >&2
    done
  fi

  echo "--- Fluentd logs ---" >&2
  kubectl logs -n "${MONITORING_NAMESPACE}" -l "${FLUENTD_SELECTOR}" --all-containers --tail=120 >&2 || true
  echo >&2

  if curl -fsS "${ELASTICSEARCH_URL}/_cluster/health" >/dev/null 2>&1; then
    echo "--- Elasticsearch cat indices ---" >&2
    curl -fsS "${ELASTICSEARCH_URL}/_cat/indices/${EXPECTED_SECURITY_INDEX_PREFIX}*?v=true" >&2 || true
    echo >&2

    echo "--- Elasticsearch canary search ---" >&2
    search_canary_document >&2 || true
    echo >&2
  fi
}

trap cleanup EXIT
trap 'print_diagnostics "$?"' ERR

start_port_forward() {
  kubectl port-forward -n "${MONITORING_NAMESPACE}" "service/${ELASTICSEARCH_SERVICE}" \
    "${ELASTICSEARCH_LOCAL_PORT}:9200" >/tmp/fos1-elasticsearch-port-forward.log 2>&1 &
  port_forward_pid="$!"
}

wait_for_elasticsearch() {
  local attempt

  for attempt in $(seq 1 30); do
    if curl -fsS "${ELASTICSEARCH_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null; then
      return 0
    fi
    sleep 2
  done

  echo "Elasticsearch did not become reachable through port-forward." >&2
  return 1
}

assert_ilm_policy() {
  local response

  response="$(curl -fsS "${ELASTICSEARCH_URL}/_ilm/policy/${ILM_POLICY_NAME}")"
  JSON_INPUT="${response}" python3 - "${ILM_POLICY_NAME}" <<'PY'
import json
import os
import sys

policy_name = sys.argv[1]
data = json.loads(os.environ["JSON_INPUT"])
policy = data.get(policy_name, {}).get("policy", {})
delete_phase = policy.get("phases", {}).get("delete", {})

if delete_phase.get("min_age") != "14d":
    raise SystemExit("missing 14d delete phase")
if "delete" not in delete_phase.get("actions", {}):
    raise SystemExit("missing delete action")
PY
}

assert_index_template() {
  local response

  response="$(curl -fsS "${ELASTICSEARCH_URL}/_index_template/${INDEX_TEMPLATE_NAME}")"
  JSON_INPUT="${response}" python3 - "${INDEX_TEMPLATE_NAME}" "${ILM_POLICY_NAME}" <<'PY'
import json
import os
import sys

template_name = sys.argv[1]
policy_name = sys.argv[2]
data = json.loads(os.environ["JSON_INPUT"])
templates = data.get("index_templates", [])

if len(templates) != 1:
    raise SystemExit("unexpected index template count")

index_template = templates[0]
if index_template.get("name") != template_name:
    raise SystemExit("unexpected template name")

template = index_template.get("index_template", {})
patterns = set(template.get("index_patterns", []))
if {"fos1-security-*", "fos1-logs-*"} - patterns:
    raise SystemExit("missing index pattern")

settings = template.get("template", {}).get("settings", {})
if settings.get("index.lifecycle.name") == policy_name:
    sys.exit(0)

index_settings = settings.get("index", {})
lifecycle = index_settings.get("lifecycle", {})
if lifecycle.get("name") != policy_name:
    raise SystemExit("missing lifecycle name")

replicas = settings.get("index.number_of_replicas")
if replicas is None:
    replicas = index_settings.get("number_of_replicas")
if replicas not in (0, "0"):
    raise SystemExit("unexpected replica count")

shards = settings.get("index.number_of_shards")
if shards is None:
    shards = index_settings.get("number_of_shards")
if shards not in (1, "1"):
    raise SystemExit("unexpected shard count")
PY
}

seed_suricata_canary() {
  local event_json
  local node

  event_json="$(cat <<EOF
{"timestamp":"${canary_timestamp}","event_type":"alert","src_ip":"192.0.2.10","src_port":40000,"dest_ip":"198.51.100.20","dest_port":443,"proto":"TCP","canary_id":"${canary_id}","canary_name":"ticket-3-suricata-log-proof","alert":{"signature_id":9900001,"signature":"FOS1 Ticket 3 Suricata canary","category":"Test Event","severity":3}}
EOF
)"

  seeded_nodes=()
  while IFS= read -r node; do
    if [[ -n "${node}" ]]; then
      seeded_nodes+=("${node}")
    fi
  done < <(
    kubectl get pods -n "${MONITORING_NAMESPACE}" -l "${FLUENTD_SELECTOR}" \
      -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | sort -u
  )

  if ((${#seeded_nodes[@]} == 0)); then
    echo "No Fluentd pods found in namespace ${MONITORING_NAMESPACE}." >&2
    return 1
  fi

  for node in "${seeded_nodes[@]}"; do
    echo "Seeding Suricata canary ${canary_id} on node ${node}:${SURICATA_LOG_PATH}"
    printf '%s\n' "${event_json}" | docker exec -i "${node}" sh -c \
      "mkdir -p \"$(dirname "${SURICATA_LOG_PATH}")\" && cat >> \"${SURICATA_LOG_PATH}\""
  done
}

restart_fluentd() {
  echo "Restarting Fluentd after Elasticsearch readiness to clear any early backoff state"
  kubectl rollout restart daemonset/fluentd -n "${FLUENTD_NAMESPACE}"
  kubectl rollout status daemonset/fluentd -n "${FLUENTD_NAMESPACE}" --timeout=240s
}

search_canary_document() {
  local search_body

  search_body="$(cat <<EOF
{
  "size": 5,
  "query": {
    "bool": {
      "must": [
        {"match_phrase": {"canary_id": "${canary_id}"}},
        {"match_phrase": {"security_sensor": "suricata"}},
        {"match_phrase": {"event_type": "alert"}}
      ]
    }
  }
}
EOF
)"

  curl -fsS -X POST \
    "${ELASTICSEARCH_URL}/${EXPECTED_SECURITY_INDEX_PREFIX}*/_search?allow_no_indices=true&ignore_unavailable=true" \
    -H "Content-Type: application/json" \
    --data-binary "${search_body}"
}

wait_for_canary_document() {
  local attempt
  local response

  for attempt in $(seq 1 24); do
    response="$(search_canary_document)"
    if JSON_INPUT="${response}" python3 - <<'PY' >/dev/null
import json
import os

data = json.loads(os.environ["JSON_INPUT"])
hits = data.get("hits", {}).get("hits", [])
raise SystemExit(0 if hits else 1)
PY
    then
      printf '%s' "${response}"
      return 0
    fi

    sleep 5
  done

  echo "Timed out waiting for canary ${canary_id} to arrive in ${EXPECTED_SECURITY_INDEX_PREFIX}*." >&2
  return 1
}

assert_canary_document() {
  local response="$1"

  JSON_INPUT="${response}" python3 - "${canary_id}" "${SURICATA_LOG_PATH}" "${EXPECTED_SECURITY_INDEX_PREFIX}" <<'PY'
import json
import os
import sys

canary_id = sys.argv[1]
log_path = sys.argv[2]
index_prefix = sys.argv[3]
data = json.loads(os.environ["JSON_INPUT"])
hits = data.get("hits", {}).get("hits", [])

if not hits:
    raise SystemExit("canary document missing")

hit = hits[0]
source = hit.get("_source", {})

expected_pairs = {
    "canary_id": canary_id,
    "security_sensor": "suricata",
    "event_type": "alert",
    "log_contract": log_path,
}

for key, value in expected_pairs.items():
    if source.get(key) != value:
        raise SystemExit(f"unexpected {key}: {source.get(key)!r}")

index_name = hit.get("_index", "")
if not index_name.startswith(index_prefix):
    raise SystemExit(f"unexpected index {index_name}")
PY
}

create_template_canary_document() {
  curl -fsS -X POST \
    "${ELASTICSEARCH_URL}/${template_index}/_doc/template-proof?refresh=true" \
    -H "Content-Type: application/json" \
    --data-binary "{\"canary_id\":\"${canary_id}\",\"proof\":\"template-attachment\"}" >/dev/null
}

assert_template_canary_settings() {
  local response

  response="$(curl -fsS "${ELASTICSEARCH_URL}/${template_index}/_settings?flat_settings=true")"
  JSON_INPUT="${response}" python3 - "${template_index}" "${ILM_POLICY_NAME}" <<'PY'
import json
import os
import sys

index_name = sys.argv[1]
policy_name = sys.argv[2]
data = json.loads(os.environ["JSON_INPUT"])
settings = data.get(index_name, {}).get("settings", {})

if settings.get("index.lifecycle.name") == policy_name:
    sys.exit(0)

index_settings = settings.get("index", {})
lifecycle = index_settings.get("lifecycle", {})
if lifecycle.get("name") != policy_name:
    raise SystemExit("template canary missing lifecycle name")

replicas = settings.get("index.number_of_replicas")
if replicas is None:
    replicas = index_settings.get("number_of_replicas")
if replicas != "0":
    raise SystemExit("template canary replicas mismatch")

shards = settings.get("index.number_of_shards")
if shards is None:
    shards = index_settings.get("number_of_shards")
if shards != "1":
    raise SystemExit("template canary shards mismatch")
PY
}

main() {
  local canary_response

  echo "Starting Elasticsearch proof against ${ELASTICSEARCH_SERVICE}.${MONITORING_NAMESPACE}"
  start_port_forward
  wait_for_elasticsearch

  echo "Checking ILM bootstrap artifacts"
  assert_ilm_policy
  assert_index_template

  restart_fluentd

  echo "Seeding deterministic Suricata canary into ${SURICATA_LOG_PATH}"
  seed_suricata_canary

  echo "Waiting for canary ${canary_id} to appear in ${EXPECTED_SECURITY_INDEX_PREFIX}*"
  canary_response="$(wait_for_canary_document)"
  assert_canary_document "${canary_response}"

  echo "Creating template-backed canary index ${template_index}"
  create_template_canary_document
  assert_template_canary_settings

  echo "Security log proof succeeded:"
  echo "  canary_id=${canary_id}"
  echo "  security_index_prefix=${EXPECTED_SECURITY_INDEX_PREFIX}"
  echo "  ilm_policy=${ILM_POLICY_NAME}"
  echo "  index_template=${INDEX_TEMPLATE_NAME}"
  echo "  template_canary_index=${template_index}"
}

main "$@"
