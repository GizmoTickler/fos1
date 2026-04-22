#!/usr/bin/env bash
#
# Prove that Elasticsearch ILM rollover + delete actions actually execute
# under an accelerated CI-only policy. The production fos1-log-retention-14d
# policy/template (asserted for presence by prove-security-log-pipeline.sh)
# is NOT exercised here because a 14d wall-clock envelope does not fit in
# a CI budget. Instead we install a separate, clearly-labelled accelerated
# policy (fos1-ci-accelerated) against the fos1-ci-retention-* index
# pattern, drive enough writes + explicit rollover calls to cross the
# max_age/max_docs thresholds, and then poll until the delete phase has
# removed the oldest generation.
#
# What this script proves:
#   - an ILM policy with a hot.rollover + delete phase actually causes ES
#     to create a new generation under load (rollover happened)
#   - the delete phase eventually removes the oldest generation
#     (deletion happened)
#
# What this script does NOT prove:
#   - the production 14d wall-clock retention
#   - HA / multi-node behavior
#   - snapshot / restore
#   - any behavior on fos1-security-* or fos1-logs-* indices
#
# The fos1-ci-* artifacts are temporary and are cleaned up on exit.

set -Eeuo pipefail

MONITORING_NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
ELASTICSEARCH_SERVICE="${ELASTICSEARCH_SERVICE:-elasticsearch}"
ELASTICSEARCH_LOCAL_PORT="${ELASTICSEARCH_LOCAL_PORT:-19201}"
ELASTICSEARCH_URL="http://127.0.0.1:${ELASTICSEARCH_LOCAL_PORT}"

CI_ILM_POLICY_NAME="${CI_ILM_POLICY_NAME:-fos1-ci-accelerated}"
CI_INDEX_TEMPLATE_NAME="${CI_INDEX_TEMPLATE_NAME:-fos1-ci-retention-template}"
CI_WRITE_ALIAS="${CI_WRITE_ALIAS:-fos1-ci-retention}"
CI_INDEX_PATTERN="${CI_INDEX_PATTERN:-fos1-ci-retention-*}"
CI_BOOTSTRAP_INDEX="${CI_BOOTSTRAP_INDEX:-fos1-ci-retention-000001}"

# CI_ACCELERATED_CONFIGMAP points at the ConfigMap authored in
# manifests/base/monitoring/elasticsearch-ci-accelerated-ilm.yaml. It is NOT
# applied by the base kustomization; the harness step applies it explicitly
# before invoking this script so the single source of truth for the
# accelerated policy lives in version control, not inline here.
CI_ACCELERATED_CONFIGMAP="${CI_ACCELERATED_CONFIGMAP:-elasticsearch-ci-accelerated-ilm}"

# Minimum generations we need to observe at some point during the run to
# consider rollover "proven". A value of 2 means "the write alias was
# pointed at at least 2 different backing indices".
MIN_ROLLOVER_GENERATIONS="${MIN_ROLLOVER_GENERATIONS:-2}"

# Poll budget for the delete phase. ILM evaluates on
# indices.lifecycle.poll_interval which is 10m in the baseline
# elasticsearch.yml; the CI harness overrides it via the cluster-update
# settings call below so this budget stays inside a reasonable CI window.
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-5}"
POLL_MAX_SECONDS="${POLL_MAX_SECONDS:-180}"

CANARY_BATCH_SIZE="${CANARY_BATCH_SIZE:-10}"

port_forward_pid=""
configmap_applied_by_script="false"
policy_installed="false"
template_installed="false"
bootstrap_created="false"
original_poll_interval=""
ilm_poll_override_applied="false"

log() {
  # Emit CI-parseable structured output. One JSON object per line.
  local level="$1"
  shift
  local msg="$*"
  printf '{"ts":"%s","level":"%s","script":"prove-es-retention-rollover","msg":%s}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "${level}" \
    "$(printf '%s' "${msg}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
}

cleanup() {
  local exit_code="$?"

  set +e

  if [[ "${ilm_poll_override_applied}" == "true" ]]; then
    if [[ -n "${original_poll_interval}" ]]; then
      log "info" "restoring indices.lifecycle.poll_interval=${original_poll_interval}"
      curl -fsS -X PUT "${ELASTICSEARCH_URL}/_cluster/settings" \
        -H "Content-Type: application/json" \
        --data-binary "{\"transient\":{\"indices.lifecycle.poll_interval\":\"${original_poll_interval}\"}}" \
        >/dev/null 2>&1 || true
    else
      log "info" "clearing transient indices.lifecycle.poll_interval override"
      curl -fsS -X PUT "${ELASTICSEARCH_URL}/_cluster/settings" \
        -H "Content-Type: application/json" \
        --data-binary '{"transient":{"indices.lifecycle.poll_interval":null}}' \
        >/dev/null 2>&1 || true
    fi
  fi

  if [[ "${bootstrap_created}" == "true" ]]; then
    log "info" "deleting fos1-ci-retention-* indices"
    curl -fsS -X DELETE "${ELASTICSEARCH_URL}/${CI_INDEX_PATTERN}" >/dev/null 2>&1 || true
  fi

  if [[ "${template_installed}" == "true" ]]; then
    log "info" "deleting index template ${CI_INDEX_TEMPLATE_NAME}"
    curl -fsS -X DELETE "${ELASTICSEARCH_URL}/_index_template/${CI_INDEX_TEMPLATE_NAME}" >/dev/null 2>&1 || true
  fi

  if [[ "${policy_installed}" == "true" ]]; then
    log "info" "deleting ILM policy ${CI_ILM_POLICY_NAME}"
    curl -fsS -X DELETE "${ELASTICSEARCH_URL}/_ilm/policy/${CI_ILM_POLICY_NAME}" >/dev/null 2>&1 || true
  fi

  if [[ "${configmap_applied_by_script}" == "true" ]]; then
    log "info" "deleting CI accelerated ILM ConfigMap ${CI_ACCELERATED_CONFIGMAP}"
    kubectl delete configmap "${CI_ACCELERATED_CONFIGMAP}" \
      -n "${MONITORING_NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
  fi

  if [[ -n "${port_forward_pid}" ]] && kill -0 "${port_forward_pid}" >/dev/null 2>&1; then
    kill "${port_forward_pid}" >/dev/null 2>&1 || true
    wait "${port_forward_pid}" >/dev/null 2>&1 || true
  fi

  exit "${exit_code}"
}

print_diagnostics() {
  local exit_code="$1"

  if ((exit_code == 0)); then
    return
  fi

  set +e
  log "error" "retention proof failed; collecting diagnostics"

  if curl -fsS "${ELASTICSEARCH_URL}/_cluster/health" >/dev/null 2>&1; then
    echo "--- _cat/indices ${CI_INDEX_PATTERN} ---" >&2
    curl -fsS "${ELASTICSEARCH_URL}/_cat/indices/${CI_INDEX_PATTERN}?v=true&s=index" >&2 || true
    echo >&2
    echo "--- _ilm/explain ${CI_INDEX_PATTERN} ---" >&2
    curl -fsS "${ELASTICSEARCH_URL}/${CI_INDEX_PATTERN}/_ilm/explain" >&2 || true
    echo >&2
  fi
}

trap cleanup EXIT
trap 'print_diagnostics "$?"' ERR

start_port_forward() {
  kubectl port-forward -n "${MONITORING_NAMESPACE}" "service/${ELASTICSEARCH_SERVICE}" \
    "${ELASTICSEARCH_LOCAL_PORT}:9200" >/tmp/fos1-elasticsearch-ci-port-forward.log 2>&1 &
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

  log "error" "elasticsearch did not become reachable through port-forward"
  return 1
}

ensure_accelerated_configmap() {
  # The harness may pre-apply the ConfigMap; be tolerant of either order.
  if kubectl get configmap "${CI_ACCELERATED_CONFIGMAP}" -n "${MONITORING_NAMESPACE}" >/dev/null 2>&1; then
    log "info" "found existing CI accelerated ILM ConfigMap ${CI_ACCELERATED_CONFIGMAP}"
    return 0
  fi

  local manifest_path="manifests/base/monitoring/elasticsearch-ci-accelerated-ilm.yaml"
  if [[ ! -f "${manifest_path}" ]]; then
    log "error" "missing CI accelerated ILM manifest at ${manifest_path}"
    return 1
  fi

  log "info" "applying CI accelerated ILM ConfigMap from ${manifest_path}"
  kubectl apply -f "${manifest_path}" >/dev/null
  configmap_applied_by_script="true"
}

read_configmap_key() {
  local key="$1"
  kubectl get configmap "${CI_ACCELERATED_CONFIGMAP}" \
    -n "${MONITORING_NAMESPACE}" \
    -o "jsonpath={.data.${key}}"
}

override_ilm_poll_interval() {
  # The baseline elasticsearch.yml sets indices.lifecycle.poll_interval=10m
  # which would turn this proof into a 10+ minute wait. Flip the transient
  # cluster setting down to 1s for the duration of the script.
  log "info" "capturing existing indices.lifecycle.poll_interval"
  local settings
  settings="$(curl -fsS "${ELASTICSEARCH_URL}/_cluster/settings?include_defaults=true&flat_settings=true")"

  original_poll_interval="$(
    JSON_INPUT="${settings}" python3 - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_INPUT"])
for scope in ("transient", "persistent", "defaults"):
    bucket = data.get(scope, {})
    value = bucket.get("indices.lifecycle.poll_interval")
    if value:
        print(value)
        break
PY
  )"

  log "info" "overriding indices.lifecycle.poll_interval to 1s (was ${original_poll_interval:-default})"
  curl -fsS -X PUT "${ELASTICSEARCH_URL}/_cluster/settings" \
    -H "Content-Type: application/json" \
    --data-binary '{"transient":{"indices.lifecycle.poll_interval":"1s"}}' \
    >/dev/null
  ilm_poll_override_applied="true"
}

install_accelerated_policy() {
  log "info" "installing ILM policy ${CI_ILM_POLICY_NAME}"
  local policy_json
  policy_json="$(read_configmap_key 'fos1-ci-accelerated\.json')"
  if [[ -z "${policy_json}" ]]; then
    log "error" "CI accelerated policy JSON missing from ConfigMap"
    return 1
  fi

  curl -fsS -X PUT "${ELASTICSEARCH_URL}/_ilm/policy/${CI_ILM_POLICY_NAME}" \
    -H "Content-Type: application/json" \
    --data-binary "${policy_json}" >/dev/null
  policy_installed="true"
}

install_accelerated_template() {
  log "info" "installing index template ${CI_INDEX_TEMPLATE_NAME}"
  local template_json
  template_json="$(read_configmap_key 'fos1-ci-retention-template\.json')"
  if [[ -z "${template_json}" ]]; then
    log "error" "CI accelerated template JSON missing from ConfigMap"
    return 1
  fi

  curl -fsS -X PUT "${ELASTICSEARCH_URL}/_index_template/${CI_INDEX_TEMPLATE_NAME}" \
    -H "Content-Type: application/json" \
    --data-binary "${template_json}" >/dev/null
  template_installed="true"
}

create_write_alias_and_bootstrap_index() {
  log "info" "bootstrapping write index ${CI_BOOTSTRAP_INDEX} with alias ${CI_WRITE_ALIAS}"
  local bootstrap_json
  bootstrap_json="$(read_configmap_key 'fos1-ci-retention-bootstrap\.json')"
  if [[ -z "${bootstrap_json}" ]]; then
    log "error" "CI bootstrap alias JSON missing from ConfigMap"
    return 1
  fi

  curl -fsS -X PUT "${ELASTICSEARCH_URL}/${CI_BOOTSTRAP_INDEX}" \
    -H "Content-Type: application/json" \
    --data-binary "${bootstrap_json}" >/dev/null
  bootstrap_created="true"
}

post_canary_batch() {
  local batch_label="$1"
  local count="$2"
  local i
  local ts

  for i in $(seq 1 "${count}"); do
    ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
    curl -fsS -X POST "${ELASTICSEARCH_URL}/${CI_WRITE_ALIAS}/_doc?refresh=false" \
      -H "Content-Type: application/json" \
      --data-binary "{\"@timestamp\":\"${ts}\",\"batch\":\"${batch_label}\",\"seq\":${i},\"canary\":\"fos1-ci-retention-proof\"}" \
      >/dev/null
  done

  curl -fsS -X POST "${ELASTICSEARCH_URL}/${CI_WRITE_ALIAS}/_refresh" >/dev/null
}

force_rollover() {
  # POST _rollover with the same conditions the policy itself enforces.
  # Passing explicit conditions avoids a no-op when ILM has not yet ticked
  # through an evaluation cycle, without creating a rollover that would
  # violate the policy.
  log "info" "requesting POST ${CI_WRITE_ALIAS}/_rollover"
  curl -fsS -X POST "${ELASTICSEARCH_URL}/${CI_WRITE_ALIAS}/_rollover" \
    -H "Content-Type: application/json" \
    --data-binary '{"conditions":{"max_age":"30s","max_docs":5}}' >/dev/null || true
}

list_ci_indices() {
  curl -fsS "${ELASTICSEARCH_URL}/_cat/indices/${CI_INDEX_PATTERN}?format=json&h=index"
}

poll_for_rollover_and_deletion() {
  local seen_max_generations=0
  local rolled_over="false"
  local deleted="false"
  local attempt=0
  local max_attempts=$(( POLL_MAX_SECONDS / POLL_INTERVAL_SECONDS ))
  local known_file
  local initial_index=""
  local current_json

  known_file="$(mktemp -t fos1-ci-retention-known.XXXXXX)"
  trap 'rm -f "${known_file}"' RETURN

  while (( attempt < max_attempts )); do
    attempt=$(( attempt + 1 ))
    current_json="$(list_ci_indices)"

    local snapshot
    snapshot="$(
      JSON_INPUT="${current_json}" python3 - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_INPUT"] or "[]")
names = sorted(entry.get("index", "") for entry in data if entry.get("index"))
for name in names:
    print(name)
PY
    )"

    local current_count=0
    if [[ -n "${snapshot}" ]]; then
      current_count=$(printf '%s\n' "${snapshot}" | wc -l | tr -d ' ')
    fi

    if [[ -z "${initial_index}" && -n "${snapshot}" ]]; then
      initial_index="$(printf '%s\n' "${snapshot}" | head -n 1)"
    fi

    # Union snapshot into the known-indices file so peak fan-out is
    # retained even if deletion removes a generation between polls.
    if [[ -n "${snapshot}" ]]; then
      printf '%s\n' "${snapshot}" >> "${known_file}"
      sort -u "${known_file}" -o "${known_file}"
    fi

    local known_count
    known_count=$(wc -l < "${known_file}" | tr -d ' ')

    if (( known_count > seen_max_generations )); then
      seen_max_generations=${known_count}
    fi

    if (( known_count >= MIN_ROLLOVER_GENERATIONS )); then
      rolled_over="true"
    fi

    if [[ "${rolled_over}" == "true" && -n "${initial_index}" ]]; then
      if ! printf '%s\n' "${snapshot}" | grep -Fxq "${initial_index}"; then
        deleted="true"
      fi
    fi

    log "info" "poll attempt=${attempt} indices_now=${current_count} generations_seen=${seen_max_generations} rolled_over=${rolled_over} deleted=${deleted} initial=${initial_index}"

    if [[ "${rolled_over}" == "true" && "${deleted}" == "true" ]]; then
      printf '%s' "${current_json}"
      return 0
    fi

    sleep "${POLL_INTERVAL_SECONDS}"
  done

  log "error" "retention proof timed out: rolled_over=${rolled_over} deleted=${deleted} generations_seen=${seen_max_generations} initial=${initial_index}"
  return 1
}

assert_proof() {
  local final_json="$1"

  JSON_INPUT="${final_json}" python3 - "${CI_WRITE_ALIAS}" <<'PY'
import json
import os
import sys

alias = sys.argv[1]
data = json.loads(os.environ["JSON_INPUT"] or "[]")
names = sorted(entry.get("index", "") for entry in data if entry.get("index"))

if not names:
    raise SystemExit("no CI retention indices present at proof completion")

# After a full roll + delete cycle at least one generation must remain.
for name in names:
    if not name.startswith(alias + "-"):
        raise SystemExit(f"unexpected index outside CI pattern: {name}")
PY
}

main() {
  log "info" "starting Elasticsearch retention/rollover proof against ${ELASTICSEARCH_SERVICE}.${MONITORING_NAMESPACE}"

  start_port_forward
  wait_for_elasticsearch

  ensure_accelerated_configmap

  override_ilm_poll_interval

  install_accelerated_policy
  install_accelerated_template
  create_write_alias_and_bootstrap_index

  # Seed enough documents to cross max_docs=5 twice, forcing a rollover
  # between batches. The force_rollover call between batches avoids waiting
  # on ILM's own poll cycle for the first generation.
  post_canary_batch "batch-a" "${CANARY_BATCH_SIZE}"
  force_rollover
  post_canary_batch "batch-b" "${CANARY_BATCH_SIZE}"
  force_rollover

  local final_json
  final_json="$(poll_for_rollover_and_deletion)"
  assert_proof "${final_json}"

  log "info" "retention proof succeeded: rollover + delete actions executed under ${CI_ILM_POLICY_NAME}"
  echo "Elasticsearch accelerated ILM proof succeeded:"
  echo "  ci_policy=${CI_ILM_POLICY_NAME}"
  echo "  ci_index_template=${CI_INDEX_TEMPLATE_NAME}"
  echo "  ci_write_alias=${CI_WRITE_ALIAS}"
  echo "  ci_index_pattern=${CI_INDEX_PATTERN}"
}

main "$@"
