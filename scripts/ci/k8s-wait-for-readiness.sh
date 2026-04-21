#!/usr/bin/env bash

set -euo pipefail

if (($# < 2)); then
  echo "usage: $0 <namespace> <timeout> [require_workloads]" >&2
  exit 1
fi

namespace="$1"
timeout="$2"
require_workloads="${3:-false}"

workloads=()
while IFS= read -r workload; do
  if [[ -n "${workload}" ]]; then
    workloads+=("${workload}")
  fi
done < <(
  kubectl get deployments,daemonsets,statefulsets -n "${namespace}" \
    -o jsonpath='{range .items[*]}{.kind}{"/"}{.metadata.name}{"\n"}{end}'
)

if ((${#workloads[@]} == 0)); then
  if [[ "${require_workloads}" == "true" ]]; then
    echo "No workloads found in namespace ${namespace}." >&2
    exit 1
  fi

  echo "No workloads found in namespace ${namespace}; skipping readiness gate."
  exit 0
fi

for workload in "${workloads[@]}"; do
  kind="${workload%%/*}"
  name="${workload##*/}"

  case "${kind}" in
    Deployment)
      resource="deployment/${name}"
      ;;
    DaemonSet)
      resource="daemonset/${name}"
      ;;
    StatefulSet)
      resource="statefulset/${name}"
      ;;
    *)
      echo "Unsupported workload kind ${kind} in namespace ${namespace}." >&2
      exit 1
      ;;
  esac

  echo "Waiting for ${resource} in namespace ${namespace} (timeout: ${timeout})"
  if ! kubectl rollout status "${resource}" -n "${namespace}" --timeout="${timeout}"; then
    echo "Readiness gate failed for ${resource} in namespace ${namespace}." >&2
    kubectl describe "${resource}" -n "${namespace}"
    exit 1
  fi
done

kubectl get deployments,daemonsets,statefulsets -n "${namespace}"
