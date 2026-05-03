#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${repo_root}/scripts/ci/prove-prometheus-scrapes.sh"

active_targets_json="$(cat <<'EOF'
{
  "status": "success",
  "data": {
    "activeTargets": [
      {
        "scrapePool": "fos1-dpi-manager-pods",
        "health": "up",
        "labels": {
          "app": "dpi-manager",
          "kubernetes_namespace": "security",
          "kubernetes_pod_name": "dpi-manager-node-a"
        }
      },
      {
        "scrapePool": "fos1-dpi-manager-pods",
        "health": "up",
        "labels": {
          "app": "dpi-manager",
          "kubernetes_namespace": "security",
          "kubernetes_pod_name": "dpi-manager-node-b"
        }
      },
      {
        "scrapePool": "fos1-ntp-controller-pods",
        "health": "up",
        "labels": {
          "app": "ntp-controller",
          "kubernetes_namespace": "network",
          "kubernetes_pod_name": "ntp-controller-abc123"
        }
      }
    ]
  }
}
EOF
)"

up_query_json="$(cat <<'EOF'
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [
      {
        "metric": {
          "app": "dpi-manager",
          "kubernetes_namespace": "security",
          "kubernetes_pod_name": "dpi-manager-node-a"
        },
        "value": [1710000000.0, "1"]
      },
      {
        "metric": {
          "app": "dpi-manager",
          "kubernetes_namespace": "security",
          "kubernetes_pod_name": "dpi-manager-node-b"
        },
        "value": [1710000000.0, "1"]
      },
      {
        "metric": {
          "app": "ntp-controller",
          "kubernetes_namespace": "network",
          "kubernetes_pod_name": "ntp-controller-abc123"
        },
        "value": [1710000000.0, "1"]
      }
    ]
  }
}
EOF
)"

JSON_INPUT="${active_targets_json}" assert_active_targets_json security dpi-manager "dpi-manager-node-a,dpi-manager-node-b" "fos1-dpi-manager-pods"
JSON_INPUT="${active_targets_json}" assert_active_targets_json network ntp-controller "ntp-controller-abc123" "fos1-ntp-controller-pods"
JSON_INPUT="${up_query_json}" assert_up_query_json security dpi-manager "dpi-manager-node-a,dpi-manager-node-b"
JSON_INPUT="${up_query_json}" assert_up_query_json network ntp-controller "ntp-controller-abc123"

echo "Prometheus proof parser tests passed."
