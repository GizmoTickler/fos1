#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "${repo_root}" <<'PY'
from pathlib import Path
import sys

repo = Path(sys.argv[1])
prometheus = repo / "manifests/base/monitoring/prometheus.yaml"
certificate = repo / "manifests/base/monitoring/prometheus-client-cert.yaml"
kustomization = repo / "manifests/base/monitoring/kustomization.yaml"
dpi = repo / "manifests/base/security/dpi-manager.yaml"
ntp = repo / "manifests/base/ntp/ntp-controller.yaml"

required_files = [prometheus, certificate, kustomization, dpi, ntp]
missing = [str(path.relative_to(repo)) for path in required_files if not path.exists()]
if missing:
    raise SystemExit("missing required manifest(s): " + ", ".join(missing))

prometheus_text = prometheus.read_text()
certificate_text = certificate.read_text()
kustomization_text = kustomization.read_text()
dpi_text = dpi.read_text()
ntp_text = ntp.read_text()


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise SystemExit(f"{label} missing {needle!r}")


def job_block(config: str, job_name: str) -> str:
    marker = f"- job_name: '{job_name}'"
    start = config.find(marker)
    if start == -1:
        raise SystemExit(f"prometheus config missing job {job_name!r}")
    next_job = config.find("\n      - job_name:", start + len(marker))
    if next_job == -1:
        return config[start:]
    return config[start:next_job]


require(kustomization_text, "- prometheus-client-cert.yaml", "monitoring kustomization")

for needle in [
    "kind: Certificate",
    "name: prometheus-client-tls",
    "namespace: monitoring",
    "secretName: prometheus-client-tls",
    "commonName: prometheus",
    "- client auth",
    "name: fos1-internal-ca",
    "kind: ClusterIssuer",
]:
    require(certificate_text, needle, "prometheus client certificate")

for needle in [
    "mountPath: /var/run/secrets/fos1.io/prometheus-client",
    "secretName: prometheus-client-tls",
]:
    require(prometheus_text, needle, "prometheus deployment")

common_tls = [
    "scheme: https",
    "ca_file: /var/run/secrets/fos1.io/prometheus-client/ca.crt",
    "cert_file: /var/run/secrets/fos1.io/prometheus-client/tls.crt",
    "key_file: /var/run/secrets/fos1.io/prometheus-client/tls.key",
]

for job_name, server_name in [
    ("fos1-dpi-manager-pods", "dpi-manager.security.svc"),
    ("fos1-ntp-controller-pods", "ntp-controller.network.svc"),
]:
    block = job_block(prometheus_text, job_name)
    for needle in common_tls:
        require(block, needle, f"prometheus job {job_name}")
    require(block, f"server_name: {server_name}", f"prometheus job {job_name}")

for manifest_text, label in [(dpi_text, "dpi-manager"), (ntp_text, "ntp-controller")]:
    require(manifest_text, "prometheus.io/scrape:", label)
    require(manifest_text, "prometheus.io/scheme: https", label)

print("Prometheus internal CA rekey manifest checks passed.")
PY
