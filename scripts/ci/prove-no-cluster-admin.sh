#!/usr/bin/env bash
# prove-no-cluster-admin.sh
#
# Sprint 30 / Ticket 42: RBAC ClusterRoles Minimum-Privilege Baseline.
#
# Scans every YAML file under manifests/ (and test-manifests/ when present)
# and fails if any ClusterRoleBinding references the cluster-admin ClusterRole
# *without* an explicit exception annotation.
#
# An explicit exception is declared on the ClusterRoleBinding object with:
#   metadata:
#     annotations:
#       fos1.io/rbac-exception: "<reason>"
# The reason must be present and non-empty; the scanner records it for audit.
#
# Exit codes:
#   0 - no offenders
#   1 - one or more bindings reference cluster-admin without the annotation
#   2 - script usage / environment error

set -euo pipefail

SCRIPT_NAME=$(basename "$0")
REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

# Directories to scan. test-manifests/ is optional and scanned only if present.
SCAN_DIRS=("${REPO_ROOT}/manifests")
if [[ -d "${REPO_ROOT}/test-manifests" ]]; then
  SCAN_DIRS+=("${REPO_ROOT}/test-manifests")
fi

# Allow callers to inject additional directories (used in negative tests).
if [[ "${EXTRA_SCAN_DIRS:-}" != "" ]]; then
  # shellcheck disable=SC2206
  EXTRA=(${EXTRA_SCAN_DIRS})
  SCAN_DIRS+=("${EXTRA[@]}")
fi

printf '[%s] scanning:\n' "${SCRIPT_NAME}"
for d in "${SCAN_DIRS[@]}"; do
  printf '  - %s\n' "${d}"
done

# Collect YAML files.
FILES=()
while IFS= read -r -d '' f; do
  FILES+=("${f}")
done < <(find "${SCAN_DIRS[@]}" -type f \( -name '*.yaml' -o -name '*.yml' \) -print0 2>/dev/null)

if [[ "${#FILES[@]}" -eq 0 ]]; then
  printf '[%s] no YAML files found under scan dirs — nothing to check.\n' "${SCRIPT_NAME}"
  exit 0
fi

# awk program: walk through each file, split on `---`, identify
# ClusterRoleBinding docs, check roleRef.name and the exception annotation.
AWK_PROG=$(cat <<'AWK'
# Reset per-document state.
function reset_doc() {
  kind = ""
  role_ref_seen = 0
  in_role_ref = 0
  role_ref_indent = -1
  role_ref_name = ""
  in_annotations = 0
  annotations_indent = -1
  exception_reason = ""
  crb_name = ""
  in_metadata = 0
  metadata_indent = -1
}

BEGIN {
  reset_doc()
}

# Strip a trailing newline already; compute indent of current line.
{
  line = $0
  # indent = count of leading spaces
  match(line, /^[ ]*/)
  indent = RLENGTH
  stripped = substr(line, indent + 1)

  # Document separator.
  if (stripped ~ /^---([[:space:]]|$)/ || stripped == "---") {
    finalize_doc()
    reset_doc()
    next
  }

  # Track top-level kind (indent == 0).
  if (indent == 0 && stripped ~ /^kind:[[:space:]]/) {
    sub(/^kind:[[:space:]]*/, "", stripped)
    gsub(/[[:space:]]+$/, "", stripped)
    # Strip quotes.
    gsub(/^"|"$/, "", stripped)
    gsub(/^'|'$/, "", stripped)
    kind = stripped
    next
  }

  # Track metadata block (top-level).
  if (indent == 0 && stripped ~ /^metadata:[[:space:]]*$/) {
    in_metadata = 1
    metadata_indent = indent
    in_annotations = 0
    next
  }
  if (in_metadata && indent <= metadata_indent && stripped !~ /^[[:space:]]*$/) {
    # Exited metadata block.
    in_metadata = 0
    in_annotations = 0
  }

  # Detect binding name (metadata.name).
  if (in_metadata && indent == metadata_indent + 2 && stripped ~ /^name:[[:space:]]/) {
    v = stripped
    sub(/^name:[[:space:]]*/, "", v)
    gsub(/[[:space:]]+$/, "", v)
    gsub(/^"|"$/, "", v)
    gsub(/^'|'$/, "", v)
    crb_name = v
  }

  # Detect annotations block inside metadata.
  if (in_metadata && indent == metadata_indent + 2 && stripped ~ /^annotations:[[:space:]]*$/) {
    in_annotations = 1
    annotations_indent = indent
    next
  }
  if (in_annotations && indent <= annotations_indent && stripped !~ /^[[:space:]]*$/) {
    in_annotations = 0
  }

  # Detect the exception annotation.
  if (in_annotations && indent > annotations_indent) {
    if (stripped ~ /^fos1\.io\/rbac-exception:[[:space:]]/) {
      v = stripped
      sub(/^fos1\.io\/rbac-exception:[[:space:]]*/, "", v)
      gsub(/[[:space:]]+$/, "", v)
      gsub(/^"|"$/, "", v)
      gsub(/^'|'$/, "", v)
      exception_reason = v
    }
  }

  # Track roleRef block (top-level).
  if (indent == 0 && stripped ~ /^roleRef:[[:space:]]*$/) {
    in_role_ref = 1
    role_ref_indent = indent
    role_ref_seen = 1
    next
  }
  if (in_role_ref && indent <= role_ref_indent && stripped !~ /^[[:space:]]*$/) {
    in_role_ref = 0
  }
  if (in_role_ref && indent > role_ref_indent && stripped ~ /^name:[[:space:]]/) {
    v = stripped
    sub(/^name:[[:space:]]*/, "", v)
    gsub(/[[:space:]]+$/, "", v)
    gsub(/^"|"$/, "", v)
    gsub(/^'|'$/, "", v)
    role_ref_name = v
  }
}

END { finalize_doc() }

function finalize_doc() {
  if (kind != "ClusterRoleBinding") return
  if (role_ref_name != "cluster-admin") return

  # cluster-admin binding — check for exception.
  if (exception_reason == "") {
    printf "OFFENDER\t%s\t%s\t%s\n", FILENAME, crb_name, "missing fos1.io/rbac-exception annotation"
  } else {
    printf "ALLOWED\t%s\t%s\t%s\n", FILENAME, crb_name, exception_reason
  }
}
AWK
)

OFFENDERS=0
ALLOWED=0

for f in "${FILES[@]}"; do
  # Run awk per file so FILENAME stays accurate.
  output=$(awk "${AWK_PROG}" "${f}" || true)
  if [[ -z "${output}" ]]; then
    continue
  fi
  while IFS=$'\t' read -r tag file binding reason; do
    case "${tag}" in
      OFFENDER)
        printf 'FAIL: %s — ClusterRoleBinding %q binds cluster-admin (%s)\n' \
          "${file}" "${binding}" "${reason}" >&2
        OFFENDERS=$((OFFENDERS + 1))
        ;;
      ALLOWED)
        printf 'NOTE: %s — ClusterRoleBinding %q binds cluster-admin (explicit exception: %s)\n' \
          "${file}" "${binding}" "${reason}"
        ALLOWED=$((ALLOWED + 1))
        ;;
    esac
  done <<<"${output}"
done

printf '[%s] scanned %d YAML files. offenders=%d, explicit-exceptions=%d\n' \
  "${SCRIPT_NAME}" "${#FILES[@]}" "${OFFENDERS}" "${ALLOWED}"

if [[ "${OFFENDERS}" -gt 0 ]]; then
  printf '[%s] FAIL: %d ClusterRoleBinding(s) reference cluster-admin without the fos1.io/rbac-exception annotation.\n' \
    "${SCRIPT_NAME}" "${OFFENDERS}" >&2
  printf '[%s]        Either scope the binding to a minimum-privilege ClusterRole, or (only when justified) add the annotation with a concrete reason.\n' \
    "${SCRIPT_NAME}" >&2
  exit 1
fi

printf '[%s] PASS: no unannotated cluster-admin bindings detected.\n' "${SCRIPT_NAME}"
exit 0
