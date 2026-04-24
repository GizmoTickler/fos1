package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/GizmoTickler/fos1/pkg/security/policy"
)

// FilterPolicyHandler serves the /v1/filter-policies routes. It reads and
// writes via a controller-runtime client.Client which may be cached (shared
// with a controller-runtime manager) or direct. Sprint 30 Ticket 41 shipped
// List/Get; Sprint 31 Ticket 48 adds the full CRUD surface — Create,
// Replace (PUT), Patch (JSON Merge Patch / Strategic Merge Patch), and
// Delete — behind the same mTLS + allowlist middleware.
type FilterPolicyHandler struct {
	// Client is used to read and mutate FilterPolicy objects. All write
	// verbs go through this interface so tests can drive them with a fake
	// client.
	Client client.Client
}

// maxPageSize bounds the number of items returned in a single list call.
// Callers that want more must follow the continue token. The cap protects
// the server from pathological memory use while still giving tooling a
// sensible default.
const maxPageSize = 500

// defaultPageSize is the page size used when the caller omits ?limit.
const defaultPageSize = 100

// maxRequestBodyBytes caps incoming request bodies on write verbs. A
// typical FilterPolicy object serialises well under 8 KiB; 1 MiB is a
// generous bound that still prevents a malicious caller from OOMing the
// server via a huge POST body.
const maxRequestBodyBytes = int64(1 << 20)

// Content types recognised by the PATCH handler. Any other content type
// produces a 415. The names match the IETF / Kubernetes conventions so
// tooling written against kube-apiserver can reuse the same headers.
const (
	contentTypeJSON              = "application/json"
	contentTypeMergePatch        = "application/merge-patch+json"
	contentTypeStrategicMerge    = "application/strategic-merge-patch+json"
	contentTypeApplyYAML         = "application/apply-patch+yaml" // explicitly unsupported
	contentTypeJSONPatch         = "application/json-patch+json"  // explicitly unsupported
	writePathContentTypeRequired = contentTypeJSON                // for POST / PUT
)

// handleList serves GET /v1/filter-policies. Supported query parameters:
//
//   - namespace — restrict the list to a single namespace (optional).
//   - limit     — cap the number of items returned (default 100, max 500).
//   - continue  — opaque continuation token from a previous response.
//
// The response envelope intentionally mirrors the shape of a Kubernetes
// List object but is simplified: apiVersion/kind identify the wrapper, and
// items is the array of FilterPolicy objects. The server does not claim to
// be a full apiserver — v0 intentionally returns a synthesized list.
func (h *FilterPolicyHandler) handleList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.doList(w, r)
	case http.MethodPost:
		h.doCreate(w, r)
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// handleItem dispatches GET/PUT/PATCH/DELETE on
// /v1/filter-policies/{namespace}/{name}.
func (h *FilterPolicyHandler) handleItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.doGet(w, r)
	case http.MethodPut:
		h.doReplace(w, r)
	case http.MethodPatch:
		h.doPatch(w, r)
	case http.MethodDelete:
		h.doDelete(w, r)
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete)
	}
}

// doList implements the GET verb on the collection route.
func (h *FilterPolicyHandler) doList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := []client.ListOption{}
	if ns := q.Get("namespace"); ns != "" {
		opts = append(opts, client.InNamespace(ns))
	}

	limit := defaultPageSize
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeBadRequest(w, "invalid limit query parameter")
			return
		}
		if n > maxPageSize {
			n = maxPageSize
		}
		limit = n
	}
	opts = append(opts, client.Limit(int64(limit)))
	if cont := q.Get("continue"); cont != "" {
		opts = append(opts, client.Continue(cont))
	}

	list := &policy.FilterPolicyList{}
	if err := h.Client.List(r.Context(), list, opts...); err != nil {
		writeBackendError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": "fos1.io/v1",
		"kind":       "FilterPolicyList",
		"metadata": map[string]any{
			"resourceVersion": list.ResourceVersion,
			"continue":        list.Continue,
		},
		"items": list.Items,
	})
}

// doGet serves GET /v1/filter-policies/{namespace}/{name}. The path shape
// was chosen over the Kubernetes convention of
// /namespaces/{ns}/filterpolicies/{name} because the API aggregates a
// single resource family and the flatter shape is easier for human
// operators to type. It is NOT compatible with kubectl discovery —
// intentionally so; v0 is a distinct management surface.
func (h *FilterPolicyHandler) doGet(w http.ResponseWriter, r *http.Request) {
	ns, name, ok := parseItemPath(r.URL.Path)
	if !ok {
		writeNotFound(w, "path must be /v1/filter-policies/{namespace}/{name}")
		return
	}

	fp := &policy.FilterPolicy{}
	if err := h.Client.Get(r.Context(), types.NamespacedName{Namespace: ns, Name: name}, fp); err != nil {
		if apierrors.IsNotFound(err) {
			writeNotFound(w, "filterpolicy not found")
			return
		}
		writeBackendError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, fp)
}

// doCreate implements POST /v1/filter-policies. The request body is a
// FilterPolicy JSON object; the server validates the spec, rejects empty /
// malformed input with 422 or 400, and returns the created object on 201.
// Namespace and name come from the request body (there is no path-level
// {namespace}/{name} on the collection route).
func (h *FilterPolicyHandler) doCreate(w http.ResponseWriter, r *http.Request) {
	subject := subjectFromRequest(r)
	started := time.Now()

	if ct := contentType(r); ct != contentTypeJSON {
		writeUnsupportedMediaType(w, ct, []string{contentTypeJSON})
		logWrite(subject, "create", "", "", http.StatusUnsupportedMediaType, started)
		return
	}

	fp, code, err := decodeFilterPolicy(r)
	if err != nil {
		writeBadRequest(w, fmt.Sprintf("decode request body: %v", err))
		logWrite(subject, "create", safeStr(fp, "ns"), safeStr(fp, "name"), code, started)
		return
	}
	// POSTs must not carry a resourceVersion — the object does not exist yet.
	if strings.TrimSpace(fp.ObjectMeta.ResourceVersion) != "" {
		writeBadRequest(w, "metadata.resourceVersion must be empty on create")
		logWrite(subject, "create", fp.ObjectMeta.Namespace, fp.ObjectMeta.Name, http.StatusBadRequest, started)
		return
	}
	if errs := ValidateFilterPolicy(fp); len(errs) > 0 {
		writeInvalid(w, errs)
		logWrite(subject, "create", fp.ObjectMeta.Namespace, fp.ObjectMeta.Name, http.StatusUnprocessableEntity, started)
		return
	}

	if err := h.Client.Create(r.Context(), fp); err != nil {
		code := mapBackendErrorToStatus(w, err)
		logWrite(subject, "create", fp.ObjectMeta.Namespace, fp.ObjectMeta.Name, code, started)
		return
	}
	writeJSON(w, http.StatusCreated, fp)
	logWrite(subject, "create", fp.ObjectMeta.Namespace, fp.ObjectMeta.Name, http.StatusCreated, started)
}

// doReplace implements PUT /v1/filter-policies/{namespace}/{name}. The
// request body is a full FilterPolicy object and the server uses
// optimistic concurrency: callers must include metadata.resourceVersion
// from a prior GET. A missing resourceVersion is a 400 (not a 409) because
// it is a client-side authoring error, not a staleness condition.
func (h *FilterPolicyHandler) doReplace(w http.ResponseWriter, r *http.Request) {
	subject := subjectFromRequest(r)
	started := time.Now()

	ns, name, ok := parseItemPath(r.URL.Path)
	if !ok {
		writeNotFound(w, "path must be /v1/filter-policies/{namespace}/{name}")
		logWrite(subject, "replace", "", "", http.StatusNotFound, started)
		return
	}

	if ct := contentType(r); ct != contentTypeJSON {
		writeUnsupportedMediaType(w, ct, []string{contentTypeJSON})
		logWrite(subject, "replace", ns, name, http.StatusUnsupportedMediaType, started)
		return
	}

	fp, _, err := decodeFilterPolicy(r)
	if err != nil {
		writeBadRequest(w, fmt.Sprintf("decode request body: %v", err))
		logWrite(subject, "replace", ns, name, http.StatusBadRequest, started)
		return
	}
	// The path wins for identity: callers must agree with the URL.
	if fp.ObjectMeta.Name != "" && fp.ObjectMeta.Name != name {
		writeBadRequest(w, "body.metadata.name must match URL path name")
		logWrite(subject, "replace", ns, name, http.StatusBadRequest, started)
		return
	}
	if fp.ObjectMeta.Namespace != "" && fp.ObjectMeta.Namespace != ns {
		writeBadRequest(w, "body.metadata.namespace must match URL path namespace")
		logWrite(subject, "replace", ns, name, http.StatusBadRequest, started)
		return
	}
	fp.ObjectMeta.Name = name
	fp.ObjectMeta.Namespace = ns

	if strings.TrimSpace(fp.ObjectMeta.ResourceVersion) == "" {
		writeBadRequest(w, "metadata.resourceVersion is required on PUT; fetch the object first and include the returned resourceVersion")
		logWrite(subject, "replace", ns, name, http.StatusBadRequest, started)
		return
	}
	if errs := ValidateFilterPolicy(fp); len(errs) > 0 {
		writeInvalid(w, errs)
		logWrite(subject, "replace", ns, name, http.StatusUnprocessableEntity, started)
		return
	}

	if err := h.Client.Update(r.Context(), fp); err != nil {
		code := mapBackendErrorToStatus(w, err)
		logWrite(subject, "replace", ns, name, code, started)
		return
	}
	writeJSON(w, http.StatusOK, fp)
	logWrite(subject, "replace", ns, name, http.StatusOK, started)
}

// doPatch implements PATCH /v1/filter-policies/{namespace}/{name}. Two
// content types are accepted: JSON Merge Patch (RFC 7396) and Kubernetes
// Strategic Merge Patch. The server fetches the current object, merges
// the patch, validates the result, and calls Update. We deliberately do
// NOT require metadata.resourceVersion on PATCH — the point of PATCH is
// to let a caller evolve part of an object without having to GET-then-PUT
// — but callers who want strict optimistic concurrency can pass one in
// the patch body and we forward it to the apiserver, which will reject a
// stale version with a 409.
func (h *FilterPolicyHandler) doPatch(w http.ResponseWriter, r *http.Request) {
	subject := subjectFromRequest(r)
	started := time.Now()

	ns, name, ok := parseItemPath(r.URL.Path)
	if !ok {
		writeNotFound(w, "path must be /v1/filter-policies/{namespace}/{name}")
		logWrite(subject, "patch", "", "", http.StatusNotFound, started)
		return
	}

	ct := contentType(r)
	switch ct {
	case contentTypeMergePatch, contentTypeStrategicMerge:
		// supported
	default:
		writeUnsupportedMediaType(w, ct, []string{contentTypeMergePatch, contentTypeStrategicMerge})
		logWrite(subject, "patch", ns, name, http.StatusUnsupportedMediaType, started)
		return
	}

	body, err := readBody(r)
	if err != nil {
		writeBadRequest(w, fmt.Sprintf("read request body: %v", err))
		logWrite(subject, "patch", ns, name, http.StatusBadRequest, started)
		return
	}

	current := &policy.FilterPolicy{}
	if err := h.Client.Get(r.Context(), types.NamespacedName{Namespace: ns, Name: name}, current); err != nil {
		if apierrors.IsNotFound(err) {
			writeNotFound(w, "filterpolicy not found")
			logWrite(subject, "patch", ns, name, http.StatusNotFound, started)
			return
		}
		writeBackendError(w, err)
		logWrite(subject, "patch", ns, name, http.StatusInternalServerError, started)
		return
	}

	merged, err := applyPatch(current, body, ct)
	if err != nil {
		writeBadRequest(w, fmt.Sprintf("apply patch: %v", err))
		logWrite(subject, "patch", ns, name, http.StatusBadRequest, started)
		return
	}
	// Identity must not drift across a patch — operators who want to
	// rename should delete and recreate.
	if merged.ObjectMeta.Namespace != ns || merged.ObjectMeta.Name != name {
		writeBadRequest(w, "patch must not change metadata.namespace or metadata.name")
		logWrite(subject, "patch", ns, name, http.StatusBadRequest, started)
		return
	}

	if errs := ValidateFilterPolicy(merged); len(errs) > 0 {
		writeInvalid(w, errs)
		logWrite(subject, "patch", ns, name, http.StatusUnprocessableEntity, started)
		return
	}

	if err := h.Client.Update(r.Context(), merged); err != nil {
		code := mapBackendErrorToStatus(w, err)
		logWrite(subject, "patch", ns, name, code, started)
		return
	}
	writeJSON(w, http.StatusOK, merged)
	logWrite(subject, "patch", ns, name, http.StatusOK, started)
}

// doDelete implements DELETE /v1/filter-policies/{namespace}/{name}. The
// optional ?propagationPolicy query param selects foreground, background
// or orphan semantics; any other value is a 400. On success the response
// body is the Kubernetes-style Status envelope so clients can distinguish
// "deleted now" from "accepted, deletion in progress" when finalizers are
// present.
func (h *FilterPolicyHandler) doDelete(w http.ResponseWriter, r *http.Request) {
	subject := subjectFromRequest(r)
	started := time.Now()

	ns, name, ok := parseItemPath(r.URL.Path)
	if !ok {
		writeNotFound(w, "path must be /v1/filter-policies/{namespace}/{name}")
		logWrite(subject, "delete", "", "", http.StatusNotFound, started)
		return
	}

	opts := []client.DeleteOption{}
	if raw := r.URL.Query().Get("propagationPolicy"); raw != "" {
		p, err := parsePropagationPolicy(raw)
		if err != nil {
			writeBadRequest(w, err.Error())
			logWrite(subject, "delete", ns, name, http.StatusBadRequest, started)
			return
		}
		opts = append(opts, client.PropagationPolicy(p))
	}

	obj := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}
	if err := h.Client.Delete(r.Context(), obj, opts...); err != nil {
		if apierrors.IsNotFound(err) {
			writeNotFound(w, "filterpolicy not found")
			logWrite(subject, "delete", ns, name, http.StatusNotFound, started)
			return
		}
		code := mapBackendErrorToStatus(w, err)
		logWrite(subject, "delete", ns, name, code, started)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"kind":    "Status",
		"status":  "Success",
		"code":    http.StatusOK,
		"message": "filterpolicy deletion accepted",
		"details": map[string]any{
			"namespace": ns,
			"name":      name,
		},
	})
	logWrite(subject, "delete", ns, name, http.StatusOK, started)
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// parseItemPath parses /v1/filter-policies/{namespace}/{name}. Returns
// false if the path does not match — callers treat that as a 404.
func parseItemPath(path string) (string, string, bool) {
	rest := strings.TrimPrefix(path, "/v1/filter-policies/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// contentType strips any parameters (e.g. `; charset=utf-8`) from the
// Content-Type header and returns the lowercased bare type.
func contentType(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// readBody reads the request body with a max-size cap. Callers use this
// before decoding so a malicious huge POST cannot exhaust memory.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, errors.New("request body is empty")
	}
	defer r.Body.Close()
	lr := io.LimitReader(r.Body, maxRequestBodyBytes+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxRequestBodyBytes {
		return nil, fmt.Errorf("request body exceeds %d bytes", maxRequestBodyBytes)
	}
	if len(buf) == 0 {
		return nil, errors.New("request body is empty")
	}
	return buf, nil
}

// decodeFilterPolicy reads and JSON-decodes a FilterPolicy from the
// request body. The second return value is the HTTP status code the
// caller should emit when err is non-nil (400 for malformed JSON,
// 413-ish if we've already been truncated by readBody, etc.).
func decodeFilterPolicy(r *http.Request) (*policy.FilterPolicy, int, error) {
	buf, err := readBody(r)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	fp := &policy.FilterPolicy{}
	dec := json.NewDecoder(strings.NewReader(string(buf)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(fp); err != nil {
		return fp, http.StatusBadRequest, err
	}
	return fp, http.StatusOK, nil
}

// applyPatch merges patchBody into current using the semantics implied by
// contentType. Strategic merge patch lacks struct tags on FilterPolicy, so
// we fall back to the plain JSON merge semantics when the strategic
// operation is not registered — the v0 alpha contract documents the
// strategic content type as best-effort for forward compatibility.
func applyPatch(current *policy.FilterPolicy, patchBody []byte, ct string) (*policy.FilterPolicy, error) {
	// Marshal the current object to its canonical JSON so we can merge
	// against a concrete byte slice. Using the client-side JSON shape
	// keeps the merge deterministic regardless of how the fake / real
	// client stored the object.
	currentJSON, err := json.Marshal(current)
	if err != nil {
		return nil, fmt.Errorf("marshal current object: %w", err)
	}

	var mergedJSON []byte
	switch ct {
	case contentTypeMergePatch:
		mergedJSON, err = jsonpatch.MergePatch(currentJSON, patchBody)
		if err != nil {
			return nil, fmt.Errorf("merge patch: %w", err)
		}
	case contentTypeStrategicMerge:
		// FilterPolicy does not declare patchStrategy tags, so
		// strategicpatch falls back to the same semantics as JSON
		// Merge Patch (lists are replaced wholesale). We still route
		// through strategicpatch so callers who supply patch-strategy
		// directives (`$patch: replace`, etc.) get a predictable
		// answer. On error we fall back to the merge-patch path so a
		// best-effort outcome is still produced.
		mergedJSON, err = strategicpatch.StrategicMergePatch(currentJSON, patchBody, policy.FilterPolicy{})
		if err != nil {
			// Strategic merge failed — surface the error rather than
			// silently switching semantics; callers can reissue with
			// application/merge-patch+json if they want best-effort
			// merge.
			return nil, fmt.Errorf("strategic merge patch: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported patch content type %q", ct)
	}

	merged := &policy.FilterPolicy{}
	if err := json.Unmarshal(mergedJSON, merged); err != nil {
		return nil, fmt.Errorf("decode merged object: %w", err)
	}
	return merged, nil
}

// parsePropagationPolicy maps the ?propagationPolicy query string value
// onto a metav1.DeletionPropagation.
func parsePropagationPolicy(raw string) (metav1.DeletionPropagation, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "foreground":
		return metav1.DeletePropagationForeground, nil
	case "background":
		return metav1.DeletePropagationBackground, nil
	case "orphan":
		return metav1.DeletePropagationOrphan, nil
	default:
		return "", fmt.Errorf("invalid propagationPolicy %q; must be Foreground, Background, or Orphan", raw)
	}
}

// subjectFromRequest extracts the authenticated Subject CN (set by the
// auth middleware). The middleware itself records 403 — this helper is
// used only for audit logging, so an empty CN becomes "<unknown>" rather
// than breaking the log line format.
func subjectFromRequest(r *http.Request) string {
	cn := extractSubjectCN(r.TLS)
	if cn == "" {
		return "<unknown>"
	}
	return cn
}

// safeStr pulls either namespace or name off a possibly-nil FilterPolicy
// for the audit log. Returning "" on nil keeps the log line shape stable
// when the body could not be decoded.
func safeStr(fp *policy.FilterPolicy, which string) string {
	if fp == nil {
		return ""
	}
	switch which {
	case "ns":
		return fp.ObjectMeta.Namespace
	case "name":
		return fp.ObjectMeta.Name
	default:
		return ""
	}
}

// logWrite emits a structured audit line for every write attempt. The
// shape is intentionally close to a Kubernetes audit event so future
// audit-sink integrations can emit the same line to Elasticsearch / Loki
// without a translator.
func logWrite(subject, verb, namespace, name string, code int, started time.Time) {
	klog.InfoS("api write",
		"subject", subject,
		"verb", verb,
		"resource", "filterpolicies.security.fos1.io",
		"namespace", namespace,
		"name", name,
		"code", code,
		"durationMs", time.Since(started).Milliseconds(),
	)
}

// mapBackendErrorToStatus converts a controller-runtime/client error on a
// write into an HTTP response and returns the status code that was
// emitted — used by the write verbs to populate the audit log.
func mapBackendErrorToStatus(w http.ResponseWriter, err error) int {
	switch {
	case apierrors.IsAlreadyExists(err):
		writeJSON(w, http.StatusConflict, map[string]any{
			"kind":    "Status",
			"status":  "Failure",
			"code":    http.StatusConflict,
			"reason":  "AlreadyExists",
			"message": err.Error(),
		})
		return http.StatusConflict
	case apierrors.IsConflict(err):
		writeJSON(w, http.StatusConflict, map[string]any{
			"kind":    "Status",
			"status":  "Failure",
			"code":    http.StatusConflict,
			"reason":  "Conflict",
			"message": err.Error(),
		})
		return http.StatusConflict
	case apierrors.IsInvalid(err):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"kind":    "Status",
			"status":  "Failure",
			"code":    http.StatusUnprocessableEntity,
			"reason":  "Invalid",
			"message": err.Error(),
		})
		return http.StatusUnprocessableEntity
	case apierrors.IsForbidden(err):
		writeJSON(w, http.StatusForbidden, map[string]any{
			"kind":    "Status",
			"status":  "Failure",
			"code":    http.StatusForbidden,
			"reason":  "Forbidden",
			"message": err.Error(),
		})
		return http.StatusForbidden
	case apierrors.IsNotFound(err):
		writeNotFound(w, err.Error())
		return http.StatusNotFound
	default:
		writeBackendError(w, err)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return http.StatusServiceUnavailable
		}
		return http.StatusInternalServerError
	}
}

// writeInvalid emits a 422 Status envelope derived from a field.ErrorList.
func writeInvalid(w http.ResponseWriter, errs field.ErrorList) {
	writeJSON(w, http.StatusUnprocessableEntity, validationErrorsToStatus(errs))
}

// writeUnsupportedMediaType emits a 415 Status envelope listing the
// content types that are accepted.
func writeUnsupportedMediaType(w http.ResponseWriter, got string, supported []string) {
	w.Header().Set("Accept-Patch", strings.Join(supported, ", "))
	writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{
		"kind":    "Status",
		"status":  "Failure",
		"code":    http.StatusUnsupportedMediaType,
		"reason":  "UnsupportedMediaType",
		"message": fmt.Sprintf("content-type %q is not accepted; must be one of %s", got, strings.Join(supported, ", ")),
	})
}

// writeJSON is a small helper that writes a JSON body with the correct
// content-type header and fails softly if the encoder errors. A failed
// encode is logged by the caller's middleware; the response is already
// past the header write so nothing more can be done here.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeMethodNotAllowed emits a 405 with an Allow header, preserving the
// simple machine-readable Status envelope used throughout the API.
func writeMethodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
		"kind":    "Status",
		"status":  "Failure",
		"code":    http.StatusMethodNotAllowed,
		"reason":  "MethodNotAllowed",
		"message": "method not allowed",
	})
}

// writeNotFound emits a uniform 404 envelope. Used both for unknown paths
// and for missing FilterPolicy objects.
func writeNotFound(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusNotFound, map[string]any{
		"kind":    "Status",
		"status":  "Failure",
		"code":    http.StatusNotFound,
		"reason":  "NotFound",
		"message": message,
	})
}

// writeBadRequest emits a uniform 400 envelope for malformed queries.
func writeBadRequest(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"kind":    "Status",
		"status":  "Failure",
		"code":    http.StatusBadRequest,
		"reason":  "BadRequest",
		"message": message,
	})
}

// writeBackendError maps a controller-runtime/client error into an HTTP
// status. The only shape that is meaningfully actionable for the caller is
// the not-found response; everything else collapses to a 500.
func writeBackendError(w http.ResponseWriter, err error) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"kind":    "Status",
			"status":  "Failure",
			"code":    http.StatusServiceUnavailable,
			"reason":  "Timeout",
			"message": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]any{
		"kind":    "Status",
		"status":  "Failure",
		"code":    http.StatusInternalServerError,
		"reason":  "InternalError",
		"message": err.Error(),
	})
}
