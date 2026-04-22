package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/GizmoTickler/fos1/pkg/security/policy"
)

// FilterPolicyHandler serves the /v1/filter-policies routes. It reads from
// a controller-runtime client.Client which may be cached (shared with a
// controller-runtime manager) or direct. Only List and Get are implemented;
// write verbs are explicitly deferred in v0.
type FilterPolicyHandler struct {
	// Client is used to fetch FilterPolicy objects. Handlers never call
	// Create/Update/Patch/Delete — v0 is read-only.
	Client client.Client
}

// maxPageSize bounds the number of items returned in a single list call.
// Callers that want more must follow the continue token. The cap protects
// the server from pathological memory use while still giving tooling a
// sensible default.
const maxPageSize = 500

// defaultPageSize is the page size used when the caller omits ?limit.
const defaultPageSize = 100

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
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

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

// handleGet serves GET /v1/filter-policies/{namespace}/{name}. The path
// shape was chosen over the Kubernetes convention of
// /namespaces/{ns}/filterpolicies/{name} because the API aggregates a single
// resource family and the flatter shape is easier for human operators to
// type. It is NOT compatible with kubectl discovery — intentionally so; v0
// is a distinct management surface.
func (h *FilterPolicyHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

	// Trim prefix and split. We expect exactly "{namespace}/{name}" once
	// the route prefix is removed. Anything else is a 404.
	rest := strings.TrimPrefix(r.URL.Path, "/v1/filter-policies/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		writeNotFound(w, "path must be /v1/filter-policies/{namespace}/{name}")
		return
	}

	key := types.NamespacedName{Namespace: parts[0], Name: parts[1]}
	fp := &policy.FilterPolicy{}
	if err := h.Client.Get(r.Context(), key, fp); err != nil {
		if apierrors.IsNotFound(err) {
			writeNotFound(w, "filterpolicy not found")
			return
		}
		writeBackendError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, fp)
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
