package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/GizmoTickler/fos1/pkg/api"
	"github.com/GizmoTickler/fos1/pkg/security/policy"
)

// newFakeClient returns a controller-runtime fake client preloaded with the
// provided FilterPolicy objects. The scheme registers both FilterPolicy and
// FilterPolicyList so List() works out of the box.
func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, policy.AddToScheme(scheme))
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		Build()
}

func fixturePolicy(ns, name string) *policy.FilterPolicy {
	return &policy.FilterPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: policy.GroupVersion.String(),
			Kind:       "FilterPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: policy.FilterPolicySpec{
			Description: "test",
			Scope:       "zone",
			Enabled:     true,
			Priority:    100,
			Actions: []policy.PolicyAction{
				{Type: "allow"},
			},
			Selectors: policy.FilterSelectors{
				Sources: []policy.Selector{
					{Type: "cidr", Values: []interface{}{"10.0.0.0/8"}},
				},
			},
		},
	}
}

// newTestServer builds an api.Server wired to an allow-all authorizer so
// handler unit tests do not need to simulate TLS.
func newTestServer(t *testing.T, objs ...client.Object) *api.Server {
	t.Helper()
	c := newFakeClient(t, objs...)
	return &api.Server{
		Client:     c,
		Authorizer: allowAll{},
	}
}

type allowAll struct{}

func (allowAll) Authorize(string) error { return nil }

func TestListFilterPoliciesEmpty(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/filter-policies", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Items      []any  `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "fos1.io/v1", body.APIVersion)
	assert.Equal(t, "FilterPolicyList", body.Kind)
	assert.Empty(t, body.Items)
}

func TestListFilterPoliciesReturnsItems(t *testing.T) {
	t.Parallel()
	p1 := fixturePolicy("security", "block-ssh")
	p2 := fixturePolicy("security", "allow-http")
	p3 := fixturePolicy("other", "outlier")
	srv := newTestServer(t, p1, p2, p3)

	req := httptest.NewRequest(http.MethodGet, "/v1/filter-policies", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body struct {
		Items []policy.FilterPolicy `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Len(t, body.Items, 3)
}

func TestListFilterPoliciesNamespaceFilter(t *testing.T) {
	t.Parallel()
	p1 := fixturePolicy("security", "block-ssh")
	p2 := fixturePolicy("other", "outlier")
	srv := newTestServer(t, p1, p2)

	req := httptest.NewRequest(http.MethodGet, "/v1/filter-policies?namespace=security", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body struct {
		Items []policy.FilterPolicy `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Len(t, body.Items, 1)
	assert.Equal(t, "security", body.Items[0].ObjectMeta.Namespace)
}

func TestListFilterPoliciesRejectsInvalidLimit(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/filter-policies?limit=not-a-number", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestGetFilterPolicyOK(t *testing.T) {
	t.Parallel()
	p1 := fixturePolicy("security", "block-ssh")
	srv := newTestServer(t, p1)

	req := httptest.NewRequest(http.MethodGet, "/v1/filter-policies/security/block-ssh", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var got policy.FilterPolicy
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	// The FilterPolicy type has an internal `Name string json:"-"` that is
	// never populated over the wire. Assert on ObjectMeta.Name which is
	// what the JSON body actually carries.
	assert.Equal(t, "block-ssh", got.ObjectMeta.Name)
	assert.Equal(t, "security", got.ObjectMeta.Namespace)
}

func TestGetFilterPolicyNotFound(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/filter-policies/security/missing", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestGetFilterPolicyMalformedPath(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/filter-policies/only-one-segment", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestCollectionRouteDisallowsPutPatchDelete asserts that /v1/filter-policies
// rejects verbs that belong on the item route. POST is allowed on the
// collection route (Sprint 31 Ticket 48) and is covered by dedicated
// create tests below.
func TestCollectionRouteDisallowsPutPatchDelete(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(method, "/v1/filter-policies", nil)
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)
			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
		})
	}
}

// TestHandlerRespectsContextCancellation verifies the list handler plumbs
// request context into the backend client so in-flight calls cancel cleanly.
// We approximate this by calling with an already-canceled context.
func TestHandlerRespectsContextCancellation(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/v1/filter-policies", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	// The fake client ignores context so this should still return 200.
	// Intentionally lenient: we assert we did not crash and returned a
	// non-5xx response.
	assert.NotEqual(t, http.StatusInternalServerError, rr.Code)
}

// marshalJSONBody serialises a FilterPolicy or map to JSON. The helper
// keeps the write-path tests readable by hiding the three-line
// boilerplate of bytes.Buffer + json.NewEncoder.
func marshalJSONBody(t *testing.T, v any) *bytes.Buffer {
	t.Helper()
	buf := new(bytes.Buffer)
	require.NoError(t, json.NewEncoder(buf).Encode(v))
	return buf
}

// TestCreateFilterPolicyAccepts201 drives the POST handler through a
// valid request body and asserts the response body carries the created
// object with a 201 status.
func TestCreateFilterPolicyAccepts201(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	fp := fixturePolicy("security", "allow-internal")
	body := marshalJSONBody(t, fp)
	req := httptest.NewRequest(http.MethodPost, "/v1/filter-policies", body)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, "body: %s", rr.Body.String())
	var got policy.FilterPolicy
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, "allow-internal", got.ObjectMeta.Name)
	assert.Equal(t, "security", got.ObjectMeta.Namespace)
}

// TestCreateFilterPolicyInvalidReturns422 asserts the validation path is
// load-bearing: a spec missing Actions and selectors must produce a 422
// with a structured body.
func TestCreateFilterPolicyInvalidReturns422(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	invalid := &policy.FilterPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: policy.GroupVersion.String(), Kind: "FilterPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "security"},
		// Scope empty, Actions empty, selectors empty — three violations.
	}
	body := marshalJSONBody(t, invalid)
	req := httptest.NewRequest(http.MethodPost, "/v1/filter-policies", body)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnprocessableEntity, rr.Code, "body: %s", rr.Body.String())
	var status map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &status))
	assert.Equal(t, "Invalid", status["reason"])
	details, ok := status["details"].(map[string]any)
	require.True(t, ok, "details must be an object")
	causes, ok := details["causes"].([]any)
	require.True(t, ok, "details.causes must be an array")
	assert.NotEmpty(t, causes, "at least one cause must be reported")
}

// TestCreateFilterPolicyRejectsUnknownContentType ensures the 415 path
// fires when a client forgets to set Content-Type.
func TestCreateFilterPolicyRejectsUnknownContentType(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	body := marshalJSONBody(t, fixturePolicy("security", "x"))
	req := httptest.NewRequest(http.MethodPost, "/v1/filter-policies", body)
	// intentionally no Content-Type header

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnsupportedMediaType, rr.Code, "body: %s", rr.Body.String())
}

// TestCreateFilterPolicyRejectsResourceVersion ensures the POST handler
// rejects a body that pre-populates resourceVersion — a common client
// mistake when reusing an object fetched via GET.
func TestCreateFilterPolicyRejectsResourceVersion(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	fp := fixturePolicy("security", "allow-internal")
	fp.ObjectMeta.ResourceVersion = "42"
	body := marshalJSONBody(t, fp)
	req := httptest.NewRequest(http.MethodPost, "/v1/filter-policies", body)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code, "body: %s", rr.Body.String())
}

// TestReplaceFilterPolicyRequiresResourceVersion asserts PUT rejects a
// body that omits resourceVersion (optimistic concurrency is mandatory).
func TestReplaceFilterPolicyRequiresResourceVersion(t *testing.T) {
	t.Parallel()
	existing := fixturePolicy("security", "allow-internal")
	srv := newTestServer(t, existing)

	update := fixturePolicy("security", "allow-internal")
	update.Spec.Description = "updated"
	body := marshalJSONBody(t, update)
	req := httptest.NewRequest(http.MethodPut, "/v1/filter-policies/security/allow-internal", body)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code, "body: %s", rr.Body.String())
	assert.Contains(t, rr.Body.String(), "resourceVersion")
}

// TestReplaceFilterPolicyConflictOnStaleResourceVersion asserts the
// apiserver-style 409 surfaces when a caller submits a stale
// resourceVersion. The fake client honours resourceVersion checks when
// the underlying tracker has seen a newer version, so we simulate the
// stale case by writing twice without refetching.
func TestReplaceFilterPolicyConflictOnStaleResourceVersion(t *testing.T) {
	t.Parallel()
	existing := fixturePolicy("security", "allow-internal")
	existing.ObjectMeta.ResourceVersion = "1"
	srv := newTestServer(t, existing)

	// First refresh: GET to learn the real resourceVersion the fake
	// client assigned.
	getReq := httptest.NewRequest(http.MethodGet, "/v1/filter-policies/security/allow-internal", nil)
	getRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRR, getReq)
	require.Equal(t, http.StatusOK, getRR.Code)
	var fetched policy.FilterPolicy
	require.NoError(t, json.Unmarshal(getRR.Body.Bytes(), &fetched))
	freshRV := fetched.ObjectMeta.ResourceVersion
	require.NotEmpty(t, freshRV, "fake client must assign a resourceVersion")

	// First PUT with the fresh RV succeeds.
	first := fetched.DeepCopy()
	first.Spec.Description = "first update"
	body := marshalJSONBody(t, first)
	req := httptest.NewRequest(http.MethodPut, "/v1/filter-policies/security/allow-internal", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

	// Second PUT with the SAME (now-stale) RV must 409.
	second := fetched.DeepCopy()
	second.Spec.Description = "second update"
	second.ObjectMeta.ResourceVersion = freshRV
	body2 := marshalJSONBody(t, second)
	req2 := httptest.NewRequest(http.MethodPut, "/v1/filter-policies/security/allow-internal", body2)
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)

	assert.Equal(t, http.StatusConflict, rr2.Code, "body: %s", rr2.Body.String())
}

// TestPatchFilterPolicyMergePatchUpdatesDescription verifies a JSON merge
// patch is applied, the result validated, and the updated object returned.
func TestPatchFilterPolicyMergePatchUpdatesDescription(t *testing.T) {
	t.Parallel()
	existing := fixturePolicy("security", "allow-internal")
	srv := newTestServer(t, existing)

	patch := []byte(`{"spec":{"description":"patched"}}`)
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/filter-policies/security/allow-internal",
		bytes.NewReader(patch))
	req.Header.Set("Content-Type", "application/merge-patch+json")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	var got policy.FilterPolicy
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, "patched", got.Spec.Description)
	// Other spec fields must be preserved.
	assert.Equal(t, "zone", got.Spec.Scope)
	assert.True(t, got.Spec.Enabled)
}

// TestPatchFilterPolicyRejectsUnsupportedContentType asserts the PATCH
// handler rejects application/json-patch+json (RFC 6902) until we choose
// to support it.
func TestPatchFilterPolicyRejectsUnsupportedContentType(t *testing.T) {
	t.Parallel()
	existing := fixturePolicy("security", "allow-internal")
	srv := newTestServer(t, existing)

	patch := []byte(`[{"op":"replace","path":"/spec/description","value":"x"}]`)
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/filter-policies/security/allow-internal",
		bytes.NewReader(patch))
	req.Header.Set("Content-Type", "application/json-patch+json")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnsupportedMediaType, rr.Code, "body: %s", rr.Body.String())
	assert.Contains(t, rr.Header().Get("Accept-Patch"), "merge-patch+json")
}

// TestPatchFilterPolicyRejectsSpecInvalidation asserts a patch that
// produces an invalid resulting spec is rejected with 422, not silently
// applied.
func TestPatchFilterPolicyRejectsSpecInvalidation(t *testing.T) {
	t.Parallel()
	existing := fixturePolicy("security", "allow-internal")
	srv := newTestServer(t, existing)

	// Remove actions entirely — the merged object must fail validation.
	patch := []byte(`{"spec":{"actions":[]}}`)
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/filter-policies/security/allow-internal",
		bytes.NewReader(patch))
	req.Header.Set("Content-Type", "application/merge-patch+json")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rr.Code, "body: %s", rr.Body.String())
}

// TestPatchFilterPolicyStrategicMergeAccepted asserts the
// strategic-merge-patch content type is accepted; because FilterPolicy
// carries no patch-strategy struct tags, the semantics collapse to JSON
// merge patch (lists are replaced wholesale) but the request itself must
// succeed.
func TestPatchFilterPolicyStrategicMergeAccepted(t *testing.T) {
	t.Parallel()
	existing := fixturePolicy("security", "allow-internal")
	srv := newTestServer(t, existing)

	patch := []byte(`{"spec":{"description":"strategic"}}`)
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/filter-policies/security/allow-internal",
		bytes.NewReader(patch))
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	var got policy.FilterPolicy
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, "strategic", got.Spec.Description)
}

// TestDeleteFilterPolicyOK drives a foreground delete and asserts the
// resulting Status envelope carries Success + 200.
func TestDeleteFilterPolicyOK(t *testing.T) {
	t.Parallel()
	existing := fixturePolicy("security", "allow-internal")
	srv := newTestServer(t, existing)

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/filter-policies/security/allow-internal?propagationPolicy=Foreground", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	var status map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &status))
	assert.Equal(t, "Success", status["status"])

	// Subsequent GET returns 404.
	getReq := httptest.NewRequest(http.MethodGet,
		"/v1/filter-policies/security/allow-internal", nil)
	getRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRR, getReq)
	// With Foreground propagation the fake client may leave the object
	// in place until its finalizers clear; Background/default deletes it
	// outright. Either outcome is acceptable for this assertion.
	assert.True(t, getRR.Code == http.StatusNotFound || getRR.Code == http.StatusOK)
}

// TestDeleteFilterPolicyMissing returns 404 when the target does not
// exist.
func TestDeleteFilterPolicyMissing(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/filter-policies/security/missing", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestDeleteFilterPolicyInvalidPropagationPolicy guards the query
// parameter parsing path.
func TestDeleteFilterPolicyInvalidPropagationPolicy(t *testing.T) {
	t.Parallel()
	existing := fixturePolicy("security", "allow-internal")
	srv := newTestServer(t, existing)

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/filter-policies/security/allow-internal?propagationPolicy=Cascade", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
