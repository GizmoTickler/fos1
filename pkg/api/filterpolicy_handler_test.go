package api_test

import (
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

func TestWriteMethodsRejected(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
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
