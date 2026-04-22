package api

import (
	_ "embed"
	"net/http"
)

// openAPISpec is the static OpenAPI 3.0 document covering the v0 surface.
// It is embedded at compile time so the binary has no filesystem dependency
// at runtime. The source lives at pkg/api/testdata/openapi.json — tests
// read the same file via `go:embed` to guarantee the spec on disk and the
// spec served are identical.
//
//go:embed testdata/openapi.json
var openAPISpec []byte

// openAPIHandler serves the embedded OpenAPI document. The response is
// served with application/json so that standard tooling (curl, Swagger UI,
// etc.) can discover the schema and generate clients.
func openAPIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(openAPISpec)
	})
}
