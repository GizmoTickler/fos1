package api

import "net/http"

// healthzHandler returns 200 unconditionally. Liveness should only fail when
// the process itself is broken; the TLS listener is already running by the
// time this endpoint is reachable, so there is nothing meaningful to check
// here. The body is a short human-readable string to aid on-call debugging.
func healthzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
