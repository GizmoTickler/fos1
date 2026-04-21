package correlation

import (
	"net/http"
	"sync/atomic"
)

type ProbeState struct {
	healthy atomic.Bool
	ready   atomic.Bool
}

func NewProbeState() *ProbeState {
	state := &ProbeState{}
	state.healthy.Store(true)
	return state
}

func (p *ProbeState) SetHealthy(value bool) {
	p.healthy.Store(value)
}

func (p *ProbeState) SetReady(value bool) {
	p.ready.Store(value)
}

func (p *ProbeState) IsHealthy() bool {
	return p.healthy.Load()
}

func (p *ProbeState) IsReady() bool {
	return p.ready.Load()
}

func NewProbeHandler(state *ProbeState) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		if !state.IsHealthy() {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		if !state.IsReady() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	return mux
}
