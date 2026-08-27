package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// addRoutes lists every API endpoint exposed by the logparser in one place.
// All routes are registered here — nowhere else.
func addRoutes(mux *http.ServeMux, logger *slog.Logger, snap Snapshotter, ready ReadyChecker) {
	mux.Handle("GET /healthz", handleHealthz(logger))
	mux.Handle("GET /readyz", handleReadyz(logger, ready))
	mux.Handle("GET /api/v1/ssgs", handleListSSGs(logger, snap))
	mux.Handle("GET /api/v1/ssgs/{name}", handleGetSSG(logger, snap))
}

func handleHealthz(logger *slog.Logger) http.Handler {
	_ = logger
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func handleReadyz(logger *slog.Logger, ready ReadyChecker) http.Handler {
	_ = logger
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ready.Ready() {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
}

func handleListSSGs(logger *slog.Logger, snap Snapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		engines := snap.Snapshot().SecretEngines
		if engines == nil {
			engines = []string{}
		}
		if err := writeJSON(w, http.StatusOK, engines); err != nil {
			logger.Warn("ssgs.encode_failed", "err", err.Error())
		}
	})
}

func handleGetSSG(logger *slog.Logger, snap Snapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		targets, ok := snap.Snapshot().Routing[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if targets == nil {
			targets = []string{}
		}
		if err := writeJSON(w, http.StatusOK, targets); err != nil {
			logger.Warn("ssgs.encode_failed", "err", err.Error(), "name", name)
		}
	})
}

// writeJSON writes v as a JSON response with the given status code.
// The returned error is non-nil only if the body could not be encoded.
func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}
