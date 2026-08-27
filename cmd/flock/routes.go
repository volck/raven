package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/volck/raven/internal/flock"
	rvclient "github.com/volck/raven/internal/flock/raven"
)

// Snapshotter exposes the cached upstream view to handlers.
type Snapshotter interface {
	Snapshot() flock.Snapshot
	Ready() bool
}

// HealthSnapshotter exposes cached per-target probe results.
type HealthSnapshotter interface {
	Health() map[string]flock.Health
	HealthFor(target string) (flock.Health, bool)
}

// EventSnapshotter exposes cached per-target raven events.
type EventSnapshotter interface {
	All() []flock.TargetEvent
	ForEngine(name string, snap flock.Snapshot) []flock.TargetEvent
	EventsForTarget(target string) []rvclient.Event
}

// StatusSnapshotter exposes cached per-target raven status payloads and
// derived inventory.
type StatusSnapshotter interface {
	All() []flock.TargetStatus
	ForEngine(name string, snap flock.Snapshot) []flock.TargetStatus
	StatusForTarget(target string) (flock.TargetStatus, bool)
	Inventory() []flock.InventoryEntry
	InventoryForEngine(name string, snap flock.Snapshot) []flock.InventoryEntry
	SecretDetail(engine, secretName string, snap flock.Snapshot) []flock.InventoryEntry
}

// WSHandler is the WebSocket fan-out endpoint. *flock.WSHub satisfies this.
type WSHandler interface {
	http.Handler
}

// PipelineSnapshotter exposes cached per-target raven pipeline payloads.
type PipelineSnapshotter interface {
	PipelineForTarget(target string) (flock.TargetPipeline, bool)
	PipelineForEngine(name string, snap flock.Snapshot) []flock.TargetPipeline
	PipelineForSecret(engine, secret string, snap flock.Snapshot) []flock.PipelineSecretRow
}

// addRoutes lists every API endpoint exposed by flock in one place.
// All routes are registered here — nowhere else.
func addRoutes(
	mux *http.ServeMux,
	logger *slog.Logger,
	ready *atomic.Bool,
	snap Snapshotter,
	health HealthSnapshotter,
	events EventSnapshotter,
	status StatusSnapshotter,
	ws WSHandler,
	pipeline PipelineSnapshotter,
) {
	mux.Handle("GET /healthz", handleHealthz(logger))
	mux.Handle("GET /readyz", handleReadyz(logger, ready))
	mux.Handle("GET /api/v1/ravens", requireReady(snap, handleListRavens(logger, snap)))
	mux.Handle("GET /api/v1/ravens/{name}", requireReady(snap, handleGetRaven(logger, snap)))
	mux.Handle("GET /api/v1/ravens/{name}/health", requireReady(snap, handleGetRavenHealth(logger, snap, health)))
	mux.Handle("GET /api/v1/ravens/{name}/events", requireReady(snap, handleGetRavenEvents(logger, snap, events)))
	mux.Handle("GET /api/v1/ravens/{name}/status", requireReady(snap, handleGetRavenStatus(logger, snap, status)))
	mux.Handle("GET /api/v1/ravens/{name}/inventory", requireReady(snap, handleGetRavenInventory(logger, snap, status)))
	mux.Handle("GET /api/v1/ravens/{name}/secrets/{secret}", requireReady(snap, handleGetRavenSecret(logger, snap, status)))
	mux.Handle("GET /api/v1/ravens/{name}/pipeline", requireReady(snap, handleGetRavenPipeline(logger, snap, pipeline)))
	mux.Handle("GET /api/v1/ravens/{name}/pipeline/{secret}", requireReady(snap, handleGetRavenPipelineSecret(logger, snap, pipeline)))
	mux.Handle("GET /api/v1/health", requireReady(snap, handleAllHealth(logger, health)))
	mux.Handle("GET /api/v1/events", requireReady(snap, handleAllEvents(logger, events)))
	mux.Handle("GET /api/v1/status", requireReady(snap, handleAllStatus(logger, status)))
	mux.Handle("GET /api/v1/inventory", requireReady(snap, handleInventory(logger, status)))
	mux.Handle("GET /api/v1/all", requireReady(snap, handleAll(logger, snap, health)))
	if ws != nil {
		mux.Handle("GET /ws", ws)
	}
}

// requireReady gates a handler until the Provider has loaded at least once.
func requireReady(snap Snapshotter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !snap.Ready() {
			_ = writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not ready"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleHealthz(logger *slog.Logger) http.Handler {
	_ = logger
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func handleReadyz(logger *slog.Logger, ready *atomic.Bool) http.Handler {
	_ = logger
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
}

func handleListRavens(logger *slog.Logger, snap Snapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		engines := snap.Snapshot().Engines
		if engines == nil {
			engines = []string{}
		}
		if err := writeJSON(w, http.StatusOK, engines); err != nil {
			logger.Warn("ravens.encode_failed", "err", err.Error())
		}
	})
}

func handleGetRaven(logger *slog.Logger, snap Snapshotter) http.Handler {
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
			logger.Warn("ravens.encode_failed", "err", err.Error(), "name", name)
		}
	})
}

type targetHealth struct {
	Target    string    `json:"target"`
	Healthy   bool      `json:"healthy"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

func handleGetRavenHealth(logger *slog.Logger, snap Snapshotter, health HealthSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		targets, ok := snap.Snapshot().Routing[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		out := make([]targetHealth, 0, len(targets))
		for _, t := range targets {
			h, _ := health.HealthFor(t)
			out = append(out, targetHealth{
				Target:    t,
				Healthy:   h.Healthy,
				Error:     h.Error,
				CheckedAt: h.CheckedAt,
			})
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("ravens.health.encode_failed", "err", err.Error(), "name", name)
		}
	})
}

func handleAllHealth(logger *slog.Logger, health HealthSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		all := health.Health()
		out := make([]targetHealth, 0, len(all))
		for t, h := range all {
			out = append(out, targetHealth{
				Target:    t,
				Healthy:   h.Healthy,
				Error:     h.Error,
				CheckedAt: h.CheckedAt,
			})
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("health.encode_failed", "err", err.Error())
		}
	})
}

func handleAll(logger *slog.Logger, snap Snapshotter, health HealthSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := snap.Snapshot()
		engines := s.Engines
		if engines == nil {
			engines = []string{}
		}
		routing := s.Routing
		if routing == nil {
			routing = map[string][]string{}
		}
		out := map[string]any{
			"engines": engines,
			"routing": routing,
			"health":  health.Health(),
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("all.encode_failed", "err", err.Error())
		}
	})
}

func handleGetRavenEvents(logger *slog.Logger, snap Snapshotter, events EventSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, ok := snap.Snapshot().Routing[name]; !ok {
			http.NotFound(w, r)
			return
		}
		out := events.ForEngine(name, snap.Snapshot())
		if out == nil {
			out = []flock.TargetEvent{}
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("ravens.events.encode_failed", "err", err.Error(), "name", name)
		}
	})
}

func handleAllEvents(logger *slog.Logger, events EventSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := events.All()
		if out == nil {
			out = []flock.TargetEvent{}
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("events.encode_failed", "err", err.Error())
		}
	})
}

func handleGetRavenStatus(logger *slog.Logger, snap Snapshotter, status StatusSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, ok := snap.Snapshot().Routing[name]; !ok {
			http.NotFound(w, r)
			return
		}
		out := status.ForEngine(name, snap.Snapshot())
		if out == nil {
			out = []flock.TargetStatus{}
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("ravens.status.encode_failed", "err", err.Error(), "name", name)
		}
	})
}

func handleAllStatus(logger *slog.Logger, status StatusSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := status.All()
		if out == nil {
			out = []flock.TargetStatus{}
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("status.encode_failed", "err", err.Error())
		}
	})
}

func handleInventory(logger *slog.Logger, status StatusSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := status.Inventory()
		if out == nil {
			out = []flock.InventoryEntry{}
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("inventory.encode_failed", "err", err.Error())
		}
	})
}

func handleGetRavenInventory(logger *slog.Logger, snap Snapshotter, status StatusSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, ok := snap.Snapshot().Routing[name]; !ok {
			http.NotFound(w, r)
			return
		}
		out := status.InventoryForEngine(name, snap.Snapshot())
		if out == nil {
			out = []flock.InventoryEntry{}
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("ravens.inventory.encode_failed", "err", err.Error(), "name", name)
		}
	})
}

func handleGetRavenSecret(logger *slog.Logger, snap Snapshotter, status StatusSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		secret := r.PathValue("secret")
		if _, ok := snap.Snapshot().Routing[name]; !ok {
			http.NotFound(w, r)
			return
		}
		out := status.SecretDetail(name, secret, snap.Snapshot())
		if len(out) == 0 {
			http.NotFound(w, r)
			return
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("ravens.secret.encode_failed", "err", err.Error(), "name", name, "secret", secret)
		}
	})
}

func handleGetRavenPipeline(logger *slog.Logger, snap Snapshotter, pipeline PipelineSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, ok := snap.Snapshot().Routing[name]; !ok {
			http.NotFound(w, r)
			return
		}
		out := pipeline.PipelineForEngine(name, snap.Snapshot())
		if out == nil {
			out = []flock.TargetPipeline{}
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("ravens.pipeline.encode_failed", "err", err.Error(), "name", name)
		}
	})
}

func handleGetRavenPipelineSecret(logger *slog.Logger, snap Snapshotter, pipeline PipelineSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		secret := r.PathValue("secret")
		if _, ok := snap.Snapshot().Routing[name]; !ok {
			http.NotFound(w, r)
			return
		}
		out := pipeline.PipelineForSecret(name, secret, snap.Snapshot())
		if len(out) == 0 {
			http.NotFound(w, r)
			return
		}
		if err := writeJSON(w, http.StatusOK, out); err != nil {
			logger.Warn("ravens.pipeline.secret.encode_failed", "err", err.Error(), "name", name, "secret", secret)
		}
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}
