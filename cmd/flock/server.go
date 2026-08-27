package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/volck/raven/cmd/flock/ui"
	"github.com/volck/raven/internal/flock"
	rvclient "github.com/volck/raven/internal/flock/raven"
)

// Server wires the HTTP handler graph for flock. Dependencies are passed
// positionally to NewServer; routes are registered exclusively in addRoutes.
type Server struct {
	handler http.Handler
	ready   *atomic.Bool
}

// emptySnap is used by tests in server_test.go (Phase A2/A1) that don't need
// real upstream state.
type emptySnap struct{}

func (emptySnap) Snapshot() flock.Snapshot              { return flock.Snapshot{} }
func (emptySnap) Ready() bool                           { return true }
func (emptySnap) Health() map[string]flock.Health       { return nil }
func (emptySnap) HealthFor(string) (flock.Health, bool) { return flock.Health{}, false }
func (emptySnap) All() []flock.TargetEvent              { return nil }
func (emptySnap) ForEngine(string, flock.Snapshot) []flock.TargetEvent {
	return nil
}
func (emptySnap) EventsForTarget(string) []rvclient.Event { return nil }

// emptyStatus implements StatusSnapshotter with no data, for tests that
// don't exercise the inventory endpoints.
type emptyStatus struct{}

func (emptyStatus) All() []flock.TargetStatus { return nil }
func (emptyStatus) ForEngine(string, flock.Snapshot) []flock.TargetStatus {
	return nil
}
func (emptyStatus) StatusForTarget(string) (flock.TargetStatus, bool) {
	return flock.TargetStatus{}, false
}
func (emptyStatus) Inventory() []flock.InventoryEntry { return nil }
func (emptyStatus) InventoryForEngine(string, flock.Snapshot) []flock.InventoryEntry {
	return nil
}
func (emptyStatus) SecretDetail(string, string, flock.Snapshot) []flock.InventoryEntry {
	return nil
}

// emptyPipeline implements PipelineSnapshotter with no data, for tests
// that don't exercise the pipeline endpoints.
type emptyPipeline struct{}

func (emptyPipeline) PipelineForTarget(string) (flock.TargetPipeline, bool) {
	return flock.TargetPipeline{}, false
}
func (emptyPipeline) PipelineForEngine(string, flock.Snapshot) []flock.TargetPipeline {
	return nil
}
func (emptyPipeline) PipelineForSecret(string, string, flock.Snapshot) []flock.PipelineSecretRow {
	return nil
}

// NewServer wires the HTTP handler graph using the supplied dependencies.
// snap, health, events, status are typically a Provider, Prober, Aggregator,
// and StatusAggregator.
func NewServer(
	logger *slog.Logger,
	ready *atomic.Bool,
	snap Snapshotter,
	health HealthSnapshotter,
	events EventSnapshotter,
	status StatusSnapshotter,
	ws WSHandler,
	pipeline PipelineSnapshotter,
) *Server {
	mux := http.NewServeMux()
	addRoutes(mux, logger, ready, snap, health, events, status, ws, pipeline)
	renderer, err := ui.NewRenderer()
	if err != nil {
		// Templates are embedded at compile time; a parse failure is a
		// programmer error, surface it loudly.
		panic(fmt.Errorf("ui renderer: %w", err))
	}
	addUIRoutes(mux, logger, renderer, snap, health, status, pipeline, events)
	return &Server{handler: mux, ready: ready}
}

// NewServerBare returns a Server with no snapshot dependencies. Used by
// Phase A tests that exercise only /healthz and /readyz.
func NewServerBare(logger *slog.Logger, ready *atomic.Bool) *Server {
	s := emptySnap{}
	// Phase A /readyz test seeds an unready atomic.Bool; preserve that.
	// Snap.Ready() always returns true, but /readyz is gated on the atomic.Bool
	// not on snap.Ready, so the test still passes.
	return NewServer(logger, ready, s, s, s, emptyStatus{}, nil, emptyPipeline{})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// markReady is a test seam used by Phase A2.
func (s *Server) markReady() { s.ready.Store(true) }
