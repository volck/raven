package main

import (
	"log/slog"
	"net/http"

	"github.com/volck/raven/internal/auditlog"
)

// Snapshotter is the read-only view of routing state the HTTP handlers depend on.
type Snapshotter interface {
	Snapshot() auditlog.RoutingConfig
}

// ReadyChecker reports whether the underlying routing provider has loaded
// at least once. The /readyz handler delegates to it.
type ReadyChecker interface {
	Ready() bool
}

// staticSnapshot adapts a LogParserConfig to Snapshotter so the HTTP layer
// can serve the static, file-loaded routing until the live Provider is
// wired in (Phase H).
type staticSnapshot auditlog.LogParserConfig

func (s staticSnapshot) Snapshot() auditlog.RoutingConfig {
	return auditlog.RoutingConfig{
		SecretEngines: append([]string(nil), s.SecretEngines...),
		Routing:       s.Routing,
	}
}

// alwaysReady satisfies ReadyChecker for paths where readiness has no
// meaningful pre-load state (e.g. static file config).
type alwaysReady struct{}

func (alwaysReady) Ready() bool { return true }

// NewServer wires the HTTP handler graph for the logparser.
// It takes all dependencies as positional args (Mat Ryer style) and returns
// a top-level http.Handler with all middleware applied.
func NewServer(logger *slog.Logger, snap Snapshotter, ready ReadyChecker) http.Handler {
	mux := http.NewServeMux()
	addRoutes(mux, logger, snap, ready)
	var handler http.Handler = mux
	return handler
}
