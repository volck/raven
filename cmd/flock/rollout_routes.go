package main

import (
	"log/slog"
	"net/http"

	wrclient "github.com/volck/raven/internal/flock/wrangler"
)

// RolloutSnapshotter serves the provisioning attempts flock has polled from
// wrangler. It is nil when no wrangler is configured.
type RolloutSnapshotter interface {
	Rollouts() []wrclient.Rollout
	RolloutsForEngine(engine string) []wrclient.Rollout
}

type rolloutsBody struct {
	Rollouts []wrclient.Rollout `json:"rollouts"`
}

func addRolloutRoutes(mux *http.ServeMux, logger *slog.Logger, snap Snapshotter, rollouts RolloutSnapshotter) {
	mux.Handle("GET /api/v1/rollouts", requireReady(snap, handleListRollouts(logger, rollouts)))
	mux.Handle("GET /api/v1/ravens/{name}/rollouts", requireReady(snap, handleGetRavenRollouts(logger, snap, rollouts)))
}

func handleListRollouts(logger *slog.Logger, rollouts RolloutSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := rolloutsBody{Rollouts: []wrclient.Rollout{}}
		if rollouts != nil {
			if got := rollouts.Rollouts(); got != nil {
				body.Rollouts = got
			}
		}
		if err := writeJSON(w, http.StatusOK, body); err != nil {
			logger.Warn("rollouts.encode_failed", "err", err.Error())
		}
	})
}

func handleGetRavenRollouts(logger *slog.Logger, snap Snapshotter, rollouts RolloutSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, ok := snap.Snapshot().Routing[name]; !ok {
			http.NotFound(w, r)
			return
		}

		body := rolloutsBody{Rollouts: []wrclient.Rollout{}}
		if rollouts != nil {
			if got := rollouts.RolloutsForEngine(name); got != nil {
				body.Rollouts = got
			}
		}
		if err := writeJSON(w, http.StatusOK, body); err != nil {
			logger.Warn("rollouts.encode_failed", "err", err.Error(), "name", name)
		}
	})
}
