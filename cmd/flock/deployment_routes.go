package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	wrclient "github.com/volck/raven/internal/flock/wrangler"
)

// DeploymentFetcher reads live workload state from wrangler, which holds the
// cluster credentials flock deliberately does not. It is nil when no wrangler
// is configured.
type DeploymentFetcher interface {
	Deployment(ctx context.Context, name string) (*wrclient.Deployment, error)
}

func addDeploymentRoutes(mux *http.ServeMux, logger *slog.Logger, snap Snapshotter, deployments DeploymentFetcher) {
	mux.Handle("GET /api/v1/ravens/{name}/deployment", requireReady(snap, handleGetRavenDeployment(logger, snap, deployments)))
}

func handleGetRavenDeployment(logger *slog.Logger, snap Snapshotter, deployments DeploymentFetcher) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, ok := snap.Snapshot().Routing[name]; !ok {
			http.NotFound(w, r)
			return
		}

		if deployments == nil {
			_ = writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no wrangler configured"})
			return
		}

		deployment, err := deployments.Deployment(r.Context(), name)
		switch {
		case errors.Is(err, wrclient.ErrNotFound):
			http.NotFound(w, r)
			return
		case err != nil:
			logger.Warn("deployment.fetch_failed", "err", err.Error(), "name", name)
			_ = writeJSON(w, http.StatusBadGateway, map[string]string{"error": "wrangler unavailable"})
			return
		}

		if err := writeJSON(w, http.StatusOK, deployment); err != nil {
			logger.Warn("deployment.encode_failed", "err", err.Error(), "name", name)
		}
	})
}
