package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

type deploymentStatuser interface {
	Status(ctx context.Context, name string) (*deploymentStatus, error)
}

// handleGetDeployment reports the live workload state for one raven. It is
// ungated, like the rollout feed: it exposes no secrets, only whether the
// thing is running.
func handleGetDeployment(deployments deploymentStatuser, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if deployments == nil {
			http.Error(w, "deployment status unavailable", http.StatusServiceUnavailable)
			return
		}

		status, err := deployments.Status(r.Context(), r.PathValue("name"))
		if errors.Is(err, errRavenNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			logger.ErrorContext(r.Context(), "read deployment status", "raven", r.PathValue("name"), "err", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(status); err != nil {
			logger.ErrorContext(r.Context(), "write deployment status", "err", err)
		}
	})
}
