package main

import (
	"log/slog"
	"net/http"
)

type serverDeps struct {
	create        createDeps
	deployments   deploymentStatuser
	verifier      tokenVerifier
	requiredScope string
	logger        *slog.Logger
}

// NewServer wires the handler graph. Routes are registered only in addRoutes.
func NewServer(deps serverDeps) http.Handler {
	mux := http.NewServeMux()
	addRoutes(mux, deps)
	return mux
}

func addRoutes(mux *http.ServeMux, deps serverDeps) {
	mux.Handle("/healthz", handleHealthz())
	mux.Handle("/api/v1/ravens", authMiddleware(deps.verifier, deps.requiredScope)(handleCreateRaven(deps.create)))
	// Provisioning is gated; reading rollout status is not.
	mux.Handle("GET /api/v1/rollouts", handleListRollouts(deps.create.journal))
	mux.Handle("GET /api/v1/ravens/{name}/deployment", handleGetDeployment(deps.deployments, deps.logger))
}

func handleHealthz() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}
