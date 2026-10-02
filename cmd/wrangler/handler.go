package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"

	"github.com/volck/raven/internal/auditlog"
	"github.com/volck/raven/internal/provision"
)

const maxRequestBody = 64 << 10

type vaultProvisioning interface {
	EnsureEngine(ctx context.Context, engine string) error
	EnsurePolicy(ctx context.Context, name, engine string) error
	CreateToken(ctx context.Context, policy string) (string, error)
	RevokeToken(ctx context.Context, token string) error
}

type ravenApplier interface {
	Preflight(ctx context.Context, spec provision.RavenSpec, force bool) error
	TokenSecretExists(ctx context.Context, spec provision.RavenSpec) (bool, error)
	Apply(ctx context.Context, spec provision.RavenSpec, token string) error
	Delete(ctx context.Context, spec provision.RavenSpec) error
}

type ravenPublisher interface {
	Publish(ctx context.Context, spec provision.RavenSpec, files []provision.File) (string, error)
}

type repoProvisioner interface {
	EnsureRepo(ctx context.Context, spec provision.RavenSpec) error
}

type createDeps struct {
	vault     vaultProvisioning
	applier   ravenApplier
	publisher ravenPublisher
	// routingPublisher is nil when git-backed logparser routing is unconfigured.
	routingPublisher ravenPublisher
	// repos is nil when Bitbucket is not configured, which skips the stage.
	repos         repoProvisioner
	appConfig     provision.ApplicationConfig
	image         string
	clusterDomain string
	// namespace is the only namespace wrangler holds RBAC in, so callers do
	// not get to choose one.
	namespace string
	journal   *journal
	logger    *slog.Logger
}

// createRequest is the caller-supplied part of a spec. The image and namespace
// are deliberately absent: wrangler decides what runs in the cluster, and where.
type createRequest struct {
	Name         string `json:"name"`
	SecretEngine string `json:"secretEngine"`
	DestEnv      string `json:"destEnv"`
	RepoURL      string `json:"repoURL"`
	RouteHost    string `json:"routeHost"`
	AWSWriteback bool   `json:"awsWriteback"`
	// Force replaces a raven that already exists instead of rejecting it.
	Force bool `json:"force"`
}

type createResponse struct {
	Branch    string        `json:"branch,omitempty"`
	Engine    string        `json:"engine,omitempty"`
	Namespace string        `json:"namespace,omitempty"`
	Error     string        `json:"error,omitempty"`
	Stages    []stageResult `json:"stages,omitempty"`
}

func policyName(spec provision.RavenSpec) string {
	return "raven-" + spec.Name
}

func handleCreateRaven(deps createDeps) http.Handler {
	logger := deps.logger
	if logger == nil {
		logger = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		spec, force, err := decodeSpec(w, r, deps.image, deps.namespace)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		actor := "unknown"
		if claims, ok := claimsFrom(r.Context()); ok {
			actor = claims.Subject
		}

		branch, report, err := provisionRaven(r.Context(), deps, spec, force)

		if deps.journal != nil {
			entry := rollout{
				Raven:     spec.Name,
				Namespace: spec.Namespace,
				Engine:    spec.SecretEngine,
				Actor:     actor,
				Branch:    branch,
				Succeeded: err == nil,
				Stages:    report.results(),
			}
			if err != nil {
				entry.Error = report.scrub(err.Error())
			}
			deps.journal.record(entry)
		}

		audit := []any{
			"actor", actor,
			"raven", spec.Name,
			"namespace", spec.Namespace,
			"engine", spec.SecretEngine,
			"policy", policyName(spec),
			"force", force,
			"stages", report.summary(),
		}

		if err != nil {
			status := http.StatusInternalServerError
			var stageErr *stageError
			if errors.As(err, &stageErr) && stageErr.stage == stagePreflight {
				status = http.StatusConflict
			}

			logger.ErrorContext(r.Context(), "provisioning failed", append(audit, "error", err, "status", status)...)
			if report.orphanedToken() {
				logger.ErrorContext(r.Context(), "orphaned vault token: minted but the raven was not created", audit...)
			}

			writeJSON(w, status, createResponse{Error: err.Error(), Stages: report.results()}, logger, r)
			return
		}

		logger.InfoContext(r.Context(), "raven provisioned", append(audit, "branch", branch)...)

		writeJSON(w, http.StatusAccepted, createResponse{
			Branch:    branch,
			Engine:    spec.SecretEngine,
			Namespace: spec.Namespace,
			Stages:    report.results(),
		}, logger, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, body createResponse, logger *slog.Logger, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.ErrorContext(r.Context(), "write response", "error", err)
	}
}

func decodeSpec(w http.ResponseWriter, r *http.Request, image, namespace string) (provision.RavenSpec, bool, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var req createRequest
	if err := decoder.Decode(&req); err != nil {
		return provision.RavenSpec{}, false, err
	}

	spec := provision.RavenSpec{
		Name:         req.Name,
		Namespace:    namespace,
		SecretEngine: req.SecretEngine,
		DestEnv:      req.DestEnv,
		RepoURL:      req.RepoURL,
		RouteHost:    req.RouteHost,
		AWSWriteback: req.AWSWriteback,
		Image:        image,
	}
	if err := spec.Validate(); err != nil {
		return provision.RavenSpec{}, false, err
	}
	return spec, req.Force, nil
}

const (
	stagePreflight = "preflight"
	stageRepo      = "repo"
	stageVault     = "vault"
	stageCluster   = "cluster"
	stageRouting   = "routing"
	stageGit       = "git"
)

type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return fmt.Sprintf("%s: %v", e.stage, e.err) }
func (e *stageError) Unwrap() error { return e.err }

// provisionRaven runs the stages in the only safe order: prerequisites before
// a token is minted, the cluster before the branch a human will approve.
func provisionRaven(ctx context.Context, deps createDeps, spec provision.RavenSpec, force bool) (string, *progress, error) {
	report := newProgress(stagePreflight, stageRepo, stageVault, stageCluster, stageRouting, stageGit)

	fail := func(stage string, err error) (string, *progress, error) {
		report.set(stage, statusFailed, err.Error())
		return "", report, &stageError{stage, err}
	}

	if err := deps.applier.Preflight(ctx, spec, force); err != nil {
		return fail(stagePreflight, err)
	}
	report.set(stagePreflight, statusDone, "")

	// Before the token: a repository failure must not leave a credential behind.
	switch {
	case deps.repos == nil:
		report.set(stageRepo, statusSkipped, "bitbucket not configured")
	default:
		if err := deps.repos.EnsureRepo(ctx, spec); err != nil {
			return fail(stageRepo, err)
		}
		report.set(stageRepo, statusDone, "")
	}

	token, reused, err := mintToken(ctx, deps, spec)
	if err != nil {
		return fail(stageVault, err)
	}
	report.redact(token)
	if reused {
		report.set(stageVault, statusSkipped, "token secret already present")
	} else {
		report.set(stageVault, statusDone, "")
	}

	// Last possible moment: everything that could still fail has passed, so a
	// forced recreate does not tear down a working raven for nothing.
	if force {
		if err := deps.applier.Delete(ctx, spec); err != nil {
			return fail(stageCluster, err)
		}
	}

	if err := deps.applier.Apply(ctx, spec, token); err != nil {
		if !reused {
			rollBackToken(ctx, deps, spec, token, report)
		}
		return fail(stageCluster, err)
	}
	report.set(stageCluster, statusDone, "")

	if deps.routingPublisher == nil {
		report.set(stageRouting, statusSkipped, "routing repository not configured")
	} else {
		files, err := renderRouting(spec, deps.clusterDomain)
		if err != nil {
			return fail(stageRouting, err)
		}
		if _, err := deps.routingPublisher.Publish(ctx, spec, files); err != nil {
			return fail(stageRouting, err)
		}
		report.set(stageRouting, statusDone, "")
	}

	if err := ctx.Err(); err != nil {
		return fail(stageGit, err)
	}

	files, err := provision.Render(spec, deps.appConfig)
	if err != nil {
		return fail(stageGit, err)
	}
	branch, err := deps.publisher.Publish(ctx, spec, files)
	if err != nil {
		return fail(stageGit, err)
	}
	report.set(stageGit, statusDone, "")

	return branch, report, nil
}

func renderRouting(spec provision.RavenSpec, clusterDomain string) ([]provision.File, error) {
	host := spec.RouteHost
	if host == "" {
		host = spec.DefaultRouteHost(clusterDomain)
	}
	cfg := auditlog.RoutingConfig{
		SecretEngines: []string{spec.SecretEngine},
		Routing:       map[string][]string{spec.SecretEngine: {"https://" + host}},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode routing: %w", err)
	}
	return []provision.File{{Name: path.Join("routes", spec.Name+".json"), Data: append(data, '\n')}}, nil
}

// rollBackToken revokes a credential that never reached the cluster. If the
// token Secret did land, a retry will reuse it and revoking would strand the
// raven, so it is left alone and stays flagged as orphaned.
func rollBackToken(ctx context.Context, deps createDeps, spec provision.RavenSpec, token string, report *progress) {
	landed, err := deps.applier.TokenSecretExists(ctx, spec)
	if err != nil || landed {
		return
	}

	if err := deps.vault.RevokeToken(ctx, token); err != nil {
		report.set(stageVault, statusDone, "token could not be revoked: "+err.Error())
		return
	}
	report.set(stageVault, statusRolledBack, "token revoked; it never reached the cluster")
}

// A token already in the cluster is reused, so a retried request does not
// leave a second 20-year credential behind.
func mintToken(ctx context.Context, deps createDeps, spec provision.RavenSpec) (token string, reused bool, err error) {
	exists, err := deps.applier.TokenSecretExists(ctx, spec)
	if err != nil {
		return "", false, err
	}
	if exists {
		return "", true, nil
	}

	if err := deps.vault.EnsureEngine(ctx, spec.SecretEngine); err != nil {
		return "", false, err
	}
	if err := deps.vault.EnsurePolicy(ctx, policyName(spec), spec.SecretEngine); err != nil {
		return "", false, err
	}
	token, err = deps.vault.CreateToken(ctx, policyName(spec))
	return token, false, err
}
