package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func baseEnv() map[string]string {
	return map[string]string{
		"WRANGLER_ADDR":              "127.0.0.1:0",
		"WRANGLER_REQUIRED_SCOPE":    "raven:provision",
		"WRANGLER_IMAGE":             testImage,
		"WRANGLER_ARGO_REPO_URL":     "ssh://git@example.com/argocd.git",
		"WRANGLER_ARGO_BASE_BRANCH":  "master",
		"WRANGLER_CLUSTER_DOMAIN":    "apps.example.com",
		"WRANGLER_OIDC_ISSUER":       "https://issuer.example.com",
		"WRANGLER_OIDC_AUDIENCE":     "wrangler",
		"VAULT_ADDR":                 "https://vault.example.com",
		"VAULT_TOKEN":                "s.roottoken",
		"WRANGLER_GIT_SSH_KEY":       "/secret/sshKey",
		"WRANGLER_GIT_KNOWN_HOSTS":   "/secret/known_hosts",
		"WRANGLER_ARGO_DEST_SERVER":  "https://kubernetes.default.svc",
		"WRANGLER_AWS_REGION":        "eu-north-1",
		"WRANGLER_AWS_SECRET_PREFIX": "/nt/vault",
		"WRANGLER_AWS_ROLE_NAME":     "nt-los-vault-integration",
	}
}

func getenvFrom(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

// Each required setting must be named when it is absent, so a misconfigured
// deployment fails at startup rather than on the first request.
func TestLoadConfig_RequiresSettings(t *testing.T) {
	t.Parallel()

	required := []string{
		"WRANGLER_REQUIRED_SCOPE",
		"WRANGLER_IMAGE",
		"WRANGLER_ARGO_REPO_URL",
		"WRANGLER_OIDC_ISSUER",
		"WRANGLER_OIDC_AUDIENCE",
		"VAULT_ADDR",
	}

	for _, key := range required {
		t.Run(key, func(t *testing.T) {
			t.Parallel()

			env := baseEnv()
			delete(env, key)

			_, err := loadConfig(getenvFrom(env))
			if err == nil {
				t.Fatalf("missing %s was accepted", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error %q does not name %s", err, key)
			}
		})
	}
}

func TestLoadConfig_ReadsRequiredScope(t *testing.T) {
	t.Parallel()

	env := baseEnv()
	env["WRANGLER_REQUIRED_SCOPE"] = "raven:admin"

	cfg, err := loadConfig(getenvFrom(env))
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.requiredScope != "raven:admin" {
		t.Errorf("requiredScope = %q, want raven:admin", cfg.requiredScope)
	}
}

func TestLoadConfig_ReadsArgoBitbucketToken(t *testing.T) {
	t.Parallel()
	env := baseEnv()
	env["WRANGLER_BITBUCKET_TOKEN"] = "sec-token"
	env["WRANGLER_ARGO_BITBUCKET_TOKEN"] = "argo-token"

	cfg, err := loadConfig(getenvFrom(env))
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.argoBitbucketToken != "argo-token" || cfg.bitbucketToken != "sec-token" {
		t.Fatal("ArgoCD and SEC tokens must be loaded independently")
	}
}

func TestLoadConfig_ReadsRoutingRepository(t *testing.T) {
	t.Parallel()
	env := baseEnv()
	env["WRANGLER_ROUTING_REPO_URL"] = "ssh://git@example.com/routing.git"
	env["WRANGLER_ROUTING_BASE_BRANCH"] = "main"

	cfg, err := loadConfig(getenvFrom(env))
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.routingRepoURL != env["WRANGLER_ROUTING_REPO_URL"] || cfg.routingBaseBranch != "main" {
		t.Fatalf("routing config = (%q, %q)", cfg.routingRepoURL, cfg.routingBaseBranch)
	}
}

// The namespace default is what keeps wrangler's RBAC a Role rather than a
// ClusterRole, so it must not silently fall back to all-namespaces.
func TestLoadConfig_NamespaceDefaultsToSSG(t *testing.T) {
	t.Parallel()

	cfg, err := loadConfig(getenvFrom(baseEnv()))
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.namespace != "ssg" {
		t.Errorf("namespace = %q, want ssg", cfg.namespace)
	}
}

// Bitbucket is optional, but half-configuring it is a mistake worth catching
// at startup rather than on the first provision.
func TestLoadConfig_BitbucketTokenRequiredWithURL(t *testing.T) {
	t.Parallel()

	env := baseEnv()
	env["WRANGLER_BITBUCKET_URL"] = "https://bitbucket.example.com"

	_, err := loadConfig(getenvFrom(env))
	if err == nil {
		t.Fatal("bitbucket url without a token was accepted")
	}
	if !strings.Contains(err.Error(), "WRANGLER_BITBUCKET_TOKEN") {
		t.Errorf("error %q does not name WRANGLER_BITBUCKET_TOKEN", err)
	}
}

// A missing user silently falls back to registering an access key, which
// Bitbucket rejects for a key already bound to an account.
func TestLoadConfig_BitbucketUserRequiredWithURL(t *testing.T) {
	t.Parallel()

	env := baseEnv()
	env["WRANGLER_BITBUCKET_URL"] = "https://bitbucket.example.com"
	env["WRANGLER_BITBUCKET_TOKEN"] = "token"
	env["WRANGLER_GIT_SSH_KEY"] = "/secret/ssh-privatekey"

	_, err := loadConfig(getenvFrom(env))
	if err == nil {
		t.Fatal("bitbucket url without a user was accepted")
	}
	if !strings.Contains(err.Error(), "WRANGLER_BITBUCKET_USER") {
		t.Errorf("error %q does not name WRANGLER_BITBUCKET_USER", err)
	}
}

// Without the reader key a provisioned repository is invisible to ArgoCD, and
// the raven only fails once its Application refuses to sync.
func TestLoadConfig_ArgocdReaderKeyRequiredWithURL(t *testing.T) {
	t.Parallel()

	env := baseEnv()
	env["WRANGLER_BITBUCKET_URL"] = "https://bitbucket.example.com"
	env["WRANGLER_BITBUCKET_TOKEN"] = "token"
	env["WRANGLER_BITBUCKET_USER"] = "kts_builder"
	env["WRANGLER_GIT_SSH_KEY"] = "/secret/ssh-privatekey"

	_, err := loadConfig(getenvFrom(env))
	if err == nil {
		t.Fatal("bitbucket url without an argocd reader key was accepted")
	}
	if !strings.Contains(err.Error(), "WRANGLER_ARGOCD_READER_KEY") {
		t.Errorf("error %q does not name WRANGLER_ARGOCD_READER_KEY", err)
	}
}

func TestLoadConfig_BitbucketOptional(t *testing.T) {
	t.Parallel()

	cfg, err := loadConfig(getenvFrom(baseEnv()))
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.bitbucketURL != "" {
		t.Errorf("bitbucketURL = %q, want empty", cfg.bitbucketURL)
	}
}

// Host key checking is only skippable by explicit opt-in.
func TestLoadConfig_KnownHostsRequiredForSSH(t *testing.T) {
	t.Parallel()

	env := baseEnv()
	delete(env, "WRANGLER_GIT_KNOWN_HOSTS")

	if _, err := loadConfig(getenvFrom(env)); err == nil {
		t.Fatal("ssh remote without known_hosts was accepted")
	}

	env["WRANGLER_GIT_INSECURE_SKIP_HOST_KEY"] = "true"
	if _, err := loadConfig(getenvFrom(env)); err != nil {
		t.Fatalf("explicit opt-out rejected: %v", err)
	}
}

func TestNewServer_HealthzNeedsNoAuth(t *testing.T) {
	t.Parallel()

	srv := NewServer(serverDeps{logger: testLogger(io.Discard)})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// The provisioning route must sit behind the gate, not beside it.
func TestNewServer_CreateRouteIsGuarded(t *testing.T) {
	t.Parallel()

	deps, _, _, publisher := newTestDeps()
	srv := NewServer(serverDeps{
		create:        deps,
		verifier:      fakeVerifier{subject: "intruder", scopes: []string{"raven:read"}},
		requiredScope: "raven:provision",
		logger:        testLogger(io.Discard),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ravens", strings.NewReader(validBody()))
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if publisher.callCount() != 0 {
		t.Error("an unauthorised caller reached the publisher")
	}
}

// Reading rollout status is deliberately open so flock can poll it without
// holding a provisioning credential.
func TestNewServer_RolloutsNeedNoAuth(t *testing.T) {
	t.Parallel()

	deps, _, _, _ := newTestDeps()
	srv := NewServer(serverDeps{
		create:        deps,
		verifier:      fakeVerifier{err: errors.New("no token supplied")},
		requiredScope: "raven:provision",
		logger:        testLogger(io.Discard),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rollouts", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"rollouts"`) {
		t.Errorf("unexpected body: %s", rec.Body)
	}
}

func TestRun_ReportsConfigErrors(t *testing.T) {
	t.Parallel()

	env := baseEnv()
	delete(env, "WRANGLER_IMAGE")

	err := run(context.Background(), getenvFrom(env), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("run() accepted a missing image")
	}
	if !strings.Contains(err.Error(), "WRANGLER_IMAGE") {
		t.Errorf("error %q does not name the missing setting", err)
	}
}
