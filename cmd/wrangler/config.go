package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/volck/raven/internal/provision"
)

type config struct {
	addr string
	// requiredScope is the OAuth2 scope a caller must be granted to provision.
	requiredScope string
	// namespace is the only namespace wrangler provisions into and reads
	// status from, which keeps its RBAC to a single Role.
	namespace      string
	image          string
	clusterDomain  string
	oidcIssuer     string
	oidcAudience   string
	vaultAddr      string
	vaultToken     string
	argoRepoURL    string
	argoBaseBranch string
	appConfig      provision.ApplicationConfig
	aws            awsSettings
	// bitbucketURL empty disables repository provisioning.
	bitbucketURL   string
	bitbucketToken string
	// bitbucketUser owns the ssh key, when that key belongs to an account
	// rather than being a standalone deploy key.
	bitbucketUser string
	// argocdReaderKey is ArgoCD's public ssh key, granted read-only access on
	// every provisioned repository so its Application can sync.
	argocdReaderKey string
	gitSSHKey       string
	gitKnownHosts   string
	gitInsecure     bool
	journalSize     int
}

func loadConfig(getenv func(string) string) (config, error) {
	cfg := config{
		// Plaintext: TLS is terminated at the edge Route.
		addr:           valueOr(getenv("WRANGLER_ADDR"), ":8080"),
		requiredScope:  getenv("WRANGLER_REQUIRED_SCOPE"),
		namespace:      valueOr(getenv("WRANGLER_NAMESPACE"), "ssg"),
		image:          getenv("WRANGLER_IMAGE"),
		clusterDomain:  getenv("WRANGLER_CLUSTER_DOMAIN"),
		oidcIssuer:     getenv("WRANGLER_OIDC_ISSUER"),
		oidcAudience:   getenv("WRANGLER_OIDC_AUDIENCE"),
		vaultAddr:      getenv("VAULT_ADDR"),
		vaultToken:     getenv("VAULT_TOKEN"),
		argoRepoURL:    getenv("WRANGLER_ARGO_REPO_URL"),
		argoBaseBranch: valueOr(getenv("WRANGLER_ARGO_BASE_BRANCH"), "master"),
		appConfig: provision.ApplicationConfig{
			TargetRevision: valueOr(getenv("WRANGLER_ARGO_TARGET_REVISION"), "HEAD"),
			DestServer:     valueOr(getenv("WRANGLER_ARGO_DEST_SERVER"), "https://kubernetes.default.svc"),
		},
		aws: awsSettings{
			Region:       getenv("WRANGLER_AWS_REGION"),
			SecretPrefix: getenv("WRANGLER_AWS_SECRET_PREFIX"),
			RoleName:     getenv("WRANGLER_AWS_ROLE_NAME"),
		},
		gitSSHKey:     getenv("WRANGLER_GIT_SSH_KEY"),
		gitKnownHosts: getenv("WRANGLER_GIT_KNOWN_HOSTS"),
		gitInsecure:   getenv("WRANGLER_GIT_INSECURE_SKIP_HOST_KEY") == "true",
		journalSize:   intOr(getenv("WRANGLER_ROLLOUT_HISTORY"), 50),

		bitbucketURL:    getenv("WRANGLER_BITBUCKET_URL"),
		bitbucketToken:  getenv("WRANGLER_BITBUCKET_TOKEN"),
		bitbucketUser:   getenv("WRANGLER_BITBUCKET_USER"),
		argocdReaderKey: strings.TrimSpace(getenv("WRANGLER_ARGOCD_READER_KEY")),
	}

	required := map[string]string{
		"WRANGLER_IMAGE":          cfg.image,
		"WRANGLER_ARGO_REPO_URL":  cfg.argoRepoURL,
		"WRANGLER_OIDC_ISSUER":    cfg.oidcIssuer,
		"WRANGLER_OIDC_AUDIENCE":  cfg.oidcAudience,
		"WRANGLER_REQUIRED_SCOPE": cfg.requiredScope,
		"VAULT_ADDR":              cfg.vaultAddr,
		"VAULT_TOKEN":             cfg.vaultToken,
	}
	missing := []string{}
	for key, value := range required {
		if value == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return config{}, fmt.Errorf("missing required configuration: %s", strings.Join(sorted(missing), ", "))
	}

	if isSSHRemote(cfg.argoRepoURL) && cfg.gitKnownHosts == "" && !cfg.gitInsecure {
		return config{}, fmt.Errorf("WRANGLER_GIT_KNOWN_HOSTS is required for %s (set WRANGLER_GIT_INSECURE_SKIP_HOST_KEY=true to override)", cfg.argoRepoURL)
	}

	if cfg.bitbucketURL != "" && cfg.bitbucketToken == "" {
		return config{}, fmt.Errorf("WRANGLER_BITBUCKET_TOKEN is required when WRANGLER_BITBUCKET_URL is set")
	}
	if cfg.bitbucketURL != "" && cfg.gitSSHKey == "" {
		return config{}, fmt.Errorf("WRANGLER_GIT_SSH_KEY is required when WRANGLER_BITBUCKET_URL is set: seeding a provisioned repository pushes with it")
	}
	if cfg.bitbucketURL != "" && cfg.bitbucketUser == "" {
		return config{}, fmt.Errorf("WRANGLER_BITBUCKET_USER is required when WRANGLER_BITBUCKET_URL is set: it names the account granted write access to provisioned repositories")
	}
	if cfg.bitbucketURL != "" && cfg.argocdReaderKey == "" {
		return config{}, fmt.Errorf("WRANGLER_ARGOCD_READER_KEY is required when WRANGLER_BITBUCKET_URL is set: argocd reads provisioned repositories with it")
	}

	return cfg, nil
}

func isSSHRemote(url string) bool {
	return strings.HasPrefix(url, "ssh://") || strings.HasPrefix(url, "git@")
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func intOr(raw string, fallback int) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return fallback
	}
	return value
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
