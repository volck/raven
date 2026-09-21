package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/volck/raven/internal/auth"
	"github.com/volck/raven/internal/provision"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Getenv, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "wrangler: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer) error {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{AddSource: true}))

	vaultClient, err := newVaultClient(cfg)
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}

	clientset, dyn, err := newClusterClients()
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	gitAuth, err := provision.NewGitAuth(cfg.argoRepoURL, cfg.gitSSHKey, cfg.gitKnownHosts, cfg.gitInsecure)
	if err != nil {
		return fmt.Errorf("git auth: %w", err)
	}

	verifier, err := auth.NewTokenVerifier(ctx, cfg.oidcIssuer, cfg.oidcAudience)
	if err != nil {
		return fmt.Errorf("oidc verifier: %w", err)
	}

	applier := newClusterApplier(clientset, dyn, ravenDefaults{
		Env:           ravenEnvFrom(getenv),
		Mounts:        defaultMounts(),
		AWS:           cfg.aws,
		ClusterDomain: cfg.clusterDomain,
	})

	rollouts := newJournal(cfg.journalSize)

	repos, err := newRepos(cfg, gitAuth, logger)
	if err != nil {
		return err
	}

	srv := newHTTPServer(cfg.addr, NewServer(serverDeps{
		create: createDeps{
			vault:     newVaultProvisioner(vaultClient),
			applier:   applier,
			publisher: provision.NewPublisher(cfg.argoRepoURL, cfg.argoBaseBranch, gitAuth),
			repos:     repos,
			appConfig: cfg.appConfig,
			image:     cfg.image,
			namespace: cfg.namespace,
			journal:   rollouts,
			logger:    logger,
		},
		verifier:      verifier,
		requiredScope: cfg.requiredScope,
		deployments:   newDeploymentReader(clientset, cfg.namespace),
		logger:        logger,
	}))

	errc := make(chan error, 1)
	go func() {
		logger.Info("wrangler listening", "addr", cfg.addr)
		fmt.Fprintf(stdout, "wrangler listening on %s\n", cfg.addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func newVaultClient(cfg config) (*vaultapi.Client, error) {
	vaultCfg := vaultapi.DefaultConfig()
	vaultCfg.Address = cfg.vaultAddr

	client, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		return nil, err
	}
	client.SetToken(cfg.vaultToken)
	return client, nil
}

func newClusterClients() (kubernetes.Interface, dynamic.Interface, error) {
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, err
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, nil, err
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, nil, err
	}
	return clientset, dyn, nil
}

// ravenEnvFrom collects the settings passed through to every raven verbatim.
func ravenEnvFrom(getenv func(string) string) map[string]string {
	passthrough := []string{
		"VAULTENDPOINT",
		"CLONE_PATH",
		"CERT_FILE",
		"LOGLEVEL",
		"DOCUMENTATION_KEYS",
		"KUBERNETESMONITOR",
		"KUBERNETESREMOVE",
		"KUBERNETES_ROLLOUT",
		"CACHE_STABLE_THRESHOLD",
		"CACHE_CHECK_INTERVAL",
		"NORMAL_CHECK_INTERVAL",
		"SLEEP_TIME",
	}

	env := map[string]string{}
	for _, key := range passthrough {
		if value := getenv("RAVEN_" + key); value != "" {
			env[key] = value
		}
	}
	return env
}

func defaultMounts() []mountedSecret {
	return []mountedSecret{
		{SecretName: "ssgsshprivatekey", MountPath: "/secret", Key: "ssh-privatekey", Path: "sshKey", ReadOnly: true},
		{SecretName: "ssc", MountPath: "/mg/secret/ssc"},
		{SecretName: "ntrootcert", MountPath: "/tmp/cert/"},
	}
}
