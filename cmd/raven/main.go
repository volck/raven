package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	ravenapi "github.com/volck/raven/internal/api"
	"github.com/volck/raven/internal/auth"
	awspkg "github.com/volck/raven/internal/aws"
	"github.com/volck/raven/internal/config"
	"github.com/volck/raven/internal/gitops"
	"github.com/volck/raven/internal/helpers"
	"github.com/volck/raven/internal/k8s"
	"github.com/volck/raven/internal/sealedsecret"
	"github.com/volck/raven/internal/store"
	vaultpkg "github.com/volck/raven/internal/vault"
)

var cfgFile string
var newConfig config.Config
var k8sWatcher *k8s.Watcher

var currentSecrets = map[string]*api.Secret{}
var secretNameLog []string

var rootCmd = &cobra.Command{
	Use:   "raven",
	Short: "Raven is a tool for managing secrets",
	Long:  `Raven is a CLI tool for managing secrets in Vault and synchronizing them across different environments.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := initializeConfig()
		startRaven(cfg)
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)

	rootCmd.Flags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.raven.yaml)")
	rootCmd.Flags().String("token", "", "token used for to grab secrets from Vault")
	rootCmd.Flags().String("se", "", "specifies secret engine to grab secrets from in Vault")
	rootCmd.Flags().String("vaultendpoint", "", "URL to the Vault installation.")
	rootCmd.Flags().String("cert", "", "used to create sealed secrets")
	rootCmd.Flags().String("repourl", "", "REPO url.")
	rootCmd.Flags().String("clonepath", "", "Path in which to clone repo and used for base for appending keys.")
	rootCmd.Flags().String("dest", "", "destination env in git repository to output SealedSecrets to.")
	rootCmd.Flags().String("loglevel", "INFO", "loglevel")
	rootCmd.Flags().Int("sleep", 360, "define how long Raven should sleep between each iteration")

	viper.BindPFlag("token", rootCmd.Flags().Lookup("token"))
	viper.BindPFlag("secretEngine", rootCmd.Flags().Lookup("se"))
	viper.BindPFlag("vaultEndpoint", rootCmd.Flags().Lookup("vaultendpoint"))
	viper.BindPFlag("pemFile", rootCmd.Flags().Lookup("cert"))
	viper.BindPFlag("repoUrl", rootCmd.Flags().Lookup("repourl"))
	viper.BindPFlag("clonePath", rootCmd.Flags().Lookup("clonepath"))
	viper.BindPFlag("loglevel", rootCmd.Flags().Lookup("loglevel"))
	viper.BindPFlag("destEnv", rootCmd.Flags().Lookup("dest"))
	viper.BindPFlag("sleepTime", rootCmd.Flags().Lookup("sleep"))

	viper.AutomaticEnv()
	loglevel := os.Getenv("LOGLEVEL")

	switch {
	case loglevel == "INFO":
		log.SetLevel(log.InfoLevel)
	case loglevel == "DEBUG":
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Println(err)
		}
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".raven")
	}
	viper.ReadInConfig()
}

func initializeConfig() *config.Config {
	token := flag.String("token", os.Getenv("VAULT_TOKEN"), "token used for to grab secrets from Vault")
	secretEngine := flag.String("se", os.Getenv("SECRET_ENGINE"), "specifies secret engine to grab secrets from in Vault")
	vaultEndpoint := flag.String("vaultendpoint", os.Getenv("VAULTENDPOINT"), "URL to the Vault installation.")
	pemFile := flag.String("cert", os.Getenv("CERT_FILE"), "used to create sealed secrets")
	repoUrl := flag.String("repourl", os.Getenv("REPO_URL"), "REPO url.")
	clonePath := flag.String("clonepath", os.Getenv("CLONE_PATH"), "Path in which to clone repo.")
	destEnv := flag.String("dest", os.Getenv("DEST_ENV"), "destination env in git repository.")
	sleepTime := flag.Int("sleep", helpers.GetIntEnv("SLEEP_TIME", 360), "define how long Raven should sleep between each iteration")
	awsWriteBack := flag.Bool("awsWriteBack", helpers.GetBoolEnv("AWS_WRITEBACK", false), "enable AWS writeback")

	flag.Parse()

	visited := true
	flag.VisitAll(func(f *flag.Flag) {
		if f.Value.String() == "" {
			fmt.Printf("[*] -%s not set. Quitting [*]\n", f.Name)
			visited = false
		}
	})
	if visited {
		newConfig.VaultEndpoint = *vaultEndpoint
		newConfig.SecretEngine = *secretEngine
		newConfig.Token = *token
		newConfig.DestEnv = *destEnv
		newConfig.PemFile = *pemFile
		newConfig.ClonePath = *clonePath
		newConfig.RepoUrl = *repoUrl
		newConfig.DocumentationKeys = helpers.InitAdditionalKeys()
		newConfig.SleepTime = *sleepTime

		kubernetesMonitor := os.Getenv("KUBERNETESMONITOR")
		kubernetesDelete := os.Getenv("KUBERNETESREMOVE")
		kubernetesDoRollout := os.Getenv("KUBERNETES_ROLLOUT")

		if kubernetesMonitor == "true" || kubernetesDelete == "true" {
			newConfig.Clientset = k8s.NewKubernetesClient()
		}

		if kubernetesDoRollout == "true" && newConfig.Clientset == nil {
			newConfig.Clientset = k8s.NewKubernetesClient()
		}
		if *awsWriteBack {
			newConfig.AwsWriteback = true
			newConfig.AwsAccessKeyId = os.Getenv("AWS_ACCESS_KEY_ID")
			newConfig.AwsSecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
			newConfig.AwsRegion = os.Getenv("AWS_REGION")
			newConfig.AwsSecretPrefix = os.Getenv("AWS_SECRET_PREFIX")
			newConfig.AwsNotificationUrl = os.Getenv("AWS_NOTIFICATION_WEBHOOK_URL")
			newConfig.AwsRole = os.Getenv("AWS_ROLE_NAME")
			helpers.JsonLogger.Info("AWS writeback enabled", "region", newConfig.AwsRegion, "secretprefix", newConfig.AwsSecretPrefix, "role", newConfig.AwsRole)
		}

		if kubernetesDoRollout == "true" {
			theLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			newClient := k8s.NewKubernetesClient()
			w := k8s.NewWatcher(theLogger, newClient, *destEnv)
			sufficientPermissions := w.CheckKubernetesServiceAccountPermissions()
			if sufficientPermissions {
				k8sWatcher = w
				w.MonitorNamespaceForSecretChange()
			} else {
				w.Logger.Info("ServiceAccount does not have permissions to watch namespace, exiting go routine")
			}
		}
		return &newConfig
	}
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func handleRequests(cfg config.Config, vaultClient *api.Client) *ravenapi.SecretEventHandler {
	mux := http.NewServeMux()

	// Health check — no auth required
	mux.Handle("/healthz", ravenapi.HealthzHandler())

	// Event-driven secret handler
	secretHandler := ravenapi.NewSecretEventHandler(vaultClient, cfg)

	// SQLite event store for persistent event history
	dbPath := os.Getenv("RAVEN_DB_PATH")
	if dbPath == "" {
		dbPath = "/tmp/raven-events.db"
	}
	eventStore, err := store.NewEventStore(dbPath, 500)
	if err != nil {
		helpers.JsonLogger.Warn("Failed to open event store, events will not persist across restarts", "error", err, "path", dbPath)
	} else {
		secretHandler.SetEventStore(eventStore)
		helpers.JsonLogger.Info("Event store opened", "path", dbPath)
	}

	// WebSocket hub for live dashboard updates
	hub := ravenapi.NewHub()
	secretHandler.SetHub(hub)
	mux.HandleFunc("/ws", hub.ServeWS)

	// Refresh/sync endpoints — no auth, accessible from dashboard
	mux.Handle("/api/v1/refresh", forceRefreshHandler(vaultClient, cfg))
	mux.Handle("/api/v1/refresh-secret", secretHandler.RefreshSecretHandler())

	// OIDC auth middleware when issuer is configured
	issuerURL := os.Getenv("OIDC_ISSUER_URL")
	audience := os.Getenv("OIDC_AUDIENCE")
	if issuerURL != "" && audience != "" {
		verifier, err := auth.NewTokenVerifier(context.Background(), issuerURL, audience)
		if err != nil {
			helpers.JsonLogger.Error("Failed to create OIDC token verifier", "error", err)
			helpers.WriteErrorToTerminationLog("Failed to create OIDC token verifier")
			return nil
		}
		middleware := auth.AuthMiddleware(verifier)
		mux.Handle("/api/v1/secret", middleware(secretHandler))
		helpers.JsonLogger.Info("OIDC authentication enabled", "issuer", issuerURL, "audience", audience)
	} else {
		mux.Handle("/api/v1/secret", secretHandler)
		helpers.JsonLogger.Warn("OIDC authentication disabled — OIDC_ISSUER_URL or OIDC_AUDIENCE not set")
	}

	// Dashboard on /
	mux.Handle("/", ravenapi.DashboardHandler(cfg, secretHandler))

	// K8s namespace status API
	mux.HandleFunc("/api/v1/k8s-status", ravenapi.K8sStatusHandler(cfg))

	// Pipeline lifecycle API
	mux.HandleFunc("/api/v1/pipeline", ravenapi.PipelineHandler(cfg, secretHandler))

	// Read-only events API — consumed by flock for aggregation
	mux.Handle("/api/v1/events", secretHandler.EventsHandler())

	// Read-only status API — bundles config + sync timing + secrets + event count.
	mux.Handle("/api/v1/status", secretHandler.StatusHandler())

	helpers.JsonLogger.Info("Starting HTTP server on :8080")
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown on SIGTERM/SIGINT
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		helpers.JsonLogger.Info("Received signal, shutting down HTTP server", "signal", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			helpers.JsonLogger.Error("HTTP server error", "error", err)
		}
	}()

	return secretHandler
}

func forceRefreshHandler(vaultClient *api.Client, cfg config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		list, err := vaultpkg.GetAllKVs(vaultClient, cfg.SecretEngine)
		if err != nil {
			helpers.JsonLogger.Warn("forceRefresh().getAllKVs failed", "error", err.Error())
		}
		if list != nil {
			for _, secret := range list.Data["keys"].([]interface{}) {
				tmpSecrets := map[string]*api.Secret{}
				input := fmt.Sprintf("%s/", cfg.SecretEngine)
				vaultpkg.IterateList(input, vaultClient, secret.(string), tmpSecrets)
				for path, val := range tmpSecrets {
					k8sSecret := k8s.CreateK8sSecret(path, cfg, val)
					ss := sealedsecret.CreateSealedSecret(cfg.PemFile, &k8sSecret)
					newBase := helpers.EnsurePathAndReturnWritePath(cfg.ClonePath, cfg.DestEnv, ss.Name)
					sealedsecret.SerializeSealedSecretToFile(ss, newBase)
					helpers.JsonLogger.Info("forceRefresh() rewrote secret", slog.String("secret", ss.Name), slog.String("newBase", newBase))
				}
			}
		}
		helpers.JsonLogger.Info("refreshHandler:forceRefresh() done")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "refreshed"})
	})
}

func startRaven(RavenCfg *config.Config) {
	if RavenCfg == nil {
		return
	}

	helpers.JsonLogger.Debug("Setting config variables", "config", newConfig)
	vaultClient, err := vaultpkg.Client(newConfig.VaultEndpoint, newConfig.Token)
	if err != nil {
		helpers.JsonLogger.Error("Failed to initialize vaultClient", "config", newConfig)
		helpers.WriteErrorToTerminationLog("Failed to initialize vaultClient")
	}

	if !vaultpkg.ValidToken(vaultClient) {
		helpers.JsonLogger.Warn("Token is invalid, need to update")
		helpers.WriteErrorToTerminationLog("[*] token is invalid, someone needs to update this![*]")
		return
	}

	secretHandler := handleRequests(newConfig, vaultClient)

	// Wire K8s watcher lifecycle events into the event system
	if k8sWatcher != nil && secretHandler != nil {
		k8sWatcher.OnEvent = func(ev k8s.K8sEvent) {
			secretHandler.RecordEvent(ev.Type, "k8s/"+ev.Namespace, ev.Secret, "ok", ev.Message)
		}
	}
	newpath := filepath.Join(RavenCfg.ClonePath, RavenCfg.SecretEngine)
	if err := os.MkdirAll(newpath, os.ModePerm); err != nil {
		helpers.JsonLogger.Error("Failed to ensure paths for first time", "NewPath", newpath)
		helpers.WriteErrorToTerminationLog("os.Mkdir failed when trying to ensure paths for first time")
	}

	gitops.GitClone(newConfig)
	State := map[string]*api.Secret{}

	for {
		if !vaultpkg.ValidToken(vaultClient) {
			helpers.JsonLogger.Warn("Token is invalid, retrying after sleep")
			helpers.Sleep(RavenCfg.SleepTime)
			continue
		}
		helpers.JsonLogger.Debug("Validated Token: grabbing list of secrets")
		list, err := vaultpkg.GetAllKVs(vaultClient, newConfig.SecretEngine)
		if err != nil {
			helpers.JsonLogger.Error("getAllKVs list error", "error", err)
			helpers.Sleep(RavenCfg.SleepTime)
			continue
		}

		if list == nil {
			helpers.JsonLogger.Warn("Secret engine returned empty list — skipping cycle (deletes are handled by event-driven path)",
				"engine", newConfig.SecretEngine)
			helpers.Sleep(RavenCfg.SleepTime)
			continue
		}

		currentSecrets = map[string]*api.Secret{}
		secretList := list.Data["keys"].([]interface{})
		synchronizeVaultSecrets(secretList, vaultClient, newConfig)
		ripeAwsSecrets := vaultpkg.FindRipeAWSSecrets(State, currentSecrets)
		awspkg.WriteMissingAWSSecrets(currentSecrets, newConfig)
		awspkg.HarvestRipeAwsSecrets(ripeAwsSecrets, newConfig)
		gitops.GitPush(newConfig)

		State = currentSecrets
		secretHandler.SetSyncStatus(time.Now(), RavenCfg.SleepTime)
		helpers.Sleep(RavenCfg.SleepTime)
	}
}

func harvestRipeSecrets(RipeSecrets []string, cfg config.Config) {
	if len(RipeSecrets) > 0 {
		repo := gitops.InitializeGitRepo(cfg)
		worktree := gitops.InitializeWorkTree(repo)
		gitops.RemoveFromWorkingtree(RipeSecrets, worktree, cfg)
		status, err := gitops.GetGitStatus(worktree)
		if err != nil {
			helpers.JsonLogger.Error("HarvestRipeSecret Worktree status failed", "error", err)
		}

		if !status.IsClean() {
			commitMessage := fmt.Sprintf("Raven removed ripe secret(s) from git")
			commit, _ := gitops.MakeCommit(worktree, commitMessage, cfg.DestEnv)
			gitops.SetPushOptions(cfg, repo, commit)
			gitops.LogHarvestDone(repo, commit)
		}
		kubernetesremove := os.Getenv("KUBERNETESREMOVE")
		if kubernetesremove == "true" {
			cfg.Clientset = k8s.NewKubernetesClient()
			secretList, err := k8s.KubernetesSecretList(cfg.Clientset, cfg.DestEnv)
			if err != nil {
				helpers.JsonLogger.Error("harvestripesecret secretlist fetch failed", "error", err)
			}
			cfg.Clientset = k8s.NewKubernetesClient()
			k8s.KubernetesRemove(RipeSecrets, secretList, cfg.Clientset, cfg.DestEnv)
			helpers.JsonLogger.Info("HarvestRipeSecrets done")
		}
	}
}

func synchronizeVaultSecrets(secretList []interface{}, client *api.Client, cfg config.Config) {
	if secretList != nil {
		// Single pass: IterateList with the engine root recurses all secrets
		input := fmt.Sprintf("%s/", cfg.SecretEngine)
		vaultpkg.IterateList(input, client, "", currentSecrets)

		if currentSecrets != nil {
			for path, theVaultSecret := range currentSecrets {
				helpers.JsonLogger.Debug("processing secret", "path", path)
				NoSync, err := vaultpkg.ExtractCustomKeyFromCustomMetadata("NO_SYNC", theVaultSecret)
				if err != nil {
					helpers.JsonLogger.Debug("synchronizeVaultSecrets.ExtractCustomKeyFromCustomMetadata", "error", err)
				}
				if NoSync != nil {
					helpers.JsonLogger.Debug("NO_SYNC set, skipping", "secret", path)
					continue
				}

				k8sSecret := k8s.CreateK8sSecret(path, cfg, theVaultSecret)
				SealedSecret := sealedsecret.CreateSealedSecret(cfg.PemFile, &k8sSecret)

				newBase := helpers.EnsurePathAndReturnWritePath(cfg.ClonePath, cfg.DestEnv, SealedSecret.Name)
				if _, err := os.Stat(newBase); os.IsNotExist(err) {
					helpers.JsonLogger.Info("Creating Sealed Secret", slog.String("action", "request.operation.create"), slog.String("secret", SealedSecret.Name))
					sealedsecret.SerializeSealedSecretToFile(SealedSecret, newBase)
					if cfg.AwsWriteback {
						err := awspkg.WriteAWSKeyValueSecret(theVaultSecret, path, cfg)
						if err != nil {
							helpers.JsonLogger.Error("synchronizeVaultSecrets.WriteAWSKeyValueSecret", "error", err)
						}
					}
					KubernetesNotificationUrl := os.Getenv("KUBERNETES_NOTIFICATION_WEBHOOK_URL")
					if KubernetesNotificationUrl != "" {
						msgTitle := "Raven created sealed secret in git"
						msgBody := fmt.Sprintf("created sealed secret in git: %s", SealedSecret.Name)
						helpers.NotifyTeamsChannel(msgTitle, msgBody, KubernetesNotificationUrl)
					}
					k8s.InitKubernetesSearch(path, cfg)
				} else if !sealedsecret.ReadSealedSecretAndCompareWithVaultStruct(path, theVaultSecret, newBase, cfg.SecretEngine) {
					helpers.JsonLogger.Debug("readSealedSecretAndCompare: already have this secret, no update needed", slog.String("secret", SealedSecret.Name))
				} else {
					helpers.JsonLogger.Info("Updating Sealed Secret", slog.String("action", "request.operation.update"), slog.String("secret", SealedSecret.Name))
					sealedsecret.SerializeSealedSecretToFile(SealedSecret, newBase)
					if cfg.AwsWriteback {
						err := awspkg.WriteAWSKeyValueSecret(theVaultSecret, path, cfg)
						if err != nil {
							helpers.JsonLogger.Error("synchronizeVaultSecrets.WriteAWSKeyValueSecret", slog.Any("error", err))
						}
					}
					KubernetesNotificationUrl := os.Getenv("KUBERNETES_NOTIFICATION_WEBHOOK_URL")
					if KubernetesNotificationUrl != "" {
						msgTitle := "Raven updated sealed secret in git"
						msgBody := fmt.Sprintf("updated sealed secret in git: %s", SealedSecret.Name)
						helpers.NotifyTeamsChannel(msgTitle, msgBody, KubernetesNotificationUrl)
					}
					k8s.InitKubernetesSearch(SealedSecret.Name, cfg)
				}
			}
		}
	}
}
