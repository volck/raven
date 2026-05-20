package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/volck/raven/internal/auditlog"
	"github.com/volck/raven/internal/auth"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx := context.Background()
	if err := run(ctx, os.Args, os.Getenv, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "logparser:", err)
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	args []string,
	getenv func(string) string,
	stdout io.Writer,
	stderr io.Writer,
) error {
	_ = args
	_ = stdout
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
	}))

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	configPath := getenv("LOGPARSER_CONFIG")
	if configPath == "" {
		configPath = "/etc/raven/logparser.json"
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config %s: %w", configPath, err)
	}

	if envSecret := getenv("OIDC_CLIENT_SECRET"); envSecret != "" {
		cfg.OIDC.ClientSecret = envSecret
	}

	if err := auditlog.ValidateConfig(cfg); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	// Build the routing snapshot source. If cfg.Git is set, use a
	// GitSource-backed Provider; otherwise fall back to the static file
	// config.
	var (
		snap     Snapshotter
		ready    ReadyChecker
		provider *auditlog.Provider
	)
	if cfg.Git != nil {
		gitCfg := *cfg.Git
		auth, err := auditlog.LoadGitAuth(gitCfg)
		if err != nil {
			return fmt.Errorf("load git auth: %w", err)
		}
		gs := auditlog.NewGitSource(gitCfg)
		if auth != nil {
			gs.SetAuth(auth)
		}
		gs.SetLogger(logger)

		pollInterval, _ := time.ParseDuration(gitCfg.PollInterval)
		provider = auditlog.NewProvider(gs,
			auditlog.WithLogger(logger),
			auditlog.WithPollInterval(pollInterval),
		)
		if err := provider.Refresh(ctx); err != nil {
			return fmt.Errorf("initial routing refresh: %w", err)
		}
		snap = provider
		ready = provider
	} else {
		snap = staticSnapshot(cfg)
		ready = alwaysReady{}
	}

	// HTTP server (start before tailer so /healthz is reachable early).
	httpAddr := getenv("HTTP_ADDR")
	if httpAddr == "" {
		httpAddr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", httpAddr, err)
	}
	httpSrv := &http.Server{
		Handler:           NewServer(logger, snap, ready),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	logger.Info("listening", "addr", ln.Addr().String())

	var offset int64
	if cfg.StateFile != "" {
		offset = loadOffset(cfg.StateFile, logger)
	}

	tailer, err := auditlog.NewFileTailer(cfg.AuditLogPath, offset)
	if err != nil {
		return fmt.Errorf("create tailer %s: %w", cfg.AuditLogPath, err)
	}

	var dispatcher *auditlog.Dispatcher
	if cfg.OIDC.TokenURL != "" {
		creds := auth.NewClientCredentials(
			cfg.OIDC.TokenURL,
			cfg.OIDC.ClientID,
			cfg.OIDC.ClientSecret,
			cfg.OIDC.Scopes,
		)
		httpClient := creds.HTTPClient(ctx)
		if provider != nil {
			dispatcher = auditlog.NewDispatcherFromSnapshot(provider, httpClient)
		} else {
			dispatcher = auditlog.NewDispatcher(cfg.Routing, httpClient)
		}
		logger.Info("OIDC client credentials configured", "token_url", cfg.OIDC.TokenURL)
	} else {
		if provider != nil {
			dispatcher = auditlog.NewDispatcherFromSnapshot(provider, nil)
		} else {
			dispatcher = auditlog.NewDispatcher(cfg.Routing, nil)
		}
		logger.Warn("No OIDC configuration — dispatching without authentication")
	}

	debounceWindow := 2 * time.Second
	if cfg.DebounceWindow != "" {
		if d, err := time.ParseDuration(cfg.DebounceWindow); err == nil {
			debounceWindow = d
		} else {
			logger.Warn("Invalid debounce_window, using default 2s", "error", err)
		}
	}

	debouncer := auditlog.NewDebouncer(debounceWindow, func(event auditlog.DispatchEvent) {
		logger.Info("Dispatching debounced event",
			"operation", event.Operation,
			"engine", event.SecretEngine,
			"path", event.SecretPath,
		)
		if err := dispatcher.Dispatch(event); err != nil {
			logger.Error("Failed to dispatch event", "error", err, "event", fmt.Sprintf("%+v", event))
		}
	})

	lines := make(chan string, 100)
	go tailer.Tail(lines)

	startupEngines := cfg.SecretEngines
	if provider != nil {
		startupEngines = provider.Snapshot().SecretEngines
	}
	logger.Info("Log parser started",
		"audit_log", cfg.AuditLogPath,
		"engines", strings.Join(startupEngines, ","),
		"debounce", debounceWindow.String(),
		"offset", offset,
	)

	g, gctx := errgroup.WithContext(ctx)

	// SIGHUP triggers an immediate routing refresh (git-backed only).
	if provider != nil {
		hupCh := make(chan os.Signal, 1)
		signal.Notify(hupCh, syscall.SIGHUP)
		g.Go(func() error {
			defer signal.Stop(hupCh)
			for {
				select {
				case <-hupCh:
					if err := provider.Refresh(gctx); err != nil {
						logger.Warn("hup_refresh_failed", "err", err.Error())
					}
				case <-gctx.Done():
					return nil
				}
			}
		})
	}

	// Routing provider poll loop (git-backed routing only).
	if provider != nil {
		g.Go(func() error {
			provider.Run(gctx)
			return nil
		})
	}

	// HTTP server.
	g.Go(func() error {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	})

	// Shutdown watcher: graceful HTTP shutdown when context is cancelled.
	g.Go(func() error {
		<-gctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	})

	// Audit log processing loop.
	g.Go(func() error {
		for {
			select {
			case line := <-lines:
				processLine(logger, cfg, snap, debouncer, line)
				if cfg.StateFile != "" {
					saveOffset(cfg.StateFile, tailer.Offset(), logger)
				}
			case <-gctx.Done():
				tailer.Stop()
				debouncer.Stop()
				if cfg.StateFile != "" {
					saveOffset(cfg.StateFile, tailer.Offset(), logger)
				}
				return nil
			}
		}
	})

	err = g.Wait()
	logger.Info("shutting down", "reason", "context_canceled")
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func processLine(logger *slog.Logger, cfg auditlog.LogParserConfig, snap Snapshotter, debouncer *auditlog.Debouncer, line string) {
	entry, err := auditlog.ParseEntry([]byte(line))
	if err != nil {
		logger.Debug("Skipping unparseable line", "error", err)
		return
	}

	op, valid := auditlog.ClassifyOperation(*entry)
	if !valid {
		return
	}

	engines := cfg.SecretEngines
	if cfg.Git != nil {
		engines = snap.Snapshot().SecretEngines
	}
	if !auditlog.MatchesEngine(entry.Request.Path, engines) {
		return
	}

	var matchedEngine string
	for _, engine := range engines {
		if strings.HasPrefix(entry.Request.Path, engine+"/") {
			matchedEngine = engine
			break
		}
	}

	secretPath := auditlog.ExtractSecretPath(entry.Request.Path, matchedEngine)

	event := auditlog.DispatchEvent{
		Operation:    op,
		SecretEngine: matchedEngine,
		SecretPath:   secretPath,
	}

	debouncer.Submit(event)
}

func loadConfig(path string) (auditlog.LogParserConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return auditlog.LogParserConfig{}, fmt.Errorf("read config: %w", err)
	}
	var cfg auditlog.LogParserConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return auditlog.LogParserConfig{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func loadOffset(stateFile string, logger *slog.Logger) int64 {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return 0
	}
	var offset int64
	if _, err := fmt.Sscanf(string(data), "%d", &offset); err != nil {
		logger.Warn("Failed to parse offset from state file", "error", err)
		return 0
	}
	return offset
}

func saveOffset(stateFile string, offset int64, logger *slog.Logger) {
	if err := os.WriteFile(stateFile, []byte(fmt.Sprintf("%d", offset)), 0600); err != nil {
		logger.Error("Failed to save offset", "error", err, "file", stateFile)
	}
}
