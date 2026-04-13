package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/volck/raven/internal/auditlog"
	"github.com/volck/raven/internal/auth"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	configPath := os.Getenv("LOGPARSER_CONFIG")
	if configPath == "" {
		configPath = "/etc/raven/logparser.json"
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		logger.Error("Failed to load config", "error", err, "path", configPath)
		os.Exit(1)
	}

	if err := auditlog.ValidateConfig(cfg); err != nil {
		logger.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}

	// Load saved offset from state file
	var offset int64
	if cfg.StateFile != "" {
		offset = loadOffset(cfg.StateFile, logger)
	}

	// Create file tailer
	tailer, err := auditlog.NewFileTailer(cfg.AuditLogPath, offset)
	if err != nil {
		logger.Error("Failed to create tailer", "error", err, "path", cfg.AuditLogPath)
		os.Exit(1)
	}

	// Create HTTP client with OIDC auth if configured
	ctx := context.Background()
	var dispatcher *auditlog.Dispatcher

	if cfg.OIDC.TokenURL != "" {
		creds := auth.NewClientCredentials(
			cfg.OIDC.TokenURL,
			cfg.OIDC.ClientID,
			cfg.OIDC.ClientSecret,
			cfg.OIDC.Scopes,
		)
		httpClient := creds.HTTPClient(ctx)
		dispatcher = auditlog.NewDispatcher(cfg.Routing, httpClient)
		logger.Info("OIDC client credentials configured", "token_url", cfg.OIDC.TokenURL)
	} else {
		dispatcher = auditlog.NewDispatcher(cfg.Routing, nil)
		logger.Warn("No OIDC configuration — dispatching without authentication")
	}

	// Parse debounce window
	debounceWindow := 2 * time.Second
	if cfg.DebounceWindow != "" {
		if d, err := time.ParseDuration(cfg.DebounceWindow); err == nil {
			debounceWindow = d
		} else {
			logger.Warn("Invalid debounce_window, using default 2s", "error", err)
		}
	}

	// Create debouncer that dispatches events after the window
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

	// Signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	lines := make(chan string, 100)
	go tailer.Tail(lines)

	logger.Info("Log parser started",
		"audit_log", cfg.AuditLogPath,
		"engines", strings.Join(cfg.SecretEngines, ","),
		"debounce", debounceWindow.String(),
		"offset", offset,
	)

	for {
		select {
		case line := <-lines:
			processLine(logger, cfg, debouncer, line)
			if cfg.StateFile != "" {
				saveOffset(cfg.StateFile, tailer.Offset(), logger)
			}
		case sig := <-sigCh:
			logger.Info("Received signal, shutting down", "signal", sig)
			tailer.Stop()
			debouncer.Stop()
			if cfg.StateFile != "" {
				saveOffset(cfg.StateFile, tailer.Offset(), logger)
			}
			return
		}
	}
}

func processLine(logger *slog.Logger, cfg auditlog.LogParserConfig, debouncer *auditlog.Debouncer, line string) {
	entry, err := auditlog.ParseEntry([]byte(line))
	if err != nil {
		logger.Debug("Skipping unparseable line", "error", err)
		return
	}

	op, valid := auditlog.ClassifyOperation(*entry)
	if !valid {
		return
	}

	if !auditlog.MatchesEngine(entry.Request.Path, cfg.SecretEngines) {
		return
	}

	var matchedEngine string
	for _, engine := range cfg.SecretEngines {
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
