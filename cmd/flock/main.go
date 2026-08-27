package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/volck/raven/internal/flock"
	lpclient "github.com/volck/raven/internal/flock/logparser"
	rvclient "github.com/volck/raven/internal/flock/raven"
)

func main() {
	if err := run(context.Background(), os.Args, os.Getenv, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	args []string,
	getenv func(string) string,
	stdout, stderr io.Writer,
) error {
	_ = args
	_ = stdout

	level := new(slog.LevelVar)
	level.Set(slog.LevelInfo)
	if lvl := getenv("LOG_LEVEL"); lvl != "" {
		var l slog.Level
		if err := l.UnmarshalText([]byte(lvl)); err == nil {
			level.Set(l)
		}
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	}))

	logparserURL := getenv("LOGPARSER_URL")
	if logparserURL == "" {
		return fmt.Errorf("LOGPARSER_URL is required")
	}
	if err := flock.ValidateProxyURL(logparserURL); err != nil {
		return fmt.Errorf("LOGPARSER_URL: %w", err)
	}

	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	addr := getenv("HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:0"
	}

	pollInterval := parseDuration(getenv("POLL_INTERVAL"), 30*time.Second)
	probeInterval := parseDuration(getenv("PROBE_INTERVAL"), 30*time.Second)
	eventInterval := parseDuration(getenv("EVENT_INTERVAL"), 30*time.Second)
	statusInterval := parseDuration(getenv("STATUS_INTERVAL"), 30*time.Second)
	refreshTimeout := parseDuration(getenv("REFRESH_TIMEOUT"), 15*time.Second)
	probeTimeout := parseDuration(getenv("PROBE_TIMEOUT"), 5*time.Second)
	eventTimeout := parseDuration(getenv("EVENT_TIMEOUT"), 10*time.Second)
	statusTimeout := parseDuration(getenv("STATUS_TIMEOUT"), 10*time.Second)

	tlsCfg, err := loadTLSConfig(getenv("FLOCK_CA_FILE"))
	if err != nil {
		return fmt.Errorf("load FLOCK_CA_FILE: %w", err)
	}
	rvOpts := func(extra ...rvclient.Option) []rvclient.Option {
		if tlsCfg != nil {
			extra = append(extra, rvclient.WithTLSConfig(tlsCfg))
		}
		return extra
	}

	lpc, err := lpclient.New(logparserURL,
		lpclient.WithLogger(logger.With("component", "logparser-client")),
		lpclient.WithRequestTimeout(refreshTimeout),
	)
	if err != nil {
		return fmt.Errorf("logparser client: %w", err)
	}

	rvc, err := rvclient.New(rvOpts(
		rvclient.WithLogger(logger.With("component", "raven-client")),
		rvclient.WithRequestTimeout(probeTimeout),
	)...)
	if err != nil {
		return fmt.Errorf("raven client: %w", err)
	}

	rvcEvents, err := rvclient.New(rvOpts(
		rvclient.WithLogger(logger.With("component", "raven-events-client")),
		rvclient.WithRequestTimeout(eventTimeout),
	)...)
	if err != nil {
		return fmt.Errorf("raven events client: %w", err)
	}

	rvcStatus, err := rvclient.New(rvOpts(
		rvclient.WithLogger(logger.With("component", "raven-status-client")),
		rvclient.WithRequestTimeout(statusTimeout),
	)...)
	if err != nil {
		return fmt.Errorf("raven status client: %w", err)
	}

	src := newLogparserSource(lpc)
	provider := flock.NewProvider(src,
		flock.WithLogger(logger.With("component", "provider")),
		flock.WithPollInterval(pollInterval),
		flock.WithRefreshTimeout(refreshTimeout),
	)
	prober := flock.NewProber(rvc,
		flock.WithProberInterval(probeInterval),
		flock.WithProberTimeout(probeTimeout),
	)
	aggregator := flock.NewAggregator(rvcEvents,
		flock.WithAggregatorInterval(eventInterval),
		flock.WithAggregatorTimeout(eventTimeout),
	)
	statusAgg := flock.NewStatusAggregator(rvcStatus,
		flock.WithStatusAggregatorInterval(statusInterval),
		flock.WithStatusAggregatorTimeout(statusTimeout),
	)

	wsHub := flock.NewWSHub(logger.With("component", "ws-hub"))
	rvcWS, err := rvclient.New(rvOpts(
		rvclient.WithLogger(logger.With("component", "raven-ws-client")),
		rvclient.WithRequestTimeout(10*time.Second),
	)...)
	if err != nil {
		return fmt.Errorf("raven ws client: %w", err)
	}
	wsBridge := flock.NewWSBridge(logger.With("component", "ws-bridge"), rvcWS, wsHub)

	pipelineInterval := parseDuration(getenv("PIPELINE_INTERVAL"), 30*time.Second)
	pipelineTimeout := parseDuration(getenv("PIPELINE_TIMEOUT"), 30*time.Second)
	rvcPipeline, err := rvclient.New(rvOpts(
		rvclient.WithLogger(logger.With("component", "raven-pipeline-client")),
		rvclient.WithRequestTimeout(pipelineTimeout),
	)...)
	if err != nil {
		return fmt.Errorf("raven pipeline client: %w", err)
	}
	pipelineAgg := flock.NewPipelineAggregator(rvcPipeline,
		flock.WithPipelineAggregatorInterval(pipelineInterval),
		flock.WithPipelineAggregatorTimeout(pipelineTimeout),
	)

	ready := new(atomic.Bool)
	srv := NewServer(logger, ready, provider, prober, aggregator, statusAgg, wsHub, pipelineAgg)

	rootHandler := http.Handler(srv)
	if getenv("FLOCK_TEST_SLOW_HANDLER") == "1" {
		slowMux := http.NewServeMux()
		slowMux.HandleFunc("GET /slow", func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(500 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("slow ok"))
		})
		slowMux.Handle("/", srv)
		rootHandler = slowMux
	}

	httpSrv := &http.Server{
		Handler:           rootHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	logger.Info("listening", "addr", listener.Addr().String())

	g, gctx := errgroup.WithContext(ctx)

	// Initial sync refresh before serving so /readyz flips quickly. Failures
	// here are non-fatal — the periodic loop will retry.
	if err := provider.Refresh(gctx); err == nil {
		prober.RunOnce(gctx, provider.Snapshot())
		aggregator.RunOnce(gctx, provider.Snapshot())
		statusAgg.RunOnce(gctx, provider.Snapshot())
		pipelineAgg.RunOnce(gctx, provider.Snapshot())
		ready.Store(true)
	}

	g.Go(func() error { return provider.Run(gctx) })
	g.Go(func() error {
		return prober.Run(gctx, provider.Snapshot)
	})
	g.Go(func() error {
		return aggregator.Run(gctx, provider.Snapshot)
	})
	g.Go(func() error {
		return statusAgg.Run(gctx, provider.Snapshot)
	})
	g.Go(func() error {
		return wsBridge.Run(gctx, provider.Snapshot, 30*time.Second)
	})
	g.Go(func() error {
		return pipelineAgg.Run(gctx, provider.Snapshot)
	})

	// Watch provider readiness and flip the atomic.Bool used by /readyz.
	g.Go(func() error {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			if provider.Ready() {
				ready.Store(true)
				return nil
			}
			select {
			case <-gctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	})

	// SIGHUP triggers an out-of-band refresh + probe pass.
	g.Go(func() error {
		hupCh := make(chan os.Signal, 1)
		signal.Notify(hupCh, syscall.SIGHUP)
		defer signal.Stop(hupCh)
		for {
			select {
			case <-gctx.Done():
				return nil
			case <-hupCh:
				logger.Info("sighup.trigger")
				provider.Trigger()
				prober.Trigger()
				aggregator.Trigger()
				statusAgg.Trigger()
				wsBridge.Reconcile(gctx, provider.Snapshot())
				pipelineAgg.Trigger()
			}
		}
	})

	g.Go(func() error {
		if err := httpSrv.Serve(listener); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("http serve: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		<-gctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		return httpSrv.Shutdown(shutdownCtx)
	})

	if err := g.Wait(); err != nil {
		return err
	}
	logger.Info("shutting down")
	return nil
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

// loadTLSConfig returns a *tls.Config whose RootCAs is the system pool
// extended with PEM certificates read from path. When path is empty, it
// returns (nil, nil) and the caller should fall back to Go's defaults.
func loadTLSConfig(path string) (*tls.Config, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates parsed from %s", path)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}
