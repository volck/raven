package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/volck/raven/cmd/flock/ui"
	"github.com/volck/raven/internal/flock"
	rvclient "github.com/volck/raven/internal/flock/raven"
)

// addUIRoutes mounts the reference UI at / plus /ui/* and /static/*.
// It is a thin presentation layer over the same Snapshotter/Status/Pipeline
// interfaces the JSON API uses, so the page shape mirrors the API shape.
func addUIRoutes(
	mux *http.ServeMux,
	logger *slog.Logger,
	renderer *ui.Renderer,
	snap Snapshotter,
	health HealthSnapshotter,
	status StatusSnapshotter,
	pipeline PipelineSnapshotter,
	events EventSnapshotter,
) {
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(ui.StaticFS())))
	mux.Handle("GET /{$}", handleUIDashboard(logger, renderer, snap, health, status))
	mux.Handle("GET /ui/engines/{name}", handleUIEngine(logger, renderer, snap, health, status, events))
	mux.Handle("GET /ui/engines/{name}/secrets/{secret}", handleUISecret(logger, renderer, snap, pipeline))
}

type engineCard struct {
	Name        string
	Targets     []string
	SecretCount int
	Worst       string // ok | warn | fail
	LastError   string
}

type dashboardVM struct {
	Title       string
	Engines     []engineCard
	TargetCount int
}

func handleUIDashboard(logger *slog.Logger, r *ui.Renderer, snap Snapshotter, health HealthSnapshotter, status StatusSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !snap.Ready() {
			writeNotReady(w, r)
			return
		}
		s := snap.Snapshot()
		engines := make([]engineCard, 0, len(s.Routing))
		seen := map[string]struct{}{}
		for name, targets := range s.Routing {
			worst := "ok"
			var lastErr string
			for _, t := range targets {
				seen[t] = struct{}{}
				if h, ok := health.HealthFor(t); ok && !h.Healthy {
					worst = "fail"
					if lastErr == "" {
						lastErr = h.Error
					}
				}
			}
			invCount := len(status.InventoryForEngine(name, s))
			engines = append(engines, engineCard{
				Name:        name,
				Targets:     targets,
				SecretCount: invCount,
				Worst:       worst,
				LastError:   lastErr,
			})
		}
		sort.Slice(engines, func(i, j int) bool { return engines[i].Name < engines[j].Name })

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := r.Render(w, "dashboard.html", dashboardVM{
			Title:       "fleet",
			Engines:     engines,
			TargetCount: len(seen),
		}); err != nil {
			logger.Warn("ui.dashboard.render_failed", "err", err.Error())
		}
	})
}

type engineTargetRow struct {
	URL         string
	HealthClass string
	HealthLabel string
	LastCommit  string
	LastError   string
	ObservedAt  string
}

type engineSecretRow struct {
	Name        string
	TargetCount int
	K8sLabel    string
}

type engineEventRow struct {
	Time       string
	Target     string
	Operation  string
	Engine     string
	Path       string
	Status     string
	StatusClass string
	Message    string
}

type engineVM struct {
	Title   string
	Engine  string
	Targets []engineTargetRow
	Secrets []engineSecretRow
	Events  []engineEventRow
}

func handleUIEngine(logger *slog.Logger, r *ui.Renderer, snap Snapshotter, health HealthSnapshotter, status StatusSnapshotter, events EventSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !snap.Ready() {
			writeNotReady(w, r)
			return
		}
		name := req.PathValue("name")
		s := snap.Snapshot()
		targets, ok := s.Routing[name]
		if !ok {
			http.NotFound(w, req)
			return
		}

		rows := make([]engineTargetRow, 0, len(targets))
		statuses := status.ForEngine(name, s)
		statusByTarget := map[string]flock.TargetStatus{}
		for _, st := range statuses {
			statusByTarget[st.Target] = st
		}
		for _, t := range targets {
			row := engineTargetRow{URL: t, HealthClass: "warn", HealthLabel: "unknown"}
			if h, ok := health.HealthFor(t); ok {
				if h.Healthy {
					row.HealthClass = "ok"
					row.HealthLabel = "ok"
				} else {
					row.HealthClass = "fail"
					row.HealthLabel = "down"
					row.LastError = h.Error
				}
			}
			if st, ok := statusByTarget[t]; ok {
				if !st.Status.Sync.LastSync.IsZero() {
					row.LastCommit = st.Status.Sync.LastSync.UTC().Format("2006-01-02 15:04:05")
				}
				if st.Status.Sync.Overdue {
					row.HealthClass = "warn"
					if row.HealthLabel == "ok" {
						row.HealthLabel = "overdue"
					}
				}
				row.ObservedAt = formatTime(st.ObservedAt)
			}
			rows = append(rows, row)
		}

		inv := status.InventoryForEngine(name, s)
		// collapse to one row per secret name; count targets and pick a
		// representative k8s label
		bySecret := map[string]*engineSecretRow{}
		for _, e := range inv {
			name := strings.TrimSuffix(e.Name, ".yaml")
			sr, ok := bySecret[name]
			if !ok {
				sr = &engineSecretRow{Name: name}
				bySecret[name] = sr
			}
			sr.TargetCount++
			if sr.K8sLabel == "" {
				sr.K8sLabel = k8sLabel(e.K8s)
			}
		}
		secrets := make([]engineSecretRow, 0, len(bySecret))
		for _, sr := range bySecret {
			secrets = append(secrets, *sr)
		}
		sort.Slice(secrets, func(i, j int) bool { return secrets[i].Name < secrets[j].Name })

		evs := events.ForEngine(name, s)
		eventRows := make([]engineEventRow, 0, len(evs))
		for _, te := range evs {
			eventRows = append(eventRows, engineEventRow{
				Time:        formatTime(te.Event.Time),
				Target:      te.Target,
				Operation:   te.Event.Operation,
				Engine:      te.Event.Engine,
				Path:        te.Event.Path,
				Status:      te.Event.Status,
				StatusClass: stageClass(te.Event.Status),
				Message:     te.Event.Message,
			})
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := r.Render(w, "engine.html", engineVM{
			Title:   "engine " + name,
			Engine:  name,
			Targets: rows,
			Secrets: secrets,
			Events:  eventRows,
		}); err != nil {
			logger.Warn("ui.engine.render_failed", "err", err.Error(), "engine", name)
		}
	})
}

type stageVM struct {
	Name        string
	Status      string
	StatusClass string
	Detail      string
}

type secretRowVM struct {
	Target     string
	ObservedAt string
	Stages     []stageVM
	RawJSON    string
}

type secretVM struct {
	Title  string
	Engine string
	Secret string
	Rows   []secretRowVM
}

func handleUISecret(logger *slog.Logger, r *ui.Renderer, snap Snapshotter, pipeline PipelineSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !snap.Ready() {
			writeNotReady(w, r)
			return
		}
		name := req.PathValue("name")
		secret := req.PathValue("secret")
		// Tolerate URLs that include the .yaml filename suffix; raven's
		// pipeline keys secrets by the bare name.
		secret = strings.TrimSuffix(secret, ".yaml")
		s := snap.Snapshot()
		if _, ok := s.Routing[name]; !ok {
			http.NotFound(w, req)
			return
		}
		rows := pipeline.PipelineForSecret(name, secret, s)
		vm := secretVM{
			Title:  secret,
			Engine: name,
			Secret: secret,
			Rows:   make([]secretRowVM, 0, len(rows)),
		}
		for _, row := range rows {
			rvm := secretRowVM{
				Target:     row.Target,
				ObservedAt: formatTime(row.ObservedAt),
				Stages:     make([]stageVM, 0, len(row.Entry.Stages)),
			}
			for _, st := range row.Entry.Stages {
				rvm.Stages = append(rvm.Stages, stageVM{
					Name:        st.Name,
					Status:      st.Status,
					StatusClass: stageClass(st.Status),
					Detail:      st.Detail,
				})
			}
			if raw, err := json.MarshalIndent(row.Entry, "", "  "); err == nil {
				rvm.RawJSON = string(raw)
			}
			vm.Rows = append(vm.Rows, rvm)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := r.Render(w, "secret.html", vm); err != nil {
			logger.Warn("ui.secret.render_failed", "err", err.Error(), "engine", name, "secret", secret)
		}
	})
}

func writeNotReady(w http.ResponseWriter, _ *ui.Renderer) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`<!doctype html><meta charset=utf-8><title>flock</title><body style="font:14px sans-serif;padding:2rem;background:#0f1115;color:#e6e6e6"><h1>flock is starting…</h1><p>The initial fleet snapshot has not loaded yet. Retry in a few seconds.</p>`))
}

func stageClass(s string) string {
	switch s {
	case "done", "ok":
		return "ok"
	case "warn":
		return "warn"
	case "fail", "error":
		return "fail"
	case "pending":
		return "pending"
	default:
		return "pending"
	}
}

func k8sLabel(k *rvclient.SecretK8sState) string {
	if k == nil {
		return "missing"
	}
	if len(k.Deployments) > 0 || len(k.StatefulSets) > 0 {
		return "present + workloads"
	}
	return "present"
}

func shortCommit(c string) string {
	if len(c) > 8 {
		return c[:8]
	}
	return c
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
