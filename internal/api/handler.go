package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	awspkg "github.com/volck/raven/internal/aws"
	"github.com/volck/raven/internal/config"
	"github.com/volck/raven/internal/gitops"
	"github.com/volck/raven/internal/helpers"
	"github.com/volck/raven/internal/k8s"
	"github.com/volck/raven/internal/sealedsecret"
	"github.com/volck/raven/internal/store"
	vaultpkg "github.com/volck/raven/internal/vault"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var jsonLogger = helpers.JsonLogger

// SecretEvent represents an incoming secret event from the audit log parser.
type SecretEvent struct {
	Operation    string `json:"operation"`
	SecretEngine string `json:"secret_engine"`
	SecretPath   string `json:"secret_path"`
}

// SecretEventResponse is the JSON response returned after processing an event.
type SecretEventResponse struct {
	Status     string `json:"status"`
	Operation  string `json:"operation"`
	SecretPath string `json:"secret_path"`
	Message    string `json:"message,omitempty"`
}

// Hooks defines injectable side-effects for the handler. This allows testing
// without real git/SSH/K8s/AWS infrastructure.
type Hooks struct {
	// GitPush commits and pushes changes via git. If nil, gitops.GitPush is used.
	GitPush func(cfg config.Config)
	// NotifyTeams sends a webhook notification. If nil, helpers.NotifyTeamsChannel is used.
	NotifyTeams func(title, body, webhookURL string)
	// WriteAWS writes a secret to AWS Secrets Manager. If nil, awspkg.WriteAWSKeyValueSecret is used.
	WriteAWS func(secret *api.Secret, path string, cfg config.Config) error
	// InitK8sSearch triggers Kubernetes secret lookup. If nil, k8s.InitKubernetesSearch is used.
	InitK8sSearch func(secret string, cfg config.Config)
	// ArgoSync triggers an ArgoCD refresh+sync of the configured Application after
	// a create/update event. If nil, the default implementation in argosync.go is used.
	ArgoSync func(ctx context.Context, secretName string) error
	// CreateK8sSecret creates a Kubernetes secret object. If nil, k8s.CreateK8sSecret is used.
	CreateK8sSecret func(name string, cfg config.Config, dataFields *api.Secret) interface{}
	// CreateSealedSecret creates a sealed secret. If nil, uses sealedsecret package functions.
	CreateSealedSecret func(pemFile string, secret interface{}) (name string, err error)
	// SerializeSealedSecret writes sealed secret to disk. If nil, uses sealedsecret package functions.
	SerializeSealedSecret func(ss interface{}, fullPath string)
}

// SecretEventHandler processes incoming secret events from the audit log parser.
type SecretEventHandler struct {
	client       *api.Client
	cfg          config.Config
	hooks        Hooks
	mu           sync.Mutex
	eventsMu     sync.RWMutex
	recentEvents []SyncEvent
	syncMu       sync.RWMutex
	syncStatus   SyncStatus
	hub          *Hub
	eventStore   *store.EventStore
}

const maxRecentEvents = 100

// SyncEvent records a processed secret event for the dashboard.
type SyncEvent struct {
	Time      time.Time `json:"time"`
	Operation string    `json:"operation"`
	Engine    string    `json:"engine"`
	Path      string    `json:"path"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
}

// SyncStatus tracks the last and next full Vault walk.
type SyncStatus struct {
	LastSync     time.Time
	NextSync     time.Time
	SleepSeconds int
}

func (h *SecretEventHandler) recordEvent(op, engine, path, status, msg string) {
	h.eventsMu.Lock()
	defer h.eventsMu.Unlock()
	ev := SyncEvent{
		Time:      time.Now(),
		Operation: op,
		Engine:    engine,
		Path:      path,
		Status:    status,
		Message:   msg,
	}
	h.recentEvents = append(h.recentEvents, ev)
	if len(h.recentEvents) > maxRecentEvents {
		h.recentEvents = h.recentEvents[len(h.recentEvents)-maxRecentEvents:]
	}
	if h.eventStore != nil {
		if _, err := h.eventStore.Insert(store.Event{
			Time:      ev.Time,
			Operation: ev.Operation,
			Engine:    ev.Engine,
			Path:      ev.Path,
			Status:    ev.Status,
			Message:   ev.Message,
		}); err != nil {
			jsonLogger.Error("failed to persist event to SQLite", "error", err)
		}
	}
	if h.hub != nil {
		count := len(h.recentEvents)
		if h.eventStore != nil {
			if c, err := h.eventStore.Count(); err == nil {
				count = c
			}
		}
		h.hub.Broadcast(WSMessage{Type: "event", Data: map[string]interface{}{
			"time":      ev.Time,
			"operation": ev.Operation,
			"engine":    ev.Engine,
			"path":      ev.Path,
			"status":    ev.Status,
			"message":   ev.Message,
			"total":     count,
		}})
	}
}

// RecentEvents returns a copy of recent events, newest first.
// If an EventStore is attached, events are loaded from SQLite;
// otherwise, from the in-memory ring buffer.
func (h *SecretEventHandler) RecentEvents() []SyncEvent {
	if h.eventStore != nil {
		dbEvents, err := h.eventStore.Recent(maxRecentEvents)
		if err != nil {
			jsonLogger.Error("failed to load events from SQLite", "error", err)
		} else {
			out := make([]SyncEvent, 0, len(dbEvents))
			for _, ev := range dbEvents {
				out = append(out, SyncEvent{
					Time:      ev.Time,
					Operation: ev.Operation,
					Engine:    ev.Engine,
					Path:      ev.Path,
					Status:    ev.Status,
					Message:   ev.Message,
				})
			}
			return out
		}
	}
	h.eventsMu.RLock()
	defer h.eventsMu.RUnlock()
	out := make([]SyncEvent, len(h.recentEvents))
	for i, ev := range h.recentEvents {
		out[len(h.recentEvents)-1-i] = ev
	}
	return out
}

// SetSyncStatus updates the full-walk sync status.
func (h *SecretEventHandler) SetSyncStatus(lastSync time.Time, sleepSeconds int) {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	h.syncStatus = SyncStatus{
		LastSync:     lastSync,
		NextSync:     lastSync.Add(time.Duration(sleepSeconds) * time.Second),
		SleepSeconds: sleepSeconds,
	}
	if h.hub != nil {
		nextSync := lastSync.Add(time.Duration(sleepSeconds) * time.Second)
		h.hub.Broadcast(WSMessage{Type: "sync_status", Data: map[string]interface{}{
			"last_sync":     lastSync.Format("2006-01-02 15:04:05 MST"),
			"next_sync":     nextSync.Format("15:04:05 MST"),
			"next_sync_iso": nextSync.UTC().Format(time.RFC3339),
			"interval":      fmt.Sprintf("%dm", sleepSeconds/60),
			"overdue":       false,
		}})
	}
}

// GetSyncStatus returns the current full-walk sync status.
func (h *SecretEventHandler) GetSyncStatus() SyncStatus {
	h.syncMu.RLock()
	defer h.syncMu.RUnlock()
	return h.syncStatus
}

// NewSecretEventHandler creates a new handler for processing secret events.
func NewSecretEventHandler(client *api.Client, cfg config.Config) *SecretEventHandler {
	return &SecretEventHandler{
		client: client,
		cfg:    cfg,
	}
}

// RecordEvent records an event and broadcasts it via WebSocket.
func (h *SecretEventHandler) RecordEvent(op, engine, path, status, msg string) {
	h.recordEvent(op, engine, path, status, msg)
}

// SetHub attaches a WebSocket hub for live broadcasting.
func (h *SecretEventHandler) SetHub(hub *Hub) {
	h.hub = hub
}

// SetEventStore attaches a SQLite event store for persistence.
func (h *SecretEventHandler) SetEventStore(es *store.EventStore) {
	h.eventStore = es
}

// NewSecretEventHandlerWithHooks creates a handler with custom hooks for testing.
func NewSecretEventHandlerWithHooks(client *api.Client, cfg config.Config, hooks Hooks) *SecretEventHandler {
	return &SecretEventHandler{
		client: client,
		cfg:    cfg,
		hooks:  hooks,
	}
}

// Hub returns the attached WebSocket hub (may be nil).
func (h *SecretEventHandler) Hub() *Hub { return h.hub }

func (h *SecretEventHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	var event SecretEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	switch event.Operation {
	case "create", "update":
		h.handleCreateOrUpdate(r.Context(), w, event)
	case "delete":
		h.handleDelete(w, event)
	default:
		http.Error(w, fmt.Sprintf("unsupported operation: %s", event.Operation), http.StatusBadRequest)
	}
}

func (h *SecretEventHandler) handleCreateOrUpdate(ctx context.Context, w http.ResponseWriter, event SecretEvent) {
	theVaultSecret := vaultpkg.GetSingleKV(h.client, event.SecretEngine, event.SecretPath)
	if theVaultSecret == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("secret not found: %s/%s", event.SecretEngine, event.SecretPath)})
		return
	}

	jsonLogger.Info("Processing secret event",
		"operation", event.Operation,
		"engine", event.SecretEngine,
		"path", event.SecretPath,
	)

	h.mu.Lock()
	defer h.mu.Unlock()

	// Check NO_SYNC custom metadata
	noSync, err := vaultpkg.ExtractCustomKeyFromCustomMetadata("NO_SYNC", theVaultSecret)
	if err != nil {
		jsonLogger.Debug("handleCreateOrUpdate.ExtractCustomKeyFromCustomMetadata", "error", err)
	}
	if noSync != nil {
		jsonLogger.Info("NO_SYNC set, skipping", "secret", event.SecretPath)
		h.recordEvent(event.Operation, event.SecretEngine, event.SecretPath, "skipped", "NO_SYNC set")
		resp := SecretEventResponse{
			Status:     "skipped",
			Operation:  event.Operation,
			SecretPath: event.SecretPath,
			Message:    "secret has NO_SYNC set, skipping",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Create K8s secret object
	k8sSecret := k8s.CreateK8sSecret(event.SecretPath, h.cfg, theVaultSecret)

	// Create sealed secret
	ss := sealedsecret.CreateSealedSecret(h.cfg.PemFile, &k8sSecret)

	// Write sealed secret to disk
	newBase := helpers.EnsurePathAndReturnWritePath(h.cfg.ClonePath, h.cfg.DestEnv, ss.Name)

	// Collision check: another Vault path may have sanitized to the same
	// Kubernetes resource name. Refuse to overwrite a sealed secret that
	// originated from a different source path.
	if existing, err := readSourcePathAnnotation(newBase); err == nil && existing != "" && existing != event.SecretPath {
		msg := fmt.Sprintf(
			"sanitized name %q already used by source path %q (incoming source %q); refusing to overwrite",
			ss.Name, existing, event.SecretPath,
		)
		jsonLogger.Error("handleCreateOrUpdate.collision",
			"sanitizedName", ss.Name,
			"existingSourcePath", existing,
			"incomingSourcePath", event.SecretPath,
			"file", newBase,
		)
		h.recordEvent(event.Operation, event.SecretEngine, event.SecretPath, "collision", msg)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(SecretEventResponse{
			Status:     "collision",
			Operation:  event.Operation,
			SecretPath: event.SecretPath,
			Message:    msg,
		})
		return
	}

	sealedsecret.SerializeSealedSecretToFile(ss, newBase)
	jsonLogger.Info("Wrote sealed secret",
		slog.String("action", "request.operation."+event.Operation),
		slog.String("secret", ss.Name),
		slog.String("path", newBase),
	)

	// AWS writeback
	if h.cfg.AwsWriteback {
		writeAWS := awspkg.WriteAWSKeyValueSecret
		if h.hooks.WriteAWS != nil {
			writeAWS = h.hooks.WriteAWS
		}
		if err := writeAWS(theVaultSecret, event.SecretPath, h.cfg); err != nil {
			jsonLogger.Error("handleCreateOrUpdate.WriteAWSKeyValueSecret", "error", err)
		}
	}

	// Teams notification
	webhookURL := os.Getenv("KUBERNETES_NOTIFICATION_WEBHOOK_URL")
	if webhookURL != "" {
		notifyFn := helpers.NotifyTeamsChannel
		if h.hooks.NotifyTeams != nil {
			notifyFn = h.hooks.NotifyTeams
		}
		msgTitle := fmt.Sprintf("Raven %sd sealed secret in git", event.Operation)
		msgBody := fmt.Sprintf("%sd sealed secret in git: %s", event.Operation, ss.Name)
		notifyFn(msgTitle, msgBody, webhookURL)
	}

	// Git commit + push
	gitPushFn := gitops.GitPush
	if h.hooks.GitPush != nil {
		gitPushFn = h.hooks.GitPush
	}
	gitPushFn(h.cfg)

	// Kubernetes search/rollout
	initK8s := k8s.InitKubernetesSearch
	if h.hooks.InitK8sSearch != nil {
		initK8s = h.hooks.InitK8sSearch
	}
	initK8s(ss.Name, h.cfg)

	// ArgoCD refresh+sync of the configured Application (opt-in via env).
	argoSync := h.defaultArgoSync
	if h.hooks.ArgoSync != nil {
		argoSync = h.hooks.ArgoSync
	}
	if err := argoSync(ctx, ss.Name); err != nil {
		jsonLogger.Error("handleCreateOrUpdate.ArgoSync", "error", err, "secret", ss.Name)
		h.recordEvent("argocd-sync", event.SecretEngine, event.SecretPath, "error", err.Error())
	}

	h.recordEvent(event.Operation, event.SecretEngine, event.SecretPath, "ok", fmt.Sprintf("sealed secret written to %s", filepath.Base(newBase)))

	resp := SecretEventResponse{
		Status:     "processed",
		Operation:  event.Operation,
		SecretPath: event.SecretPath,
		Message:    fmt.Sprintf("secret %s %sd successfully", event.SecretPath, event.Operation),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *SecretEventHandler) handleDelete(w http.ResponseWriter, event SecretEvent) {
	jsonLogger.Info("Processing delete event",
		"engine", event.SecretEngine,
		"path", event.SecretPath,
	)

	h.mu.Lock()
	defer h.mu.Unlock()

	// Remove the sealed secret file from disk
	filePath := helpers.EnsurePathAndReturnWritePath(h.cfg.ClonePath, h.cfg.DestEnv, event.SecretPath)
	if _, err := os.Stat(filePath); err == nil {
		if err := os.Remove(filePath); err != nil {
			jsonLogger.Error("failed to remove sealed secret file", "error", err, "path", filePath)
			h.recordEvent(event.Operation, event.SecretEngine, event.SecretPath, "error", "failed to remove file: "+err.Error())
			http.Error(w, "failed to remove file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		jsonLogger.Info("Removed sealed secret file", "path", filePath)
	}

	// Git commit + push
	gitPushFn := gitops.GitPush
	if h.hooks.GitPush != nil {
		gitPushFn = h.hooks.GitPush
	}
	gitPushFn(h.cfg)

	// Kubernetes removal
	kubernetesRemove := os.Getenv("KUBERNETESREMOVE")
	if kubernetesRemove == "true" && h.cfg.Clientset != nil {
		secretList, err := k8s.KubernetesSecretList(h.cfg.Clientset, h.cfg.DestEnv)
		if err != nil {
			jsonLogger.Error("handleDelete.KubernetesSecretList", "error", err)
		} else {
			k8s.KubernetesRemove([]string{event.SecretPath}, secretList, h.cfg.Clientset, h.cfg.DestEnv)
		}
	}

	// Teams notification
	webhookURL := os.Getenv("KUBERNETES_NOTIFICATION_WEBHOOK_URL")
	if webhookURL != "" {
		notifyFn := helpers.NotifyTeamsChannel
		if h.hooks.NotifyTeams != nil {
			notifyFn = h.hooks.NotifyTeams
		}
		notifyFn("Raven deleted sealed secret from git",
			fmt.Sprintf("deleted sealed secret from git: %s", event.SecretPath),
			webhookURL)
	}

	h.recordEvent(event.Operation, event.SecretEngine, event.SecretPath, "ok", "deleted")

	resp := SecretEventResponse{
		Status:     "processed",
		Operation:  event.Operation,
		SecretPath: event.SecretPath,
		Message:    fmt.Sprintf("secret %s deleted successfully", event.SecretPath),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// RefreshSecretHandler returns a handler that re-syncs a single secret from Vault.
func (h *SecretEventHandler) RefreshSecretHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
		var req struct {
			SecretPath string `json:"secret_path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SecretPath == "" {
			http.Error(w, "invalid request: secret_path required", http.StatusBadRequest)
			return
		}
		event := SecretEvent{
			Operation:    "update",
			SecretEngine: h.cfg.SecretEngine,
			SecretPath:   req.SecretPath,
		}
		h.handleCreateOrUpdate(r.Context(), w, event)
	}
}

// HealthzHandler returns a simple health check handler.
func HealthzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
}

// EventsHandler returns a read-only JSON list of recent SyncEvents. Newest
// first. Intended for machine consumption (e.g. flock aggregation).
func (h *SecretEventHandler) EventsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		events := h.RecentEvents()
		if events == nil {
			events = []SyncEvent{}
		}
		if err := json.NewEncoder(w).Encode(events); err != nil {
			jsonLogger.Error("events: encode failed", "error", err)
		}
	})
}

// StatusInfo is a JSON-friendly snapshot of everything the dashboard
// renders for this raven. Consumed by flock for aggregation.
type StatusInfo struct {
	Engine      string       `json:"engine"`
	DestEnv     string       `json:"dest_env"`
	VaultURL    string       `json:"vault_url"`
	Sync        SyncSummary  `json:"sync"`
	Secrets     []SecretFile `json:"secrets"`
	SecretCount int          `json:"secret_count"`
	EventCount  int          `json:"event_count"`
	GeneratedAt time.Time    `json:"generated_at"`
}

// SyncSummary is the dashboard's sync timing block, machine-readable.
type SyncSummary struct {
	LastSync     time.Time `json:"last_sync"`
	NextSync     time.Time `json:"next_sync"`
	SleepSeconds int       `json:"sleep_seconds"`
	Overdue      bool      `json:"overdue"`
}

// SecretFile is a gitops-managed secret yaml with its current K8s state
// (if a matching Secret exists in the target namespace).
type SecretFile struct {
	Name       string          `json:"name"`
	SecretName string          `json:"secret_name"`
	Modified   time.Time       `json:"modified"`
	K8s        *SecretK8sState `json:"k8s,omitempty"`
}

// SecretK8sState captures what we know about a gitops secret as it exists
// in the destination K8s namespace.
type SecretK8sState struct {
	Created      string   `json:"created,omitempty"`
	Modified     string   `json:"modified,omitempty"`
	Source       string   `json:"source,omitempty"`
	Deployments  []string `json:"deployments,omitempty"`
	StatefulSets []string `json:"statefulsets,omitempty"`
}

// StatusHandler returns the bundled status payload (engine config, sync
// timing, secret list, event count). Read-only.
func (h *SecretEventHandler) StatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var secrets []SecretFile
		secretCount := 0
		files, err := gitops.GetBaseListOfFiles(h.cfg)
		if err == nil {
			secrets = make([]SecretFile, 0, len(files))
			for _, f := range files {
				name := f.Name()
				secrets = append(secrets, SecretFile{
					Name:       name,
					SecretName: strings.TrimSuffix(name, ".yaml"),
					Modified:   f.ModTime(),
				})
			}
			secretCount = len(secrets)
		}

		// Join with K8s state when a clientset is configured. Best-effort —
		// failures here just leave SecretFile.K8s nil.
		if h.cfg.Clientset != nil {
			joinK8sState(r.Context(), h.cfg, secrets)
		}

		sync := h.GetSyncStatus()
		summary := SyncSummary{
			LastSync:     sync.LastSync,
			NextSync:     sync.NextSync,
			SleepSeconds: sync.SleepSeconds,
		}
		if !sync.NextSync.IsZero() {
			summary.Overdue = time.Now().After(sync.NextSync)
		}

		eventCount := 0
		if h.eventStore != nil {
			if c, err := h.eventStore.Count(); err == nil {
				eventCount = c
			}
		} else {
			h.eventsMu.RLock()
			eventCount = len(h.recentEvents)
			h.eventsMu.RUnlock()
		}

		out := StatusInfo{
			Engine:      h.cfg.SecretEngine,
			DestEnv:     h.cfg.DestEnv,
			VaultURL:    h.cfg.VaultEndpoint,
			Sync:        summary,
			Secrets:     secrets,
			SecretCount: secretCount,
			EventCount:  eventCount,
			GeneratedAt: time.Now(),
		}
		if err := json.NewEncoder(w).Encode(out); err != nil {
			jsonLogger.Error("status: encode failed", "error", err)
		}
	})
}

// joinK8sState mutates `secrets` in place, attaching SecretK8sState to each
// entry whose SecretName matches a raven-labeled K8s Secret in the dest
// namespace. Errors are swallowed: nil K8s field == "unknown".
func joinK8sState(ctx context.Context, cfg config.Config, secrets []SecretFile) {
	secretList, err := k8s.KubernetesSecretList(cfg.Clientset, cfg.DestEnv)
	if err != nil || secretList == nil {
		return
	}
	deps, _ := cfg.Clientset.AppsV1().Deployments(cfg.DestEnv).List(ctx, metav1.ListOptions{})
	stss, _ := cfg.Clientset.AppsV1().StatefulSets(cfg.DestEnv).List(ctx, metav1.ListOptions{})

	byName := make(map[string]*SecretK8sState, len(secretList.Items))
	for _, s := range secretList.Items {
		if !k8s.Hask8sRavenLabel(s) {
			continue
		}
		created := s.CreationTimestamp.Format("2006-01-02 15:04:05")
		modified := created
		for _, mf := range s.ManagedFields {
			if mf.Time != nil && mf.Time.Time.After(s.CreationTimestamp.Time) {
				modified = mf.Time.Format("2006-01-02 15:04:05")
			}
		}
		st := &SecretK8sState{
			Created:  created,
			Modified: modified,
			Source:   s.Annotations["source"],
		}
		if deps != nil {
			for _, d := range deps.Items {
				for _, v := range d.Spec.Template.Spec.Volumes {
					if v.Secret != nil && v.Secret.SecretName == s.Name {
						st.Deployments = append(st.Deployments, d.Name)
					}
				}
			}
		}
		if stss != nil {
			for _, ss := range stss.Items {
				for _, v := range ss.Spec.Template.Spec.Volumes {
					if v.Secret != nil && v.Secret.SecretName == s.Name {
						st.StatefulSets = append(st.StatefulSets, ss.Name)
					}
				}
			}
		}
		byName[s.Name] = st
	}
	for i := range secrets {
		if st, ok := byName[secrets[i].SecretName]; ok {
			secrets[i].K8s = st
		}
	}
}

// K8sSecretInfo represents a Raven-managed secret found in the K8s namespace.
type K8sSecretInfo struct {
	Name         string   `json:"name"`
	Created      string   `json:"created"`
	Modified     string   `json:"modified"`
	Source       string   `json:"source"`
	Deployments  []string `json:"deployments"`
	StatefulSets []string `json:"statefulsets"`
}

// K8sStatusResponse is the JSON response from the /api/v1/k8s-status endpoint.
type K8sStatusResponse struct {
	Enabled   bool            `json:"enabled"`
	Namespace string          `json:"namespace"`
	Secrets   []K8sSecretInfo `json:"secrets"`
	Rollout   bool            `json:"rollout_enabled"`
	Monitor   bool            `json:"monitor_enabled"`
	Cleanup   bool            `json:"cleanup_enabled"`
}

// K8sStatusHandler returns an HTTP handler that queries K8s namespace status.
func K8sStatusHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		rollout := os.Getenv("KUBERNETES_ROLLOUT") == "true"
		monitor := os.Getenv("KUBERNETESMONITOR") == "true"
		cleanup := os.Getenv("KUBERNETESREMOVE") == "true"

		if cfg.Clientset == nil {
			json.NewEncoder(w).Encode(K8sStatusResponse{
				Enabled:   false,
				Namespace: cfg.DestEnv,
				Rollout:   rollout,
				Monitor:   monitor,
				Cleanup:   cleanup,
			})
			return
		}

		secretList, err := k8s.KubernetesSecretList(cfg.Clientset, cfg.DestEnv)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(K8sStatusResponse{
				Enabled:   true,
				Namespace: cfg.DestEnv,
				Rollout:   rollout,
				Monitor:   monitor,
				Cleanup:   cleanup,
			})
			jsonLogger.Error("k8s-status: failed to list secrets", "error", err)
			return
		}

		ctx := r.Context()
		deps, _ := cfg.Clientset.AppsV1().Deployments(cfg.DestEnv).List(ctx, metav1.ListOptions{})
		stss, _ := cfg.Clientset.AppsV1().StatefulSets(cfg.DestEnv).List(ctx, metav1.ListOptions{})

		var secrets []K8sSecretInfo
		for _, s := range secretList.Items {
			if !k8s.Hask8sRavenLabel(s) {
				continue
			}

			created := s.CreationTimestamp.Format("2006-01-02 15:04:05")
			modified := created
			for _, mf := range s.ManagedFields {
				if mf.Time != nil && mf.Time.Time.After(s.CreationTimestamp.Time) {
					modified = mf.Time.Format("2006-01-02 15:04:05")
				}
			}

			var depNames []string
			if deps != nil {
				for _, d := range deps.Items {
					for _, v := range d.Spec.Template.Spec.Volumes {
						if v.Secret != nil && v.Secret.SecretName == s.Name {
							depNames = append(depNames, d.Name)
						}
					}
				}
			}

			var stsNames []string
			if stss != nil {
				for _, ss := range stss.Items {
					for _, v := range ss.Spec.Template.Spec.Volumes {
						if v.Secret != nil && v.Secret.SecretName == s.Name {
							stsNames = append(stsNames, ss.Name)
						}
					}
				}
			}

			secrets = append(secrets, K8sSecretInfo{
				Name:         s.Name,
				Created:      created,
				Modified:     modified,
				Source:       s.Annotations["source"],
				Deployments:  depNames,
				StatefulSets: stsNames,
			})
		}

		json.NewEncoder(w).Encode(K8sStatusResponse{
			Enabled:   true,
			Namespace: cfg.DestEnv,
			Secrets:   secrets,
			Rollout:   rollout,
			Monitor:   monitor,
			Cleanup:   cleanup,
		})
	}
}

// PipelineStage represents one stage in a secret's lifecycle.
type PipelineStage struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "done", "active", "pending"
	Time   string `json:"time,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// PipelineEntry represents the lifecycle of a single secret.
type PipelineEntry struct {
	Secret       string          `json:"secret"`
	Stages       []PipelineStage `json:"stages"`
	K8sCreated   string          `json:"k8s_created,omitempty"`
	K8sModified  string          `json:"k8s_modified,omitempty"`
	Source       string          `json:"source,omitempty"`
	DataKeys     []string        `json:"data_keys,omitempty"`
	Deployments  []string        `json:"deployments,omitempty"`
	StatefulSets []string        `json:"statefulsets,omitempty"`
	Namespace    string          `json:"namespace,omitempty"`
	Engine       string          `json:"engine,omitempty"`
}

// PipelineHandler returns the lifecycle pipeline for all secrets.
func PipelineHandler(cfg config.Config, events *SecretEventHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		files, _ := gitops.GetBaseListOfFiles(cfg)

		type k8sMeta struct {
			Created      string
			Modified     string
			Source       string
			DataKeys     []string
			Deployments  []string
			StatefulSets []string
		}
		k8sSecrets := map[string]*k8sMeta{}
		if cfg.Clientset != nil {
			ctx := r.Context()
			if sl, err := k8s.KubernetesSecretList(cfg.Clientset, cfg.DestEnv); err == nil {
				deps, _ := cfg.Clientset.AppsV1().Deployments(cfg.DestEnv).List(ctx, metav1.ListOptions{})
				stss, _ := cfg.Clientset.AppsV1().StatefulSets(cfg.DestEnv).List(ctx, metav1.ListOptions{})
				for _, s := range sl.Items {
					if !k8s.Hask8sRavenLabel(s) {
						continue
					}
					created := s.CreationTimestamp.Format("2006-01-02 15:04:05")
					modified := created
					for _, mf := range s.ManagedFields {
						if mf.Time != nil && mf.Time.Time.After(s.CreationTimestamp.Time) {
							modified = mf.Time.Format("2006-01-02 15:04:05")
						}
					}
					var keys []string
					for k := range s.Data {
						keys = append(keys, k)
					}
					var depNames, stsNames []string
					if deps != nil {
						for _, d := range deps.Items {
							for _, v := range d.Spec.Template.Spec.Volumes {
								if v.Secret != nil && v.Secret.SecretName == s.Name {
									depNames = append(depNames, d.Name)
								}
							}
						}
					}
					if stss != nil {
						for _, ss := range stss.Items {
							for _, v := range ss.Spec.Template.Spec.Volumes {
								if v.Secret != nil && v.Secret.SecretName == s.Name {
									stsNames = append(stsNames, ss.Name)
								}
							}
						}
					}
					k8sSecrets[s.Name] = &k8sMeta{
						Created:      created,
						Modified:     modified,
						Source:       s.Annotations["source"],
						DataKeys:     keys,
						Deployments:  depNames,
						StatefulSets: stsNames,
					}
				}
			}
		}

		// Build event history lookup: secret -> operation -> latest event
		eventMap := map[string]map[string]store.Event{}
		if events.eventStore != nil {
			for _, f := range files {
				name := strings.TrimSuffix(f.Name(), ".yaml")
				evs, err := events.eventStore.EventsByPath(name)
				if err != nil || len(evs) == 0 {
					continue
				}
				m := map[string]store.Event{}
				for _, ev := range evs {
					if _, exists := m[ev.Operation]; !exists {
						m[ev.Operation] = ev
					}
				}
				eventMap[name] = m
			}
		}

		var entries []PipelineEntry
		for _, f := range files {
			name := strings.TrimSuffix(f.Name(), ".yaml")
			evHistory := eventMap[name]

			// Stage 1: Vault
			vaultStage := PipelineStage{Name: "Vault", Status: "pending"}
			if ev, ok := evHistory["create"]; ok {
				vaultStage.Status = "done"
				vaultStage.Time = ev.Time.Format("15:04:05")
				vaultStage.Detail = ev.Operation
			} else if ev, ok := evHistory["update"]; ok {
				vaultStage.Status = "done"
				vaultStage.Time = ev.Time.Format("15:04:05")
				vaultStage.Detail = ev.Operation
			}

			// Stage 2: Sealed (Raven wrote sealed secret to git)
			sealedStage := PipelineStage{Name: "Sealed", Status: "done"}
			if vaultStage.Time != "" {
				sealedStage.Time = vaultStage.Time
			}
			sealedStage.Detail = name + ".yaml"

			// Stage 3: Git pushed
			gitStage := PipelineStage{Name: "Git", Status: "done", Detail: "in worktree"}
			if vaultStage.Time != "" {
				gitStage.Time = vaultStage.Time
			}

			// Stage 4: ArgoCD synced
			argoStage := PipelineStage{Name: "ArgoCD", Status: "pending"}
			meta := k8sSecrets[name]
			if meta != nil {
				argoStage.Status = "done"
				argoStage.Detail = "synced"
			}

			// Stage 5: K8s Secret
			k8sStage := PipelineStage{Name: "K8s Secret", Status: "pending"}
			if meta != nil {
				k8sStage.Status = "done"
				if ev, ok := evHistory["k8s-added"]; ok {
					k8sStage.Time = ev.Time.Format("15:04:05")
				} else if ev, ok := evHistory["k8s-modified"]; ok {
					k8sStage.Time = ev.Time.Format("15:04:05")
				}
			}

			// Stage 6: Rollout
			rolloutStage := PipelineStage{Name: "Rollout", Status: "pending"}
			if ev, ok := evHistory["k8s-rollout"]; ok {
				rolloutStage.Status = "done"
				rolloutStage.Time = ev.Time.Format("15:04:05")
				rolloutStage.Detail = ev.Message
			} else if meta != nil {
				rolloutStage.Detail = "no workloads"
			}

			pe := PipelineEntry{
				Secret:    name,
				Stages:    []PipelineStage{vaultStage, sealedStage, gitStage, argoStage, k8sStage, rolloutStage},
				Namespace: cfg.DestEnv,
				Engine:    cfg.SecretEngine,
			}
			if meta != nil {
				pe.K8sCreated = meta.Created
				pe.K8sModified = meta.Modified
				pe.Source = meta.Source
				pe.DataKeys = meta.DataKeys
				pe.Deployments = meta.Deployments
				pe.StatefulSets = meta.StatefulSets
			}
			entries = append(entries, pe)
		}
		json.NewEncoder(w).Encode(entries)
	}
}

// readSourcePathAnnotation reads a serialized SealedSecret YAML from path and
// returns the value of the raven.no/source-path annotation. Returns "" and
// nil error when the file does not exist (no collision). Returns "" and a
// non-nil error only when the file exists but cannot be parsed; in that case
// the caller should err on the side of treating it as no-collision (logs the
// error elsewhere) rather than silently blocking writes.
func readSourcePathAnnotation(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	var doc struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", err
	}
	return doc.Metadata.Annotations[helpers.AnnotationSourcePath], nil
}
