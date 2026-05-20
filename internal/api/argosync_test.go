package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/volck/raven/internal/config"
	"github.com/volck/raven/internal/testutil"
)

// TestHandleCreateOrUpdate_TriggersArgoSync verifies the ArgoSync hook fires
// once per create/update with the sealed-secret name.
func TestHandleCreateOrUpdate_TriggersArgoSync(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	tmpDir := t.TempDir()
	pemFile := writeTempPemFile(t, tmpDir)
	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = tmpDir
	cfg.PemFile = pemFile

	_, err := client.Logical().Write("kv/data/argo-sync-secret", map[string]interface{}{
		"data":     map[string]interface{}{"k": "v"},
		"metadata": map[string]interface{}{"version": 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	hooks, _ := testHooks(t)
	var argoCalls atomic.Int32
	var seenSecret atomic.Value
	hooks.ArgoSync = func(ctx context.Context, secretName string) error {
		argoCalls.Add(1)
		seenSecret.Store(secretName)
		return nil
	}

	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	event := SecretEvent{Operation: "update", SecretEngine: "kv", SecretPath: "argo-sync-secret"}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if argoCalls.Load() != 1 {
		t.Fatalf("expected ArgoSync called once, got %d", argoCalls.Load())
	}
	if got, _ := seenSecret.Load().(string); got != "argo-sync-secret" {
		t.Errorf("ArgoSync got secret=%q, want argo-sync-secret", got)
	}
}

// TestHandleCreateOrUpdate_ArgoSyncErrorDoesNotFailRequest verifies that an
// ArgoCD sync failure is recorded as an error event but still returns 200.
func TestHandleCreateOrUpdate_ArgoSyncErrorDoesNotFailRequest(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	tmpDir := t.TempDir()
	pemFile := writeTempPemFile(t, tmpDir)
	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = tmpDir
	cfg.PemFile = pemFile

	_, err := client.Logical().Write("kv/data/argo-err-secret", map[string]interface{}{
		"data":     map[string]interface{}{"k": "v"},
		"metadata": map[string]interface{}{"version": 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	hooks, _ := testHooks(t)
	hooks.ArgoSync = func(ctx context.Context, secretName string) error {
		return errors.New("argocd: boom")
	}
	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	event := SecretEvent{Operation: "create", SecretEngine: "kv", SecretPath: "argo-err-secret"}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("ArgoSync error should not fail request, got %d: %s", rr.Code, rr.Body.String())
	}

	var foundErrEvent bool
	for _, ev := range handler.RecentEvents() {
		if ev.Operation == "argocd-sync" && ev.Status == "error" {
			foundErrEvent = true
			break
		}
	}
	if !foundErrEvent {
		t.Error("expected argocd-sync error event to be recorded")
	}
}

// TestHandleDelete_DoesNotCallArgoSync verifies deletions don't trigger a sync.
func TestHandleDelete_DoesNotCallArgoSync(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	tmpDir := t.TempDir()
	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = tmpDir
	cfg.PemFile = writeTempPemFile(t, tmpDir)

	hooks, _ := testHooks(t)
	var argoCalls atomic.Int32
	hooks.ArgoSync = func(ctx context.Context, secretName string) error {
		argoCalls.Add(1)
		return nil
	}
	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	event := SecretEvent{Operation: "delete", SecretEngine: "kv", SecretPath: "anything"}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if argoCalls.Load() != 0 {
		t.Errorf("ArgoSync should not fire on delete, got %d calls", argoCalls.Load())
	}
}

// TestDefaultArgoSync_DisabledIsNoop verifies the default implementation is a
// no-op when ARGOCD_SYNC_ENABLED is not set.
func TestDefaultArgoSync_DisabledIsNoop(t *testing.T) {
	t.Setenv("ARGOCD_SYNC_ENABLED", "")
	t.Setenv("ARGOCD_SERVER", "")
	t.Setenv("ARGOCD_AUTH_TOKEN", "")
	t.Setenv("ARGOCD_APP_NAME", "ssg")

	// reset lazy init for test isolation
	argoClientOnce = sync.Once{}
	argoClient = nil

	h := &SecretEventHandler{cfg: config.Config{}}
	if err := h.defaultArgoSync(context.Background(), "any"); err != nil {
		t.Fatalf("disabled default should no-op, got: %v", err)
	}
}
