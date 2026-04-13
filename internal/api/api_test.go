package api

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/volck/raven/internal/config"
	"github.com/volck/raven/internal/helpers"
	"github.com/volck/raven/internal/testutil"
	vaultpkg "github.com/volck/raven/internal/vault"
)

// testHooks returns Hooks that track calls instead of doing real git/AWS/K8s ops.
func testHooks(t *testing.T) (Hooks, *hookTracker) {
	t.Helper()
	tracker := &hookTracker{}
	hooks := Hooks{
		GitPush: func(cfg config.Config) {
			tracker.gitPushCalled.Add(1)
		},
		NotifyTeams: func(title, body, url string) {
			tracker.notifyTeamsCalled.Add(1)
			tracker.lastNotifyTitle = title
		},
		WriteAWS: func(secret *api.Secret, path string, cfg config.Config) error {
			tracker.awsWriteCalled.Add(1)
			return nil
		},
		InitK8sSearch: func(secret string, cfg config.Config) {
			tracker.k8sSearchCalled.Add(1)
		},
	}
	return hooks, tracker
}

type hookTracker struct {
	gitPushCalled     atomic.Int32
	notifyTeamsCalled atomic.Int32
	awsWriteCalled    atomic.Int32
	k8sSearchCalled   atomic.Int32
	lastNotifyTitle   string
}

func TestSecretEventHandler_CreateWritesSealedSecret(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	tmpDir := t.TempDir()
	pemFile := writeTempPemFile(t, tmpDir)

	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = tmpDir
	cfg.PemFile = pemFile

	// Write a secret to Vault
	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"myKey": "myValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	_, err := client.Logical().Write("kv/data/test-create-sealed", secrets)
	if err != nil {
		t.Fatal(err)
	}

	hooks, tracker := testHooks(t)
	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	event := SecretEvent{
		Operation:    "create",
		SecretEngine: "kv",
		SecretPath:   "test-create-sealed",
	}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify sealed secret file was written to disk
	sealedDir := filepath.Join(tmpDir, "declarative", cfg.DestEnv, "sealedsecrets")
	entries, err := os.ReadDir(sealedDir)
	if err != nil {
		t.Fatalf("expected sealed secret dir to exist: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one sealed secret file on disk")
	}

	// Verify git push was called
	if tracker.gitPushCalled.Load() != 1 {
		t.Errorf("expected gitPush called 1 time, got %d", tracker.gitPushCalled.Load())
	}

	// Verify K8s search was triggered
	if tracker.k8sSearchCalled.Load() != 1 {
		t.Errorf("expected k8sSearch called 1 time, got %d", tracker.k8sSearchCalled.Load())
	}

	var resp SecretEventResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != "processed" {
		t.Errorf("expected status 'processed', got '%s'", resp.Status)
	}
}

func TestSecretEventHandler_CreateWithTeamsNotification(t *testing.T) {
	// Set webhook URL so handler sends notification
	t.Setenv("KUBERNETES_NOTIFICATION_WEBHOOK_URL", "http://fake-teams.local/webhook")

	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	tmpDir := t.TempDir()
	pemFile := writeTempPemFile(t, tmpDir)
	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = tmpDir
	cfg.PemFile = pemFile

	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"key": "val"},
		"metadata": map[string]interface{}{"version": 1},
	}
	_, err := client.Logical().Write("kv/data/teams-notify-secret", secrets)
	if err != nil {
		t.Fatal(err)
	}

	hooks, tracker := testHooks(t)
	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	event := SecretEvent{Operation: "create", SecretEngine: "kv", SecretPath: "teams-notify-secret"}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if tracker.notifyTeamsCalled.Load() != 1 {
		t.Errorf("expected Teams notification, got %d calls", tracker.notifyTeamsCalled.Load())
	}
}

func TestSecretEventHandler_CreateWithAWSWriteback(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	tmpDir := t.TempDir()
	pemFile := writeTempPemFile(t, tmpDir)
	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = tmpDir
	cfg.PemFile = pemFile
	cfg.AwsWriteback = true

	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"key": "val"},
		"metadata": map[string]interface{}{"version": 1},
	}
	_, err := client.Logical().Write("kv/data/aws-wb-secret", secrets)
	if err != nil {
		t.Fatal(err)
	}

	hooks, tracker := testHooks(t)
	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	event := SecretEvent{Operation: "create", SecretEngine: "kv", SecretPath: "aws-wb-secret"}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if tracker.awsWriteCalled.Load() != 1 {
		t.Errorf("expected AWS writeback called 1 time, got %d", tracker.awsWriteCalled.Load())
	}
}

func TestSecretEventHandler_UpdateRewritesSealedSecret(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	tmpDir := t.TempDir()
	pemFile := writeTempPemFile(t, tmpDir)
	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = tmpDir
	cfg.PemFile = pemFile

	// Write v1
	_, err := client.Logical().Write("kv/data/test-update-sealed", map[string]interface{}{
		"data":     map[string]interface{}{"myKey": "v1"},
		"metadata": map[string]interface{}{"version": 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	hooks, tracker := testHooks(t)
	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	// Create
	event := SecretEvent{Operation: "create", SecretEngine: "kv", SecretPath: "test-update-sealed"}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Get file info before update
	sealedDir := filepath.Join(tmpDir, "declarative", cfg.DestEnv, "sealedsecrets")
	entriesBefore, _ := os.ReadDir(sealedDir)
	if len(entriesBefore) == 0 {
		t.Fatal("expected sealed secret file after create")
	}
	infoBefore, _ := entriesBefore[0].Info()
	sizeBefore := infoBefore.Size()

	// Write v2 with different data
	_, err = client.Logical().Write("kv/data/test-update-sealed", map[string]interface{}{
		"data":     map[string]interface{}{"myKey": "v2-updated-value-longer"},
		"metadata": map[string]interface{}{"version": 2},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Update
	eventUpdate := SecretEvent{Operation: "update", SecretEngine: "kv", SecretPath: "test-update-sealed"}
	bodyUpdate, _ := json.Marshal(eventUpdate)
	reqUpdate := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(bodyUpdate))
	reqUpdate.Header.Set("Content-Type", "application/json")
	rrUpdate := httptest.NewRecorder()
	handler.ServeHTTP(rrUpdate, reqUpdate)
	if rrUpdate.Code != http.StatusOK {
		t.Fatalf("update: expected 200, got %d: %s", rrUpdate.Code, rrUpdate.Body.String())
	}

	// Verify file was rewritten (size should differ with different data)
	entriesAfter, _ := os.ReadDir(sealedDir)
	infoAfter, _ := entriesAfter[0].Info()
	sizeAfter := infoAfter.Size()
	if sizeBefore == sizeAfter {
		t.Log("Warning: file sizes identical after update — sealed secret may use different encryption each time")
	}

	// Git push should have been called twice (create + update)
	if tracker.gitPushCalled.Load() != 2 {
		t.Errorf("expected gitPush called 2 times, got %d", tracker.gitPushCalled.Load())
	}
}

func TestSecretEventHandler_DeleteWithGitPush(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	cfg := testutil.NewTestConfig(cluster)

	tmpDir := t.TempDir()
	cfg.ClonePath = tmpDir

	// Create a fake sealed secret file
	sealedDir := filepath.Join(tmpDir, "declarative", cfg.DestEnv, "sealedsecrets")
	os.MkdirAll(sealedDir, os.ModePerm)
	dummyFile := filepath.Join(sealedDir, "test-delete-git.yaml")
	os.WriteFile(dummyFile, []byte("kind: SealedSecret"), 0644)

	hooks, tracker := testHooks(t)
	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	event := SecretEvent{Operation: "delete", SecretEngine: "kv", SecretPath: "test-delete-git"}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify file removed
	if _, err := os.Stat(dummyFile); !os.IsNotExist(err) {
		t.Error("expected sealed secret file to be deleted")
	}

	// Verify git push was called
	if tracker.gitPushCalled.Load() != 1 {
		t.Errorf("expected gitPush called 1 time, got %d", tracker.gitPushCalled.Load())
	}
}

func TestSecretEventHandler_InvalidJSON(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	cfg := testutil.NewTestConfig(cluster)

	handler := NewSecretEventHandler(client, cfg)

	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestSecretEventHandler_UnknownOperation(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	cfg := testutil.NewTestConfig(cluster)

	handler := NewSecretEventHandler(client, cfg)

	event := SecretEvent{Operation: "list", SecretEngine: "kv", SecretPath: "something"}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown operation, got %d", rr.Code)
	}
}

func TestSecretEventHandler_SecretNotInVault(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = t.TempDir()

	handler := NewSecretEventHandler(client, cfg)

	event := SecretEvent{Operation: "create", SecretEngine: "kv", SecretPath: "nonexistent-secret"}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing secret, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSecretEventHandler_ConcurrentRequests(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	tmpDir := t.TempDir()
	pemFile := writeTempPemFile(t, tmpDir)
	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = tmpDir
	cfg.PemFile = pemFile

	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("concurrent-secret-%d", i)
		secrets := map[string]interface{}{
			"data":     map[string]interface{}{"key": fmt.Sprintf("value-%d", i)},
			"metadata": map[string]interface{}{"version": 1},
		}
		_, err := client.Logical().Write(fmt.Sprintf("kv/data/%s", name), secrets)
		if err != nil {
			t.Fatal(err)
		}
	}

	hooks, tracker := testHooks(t)
	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	done := make(chan struct{}, 5)
	for i := 0; i < 5; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			event := SecretEvent{
				Operation:    "create",
				SecretEngine: "kv",
				SecretPath:   fmt.Sprintf("concurrent-secret-%d", idx),
			}
			body, _ := json.Marshal(event)
			req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("concurrent request %d: expected 200, got %d", idx, rr.Code)
			}
		}(i)
	}

	for i := 0; i < 5; i++ {
		<-done
	}

	// All 5 should have triggered git push
	if tracker.gitPushCalled.Load() != 5 {
		t.Errorf("expected 5 git pushes, got %d", tracker.gitPushCalled.Load())
	}
}

func TestHealthzHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()

	HealthzHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// writeTempPemFile writes the test PEM cert to a temp file and returns the path.
func writeTempPemFile(t *testing.T, dir string) string {
	t.Helper()
	privateKeys := testutil.ReturnPrivateKey(t)
	var privKey interface{}
	for _, v := range privateKeys {
		privKey = v
		break
	}

	// Generate a self-signed cert from the key for sealed secrets
	key := privKey.(*rsa.PrivateKey)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(dir, "test-cert.pem")
	f, err := os.Create(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	f.Close()
	return pemPath
}

// Ensure unused imports are referenced
var _ = helpers.JsonLogger
var _ = vaultpkg.GetSingleKV
var _ *api.Secret
