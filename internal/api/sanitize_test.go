package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/volck/raven/internal/helpers"
	"github.com/volck/raven/internal/testutil"
	"sigs.k8s.io/yaml"
)

// rfc1123Subdomain is the same pattern enforced by Kubernetes for
// metadata.name on Secret / SealedSecret resources.
var rfc1123Subdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// TestSecretEventHandler_SanitizesNameAndRecordsSourcePath reproduces the
// ArgoCD failure case: a Vault path containing '/' must produce a sealed
// secret whose metadata.name is a valid RFC 1123 subdomain, with the
// original path preserved in the raven.no/source-path annotation.
func TestSecretEventHandler_SanitizesNameAndRecordsSourcePath(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	tmpDir := t.TempDir()
	pemFile := writeTempPemFile(t, tmpDir)

	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = tmpDir
	cfg.PemFile = pemFile

	const vaultPath = "nt/middlearth-aws-resource-viewer-credentials-prod"
	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"myKey": "myValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	if _, err := client.Logical().Write("kv/data/"+vaultPath, secrets); err != nil {
		t.Fatal(err)
	}

	hooks, _ := testHooks(t)
	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	event := SecretEvent{Operation: "create", SecretEngine: "kv", SecretPath: vaultPath}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	wantName := helpers.SanitizeK8sName(vaultPath)
	if !rfc1123Subdomain.MatchString(wantName) {
		t.Fatalf("sanitizer produced invalid name %q", wantName)
	}

	sealedDir := filepath.Join(tmpDir, "declarative", cfg.DestEnv, "sealedsecrets")
	wantFile := filepath.Join(sealedDir, wantName+".yaml")
	data, err := os.ReadFile(wantFile)
	if err != nil {
		// Aid debugging by listing what *was* written.
		entries, _ := os.ReadDir(sealedDir)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected sealed secret at %q, dir contents: %v", wantFile, names)
	}

	var doc struct {
		Metadata struct {
			Name        string            `json:"name"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse sealed secret yaml: %v", err)
	}

	if doc.Metadata.Name != wantName {
		t.Errorf("metadata.name = %q, want %q", doc.Metadata.Name, wantName)
	}
	if !rfc1123Subdomain.MatchString(doc.Metadata.Name) {
		t.Errorf("metadata.name %q is not a valid RFC 1123 subdomain", doc.Metadata.Name)
	}
	if got := doc.Metadata.Annotations[helpers.AnnotationSourcePath]; got != vaultPath {
		t.Errorf("annotation %q = %q, want %q", helpers.AnnotationSourcePath, got, vaultPath)
	}
}

// TestSecretEventHandler_RejectsCollision verifies that two different Vault
// paths which sanitize to the same Kubernetes name produce a 409 Conflict
// for the second write, and that the on-disk file is left untouched.
func TestSecretEventHandler_RejectsCollision(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	tmpDir := t.TempDir()
	pemFile := writeTempPemFile(t, tmpDir)

	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = tmpDir
	cfg.PemFile = pemFile

	// Two paths that sanitize to the same name "nt-foo":
	//   "nt/foo"  → "nt-foo"
	//   "nt-foo"  → "nt-foo"
	const firstPath = "nt/foo"
	const secondPath = "nt-foo"
	if helpers.SanitizeK8sName(firstPath) != helpers.SanitizeK8sName(secondPath) {
		t.Fatalf("test precondition violated: paths do not sanitize identically")
	}

	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"k": "v"},
		"metadata": map[string]interface{}{"version": 1},
	}
	for _, p := range []string{firstPath, secondPath} {
		if _, err := client.Logical().Write("kv/data/"+p, secrets); err != nil {
			t.Fatalf("write vault secret %q: %v", p, err)
		}
	}

	hooks, _ := testHooks(t)
	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	post := func(path string) *httptest.ResponseRecorder {
		event := SecretEvent{Operation: "create", SecretEngine: "kv", SecretPath: path}
		body, _ := json.Marshal(event)
		req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	// First write succeeds.
	if rr := post(firstPath); rr.Code != http.StatusOK {
		t.Fatalf("first write: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	wantName := helpers.SanitizeK8sName(firstPath)
	sealedFile := filepath.Join(tmpDir, "declarative", cfg.DestEnv, "sealedsecrets", wantName+".yaml")
	firstBytes, err := os.ReadFile(sealedFile)
	if err != nil {
		t.Fatalf("expected sealed secret on disk after first write: %v", err)
	}

	// Second write must collide.
	rr := post(secondPath)
	if rr.Code != http.StatusConflict {
		t.Fatalf("second write: expected 409 Conflict, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp SecretEventResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "collision" {
		t.Errorf("response status = %q, want %q", resp.Status, "collision")
	}

	// File contents must be unchanged.
	afterBytes, err := os.ReadFile(sealedFile)
	if err != nil {
		t.Fatalf("read sealed secret after collision: %v", err)
	}
	if !bytes.Equal(firstBytes, afterBytes) {
		t.Errorf("collision did not preserve original file; contents changed")
	}
}

// TestSecretEventHandler_SamePathUpdateIsNotCollision verifies that
// re-writing a sealed secret from the *same* source path (a legitimate
// update) is not treated as a collision.
func TestSecretEventHandler_SamePathUpdateIsNotCollision(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	tmpDir := t.TempDir()
	pemFile := writeTempPemFile(t, tmpDir)

	cfg := testutil.NewTestConfig(cluster)
	cfg.ClonePath = tmpDir
	cfg.PemFile = pemFile

	const vaultPath = "nt/some-secret"
	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"k": "v"},
		"metadata": map[string]interface{}{"version": 1},
	}
	if _, err := client.Logical().Write("kv/data/"+vaultPath, secrets); err != nil {
		t.Fatal(err)
	}

	hooks, _ := testHooks(t)
	handler := NewSecretEventHandlerWithHooks(client, cfg, hooks)

	for i, op := range []string{"create", "update"} {
		event := SecretEvent{Operation: op, SecretEngine: "kv", SecretPath: vaultPath}
		body, _ := json.Marshal(event)
		req := httptest.NewRequest("POST", "/api/v1/secret", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("call %d (%s): expected 200, got %d: %s", i, op, rr.Code, rr.Body.String())
		}
	}
}
