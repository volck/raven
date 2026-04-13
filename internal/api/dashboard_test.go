package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/volck/raven/internal/config"
)

func TestDashboardHandler_ReturnsHTML(t *testing.T) {
	// Create a temp dir with some fake sealed secret files
	tmpDir := t.TempDir()
	ssDir := filepath.Join(tmpDir, "declarative", "testns", "sealedsecrets")
	if err := os.MkdirAll(ssDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"secret-one.yaml", "secret-two.yaml"} {
		if err := os.WriteFile(filepath.Join(ssDir, name), []byte("---"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cfg := config.Config{
		ClonePath:    tmpDir,
		DestEnv:      "testns",
		SecretEngine: "kv",
		VaultEndpoint: "http://vault:8200",
	}

	handler := NewSecretEventHandler(nil, cfg)
	dashHandler := DashboardHandler(cfg, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	dashHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected text/html content-type, got %q", ct)
	}
	for _, want := range []string{"Raven", "secret-one.yaml", "secret-two.yaml", "kv", "testns"} {
		if !contains(body, want) {
			t.Errorf("dashboard HTML missing %q", want)
		}
	}
}

func TestDashboardHandler_404ForOtherPaths(t *testing.T) {
	cfg := config.Config{ClonePath: t.TempDir(), DestEnv: "ns"}
	handler := NewSecretEventHandler(nil, cfg)
	dashHandler := DashboardHandler(cfg, handler)

	req := httptest.NewRequest(http.MethodGet, "/notfound", nil)
	rr := httptest.NewRecorder()
	dashHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestDashboardHandler_EmptyWorktree(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.Config{
		ClonePath:    tmpDir,
		DestEnv:      "empty",
		SecretEngine: "kv",
	}
	handler := NewSecretEventHandler(nil, cfg)
	dashHandler := DashboardHandler(cfg, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	dashHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !contains(rr.Body.String(), "No sealed secrets found") {
		t.Error("expected empty state message")
	}
}

func TestRecentEvents_RecordAndRetrieve(t *testing.T) {
	handler := &SecretEventHandler{}

	handler.recordEvent("create", "kv", "secret-a", "ok", "created")
	handler.recordEvent("update", "kv", "secret-b", "ok", "updated")
	handler.recordEvent("delete", "kv", "secret-c", "ok", "deleted")

	events := handler.RecentEvents()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	// newest first
	if events[0].Path != "secret-c" {
		t.Errorf("expected newest first, got %q", events[0].Path)
	}
	if events[2].Path != "secret-a" {
		t.Errorf("expected oldest last, got %q", events[2].Path)
	}
}

func TestRecentEvents_CapsAt100(t *testing.T) {
	handler := &SecretEventHandler{}

	for i := 0; i < 120; i++ {
		handler.recordEvent("create", "kv", "secret", "ok", "msg")
	}

	events := handler.RecentEvents()
	if len(events) != 100 {
		t.Fatalf("expected 100 events (capped), got %d", len(events))
	}
}

func TestRecentEvents_ShownInDashboard(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.Config{
		ClonePath:    tmpDir,
		DestEnv:      "ns",
		SecretEngine: "kv",
	}
	handler := NewSecretEventHandler(nil, cfg)
	handler.recordEvent("create", "kv", "my-secret", "ok", "synced successfully")

	// Wait a tick so the event timestamp is populated
	time.Sleep(time.Millisecond)

	dashHandler := DashboardHandler(cfg, handler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	dashHandler.ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{"my-secret", "create", "synced successfully"} {
		if !contains(body, want) {
			t.Errorf("dashboard HTML missing event data %q", want)
		}
	}
}

func TestSyncStatus_ShownInDashboard(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.Config{
		ClonePath:    tmpDir,
		DestEnv:      "ns",
		SecretEngine: "kv",
	}
	handler := NewSecretEventHandler(nil, cfg)
	handler.SetSyncStatus(time.Date(2026, 4, 13, 10, 30, 0, 0, time.UTC), 1800)

	dashHandler := DashboardHandler(cfg, handler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	dashHandler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if !contains(body, "2026-04-13 10:30:00 UTC") {
		t.Error("dashboard should show last sync time")
	}
	if !contains(body, "11:00:00 UTC") {
		t.Error("dashboard should show next sync time (30m later)")
	}
	if !contains(body, "30m") {
		t.Error("dashboard should show sync interval")
	}
}

func TestSyncStatus_NotYetSynced(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.Config{
		ClonePath:    tmpDir,
		DestEnv:      "ns",
		SecretEngine: "kv",
	}
	handler := NewSecretEventHandler(nil, cfg)
	// Don't call SetSyncStatus

	dashHandler := DashboardHandler(cfg, handler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	dashHandler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if !contains(body, "not yet") {
		t.Error("dashboard should show 'not yet' when no sync has occurred")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDashboardHandler_ShowsRefreshButtons(t *testing.T) {
	tmpDir := t.TempDir()
	ssDir := filepath.Join(tmpDir, "declarative", "ns", "sealedsecrets")
	if err := os.MkdirAll(ssDir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(ssDir, "my-app.yaml"), []byte("---"), 0o644)

	cfg := config.Config{ClonePath: tmpDir, DestEnv: "ns", SecretEngine: "kv"}
	handler := NewSecretEventHandler(nil, cfg)
	dashHandler := DashboardHandler(cfg, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	dashHandler.ServeHTTP(rr, req)

	body := rr.Body.String()
	// Should show secret name without .yaml
	if !contains(body, "<strong>my-app</strong>") {
		t.Error("dashboard should show secret name without .yaml")
	}
	// Should have refresh button
	if !contains(body, "refreshSecret('my-app'") {
		t.Error("dashboard should have refresh button for each secret")
	}
	// Should still show file name
	if !contains(body, "my-app.yaml") {
		t.Error("dashboard should show the yaml filename")
	}
}

func TestRefreshSecretHandler_MissingPath(t *testing.T) {
	handler := &SecretEventHandler{}
	h := handler.RefreshSecretHandler()

	// Empty body
	req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh-secret", bytes.NewBufferString("{}"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestRefreshSecretHandler_MethodNotAllowed(t *testing.T) {
	handler := &SecretEventHandler{}
	h := handler.RefreshSecretHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/refresh-secret", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestWebSocketHub_BroadcastToClients(t *testing.T) {
	hub := NewHub()

	// Start a test server with the WS handler
	srv := httptest.NewServer(http.HandlerFunc(hub.ServeWS))
	defer srv.Close()

	// Connect a client
	wsURL := "ws" + srv.URL[4:] // http -> ws
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Give the server a moment to register the client
	time.Sleep(50 * time.Millisecond)
	if hub.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", hub.ClientCount())
	}

	// Broadcast a message
	hub.Broadcast(WSMessage{Type: "event", Data: map[string]string{"path": "hello"}})

	// Read the message on the client
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Contains(msg, []byte(`"type":"event"`)) {
		t.Fatalf("unexpected message: %s", msg)
	}
	if !bytes.Contains(msg, []byte(`"path":"hello"`)) {
		t.Fatalf("missing path in message: %s", msg)
	}
}

func TestWebSocketHub_ClientDisconnect(t *testing.T) {
	hub := NewHub()

	srv := httptest.NewServer(http.HandlerFunc(hub.ServeWS))
	defer srv.Close()

	wsURL := "ws" + srv.URL[4:]
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if hub.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", hub.ClientCount())
	}

	conn.Close()
	time.Sleep(100 * time.Millisecond)

	// Broadcast after disconnect — should not panic, client count goes to 0
	hub.Broadcast(WSMessage{Type: "test", Data: nil})
	// Client may linger briefly, but should be cleaned up
}
