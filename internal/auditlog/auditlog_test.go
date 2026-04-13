package auditlog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseEntry_CreateSecret(t *testing.T) {
	line := `{"type":"response","auth":{"token_type":"service"},"request":{"id":"abc123","operation":"create","path":"team-a-kv/data/mysecret","mount_type":"kv"},"response":{},"error":""}`

	entry, err := ParseEntry([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Type != "response" {
		t.Errorf("expected type 'response', got '%s'", entry.Type)
	}
	if entry.Request.Operation != "create" {
		t.Errorf("expected operation 'create', got '%s'", entry.Request.Operation)
	}
	if entry.Request.Path != "team-a-kv/data/mysecret" {
		t.Errorf("expected path 'team-a-kv/data/mysecret', got '%s'", entry.Request.Path)
	}
	if entry.Request.MountType != "kv" {
		t.Errorf("expected mount_type 'kv', got '%s'", entry.Request.MountType)
	}
}

func TestParseEntry_AllOperations(t *testing.T) {
	tests := []struct {
		name          string
		line          string
		wantOperation string
		wantPath      string
		wantErr       bool
	}{
		{
			name:          "create",
			line:          `{"type":"response","request":{"operation":"create","path":"kv/data/secret1","mount_type":"kv"},"error":""}`,
			wantOperation: "create",
			wantPath:      "kv/data/secret1",
		},
		{
			name:          "update",
			line:          `{"type":"response","request":{"operation":"update","path":"kv/data/secret1","mount_type":"kv"},"error":""}`,
			wantOperation: "update",
			wantPath:      "kv/data/secret1",
		},
		{
			name:          "delete",
			line:          `{"type":"response","request":{"operation":"delete","path":"kv/data/secret1","mount_type":"kv"},"error":""}`,
			wantOperation: "delete",
			wantPath:      "kv/data/secret1",
		},
		{
			name:          "soft-delete via delete path",
			line:          `{"type":"response","request":{"operation":"create","path":"kv/delete/secret1","mount_type":"kv"},"error":""}`,
			wantOperation: "create",
			wantPath:      "kv/delete/secret1",
		},
		{
			name:          "destroy",
			line:          `{"type":"response","request":{"operation":"create","path":"kv/destroy/secret1","mount_type":"kv"},"error":""}`,
			wantOperation: "create",
			wantPath:      "kv/destroy/secret1",
		},
		{
			name:    "invalid json",
			line:    `not json at all`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := ParseEntry([]byte(tt.line))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if entry.Request.Operation != tt.wantOperation {
				t.Errorf("expected operation '%s', got '%s'", tt.wantOperation, entry.Request.Operation)
			}
			if entry.Request.Path != tt.wantPath {
				t.Errorf("expected path '%s', got '%s'", tt.wantPath, entry.Request.Path)
			}
		})
	}
}

func TestParseEntry_IgnoresRequestType(t *testing.T) {
	line := `{"type":"request","request":{"operation":"create","path":"kv/data/secret1","mount_type":"kv"}}`
	entry, err := ParseEntry([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Type != "request" {
		t.Errorf("expected type 'request', got '%s'", entry.Type)
	}
}

func TestParseEntry_WithError(t *testing.T) {
	line := `{"type":"response","request":{"operation":"create","path":"kv/data/secret1","mount_type":"kv"},"error":"permission denied"}`
	entry, err := ParseEntry([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Error != "permission denied" {
		t.Errorf("expected error 'permission denied', got '%s'", entry.Error)
	}
}

func TestFilterBySecretEngine(t *testing.T) {
	engines := []string{"team-a-kv", "team-b-kv"}

	tests := []struct {
		name    string
		path    string
		matches bool
	}{
		{"matches team-a", "team-a-kv/data/mysecret", true},
		{"matches team-b", "team-b-kv/data/othersecret", true},
		{"no match", "team-c-kv/data/secret", false},
		{"metadata path", "team-a-kv/metadata/mysecret", true},
		{"partial match should not match", "team-a-kvv/data/secret", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesEngine(tt.path, engines); got != tt.matches {
				t.Errorf("MatchesEngine(%q) = %v, want %v", tt.path, got, tt.matches)
			}
		})
	}
}

func TestExtractSecretPath(t *testing.T) {
	tests := []struct {
		name     string
		fullPath string
		engine   string
		expected string
	}{
		{"simple", "team-a-kv/data/mysecret", "team-a-kv", "mysecret"},
		{"nested subpath", "team-a-kv/data/subpath/one/two/mysecret", "team-a-kv", "subpath/one/two/mysecret"},
		{"metadata path", "team-a-kv/metadata/mysecret", "team-a-kv", "mysecret"},
		{"delete path", "team-a-kv/delete/mysecret", "team-a-kv", "mysecret"},
		{"destroy path", "team-a-kv/destroy/mysecret", "team-a-kv", "mysecret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractSecretPath(tt.fullPath, tt.engine)
			if got != tt.expected {
				t.Errorf("ExtractSecretPath(%q, %q) = %q, want %q", tt.fullPath, tt.engine, got, tt.expected)
			}
		})
	}
}

func TestClassifyOperation(t *testing.T) {
	tests := []struct {
		name      string
		entry     AuditEntry
		wantOp    string
		wantValid bool
	}{
		{
			name: "create on data path",
			entry: AuditEntry{
				Type:  "response",
				Error: "",
				Request: AuditRequest{Operation: "create", Path: "kv/data/secret", MountType: "kv"},
			},
			wantOp:    "create",
			wantValid: true,
		},
		{
			name: "update on data path",
			entry: AuditEntry{
				Type:  "response",
				Error: "",
				Request: AuditRequest{Operation: "update", Path: "kv/data/secret", MountType: "kv"},
			},
			wantOp:    "update",
			wantValid: true,
		},
		{
			name: "delete on data path",
			entry: AuditEntry{
				Type:  "response",
				Error: "",
				Request: AuditRequest{Operation: "delete", Path: "kv/data/secret", MountType: "kv"},
			},
			wantOp:    "delete",
			wantValid: true,
		},
		{
			name: "soft-delete via delete path",
			entry: AuditEntry{
				Type:  "response",
				Error: "",
				Request: AuditRequest{Operation: "create", Path: "kv/delete/secret", MountType: "kv"},
			},
			wantOp:    "delete",
			wantValid: true,
		},
		{
			name: "destroy path",
			entry: AuditEntry{
				Type:  "response",
				Error: "",
				Request: AuditRequest{Operation: "create", Path: "kv/destroy/secret", MountType: "kv"},
			},
			wantOp:    "delete",
			wantValid: true,
		},
		{
			name: "list operation ignored",
			entry: AuditEntry{
				Type:  "response",
				Error: "",
				Request: AuditRequest{Operation: "list", Path: "kv/metadata/", MountType: "kv"},
			},
			wantValid: false,
		},
		{
			name: "read operation ignored",
			entry: AuditEntry{
				Type:  "response",
				Error: "",
				Request: AuditRequest{Operation: "read", Path: "kv/data/secret", MountType: "kv"},
			},
			wantValid: false,
		},
		{
			name: "request type ignored",
			entry: AuditEntry{
				Type:  "request",
				Error: "",
				Request: AuditRequest{Operation: "create", Path: "kv/data/secret", MountType: "kv"},
			},
			wantValid: false,
		},
		{
			name: "error response ignored",
			entry: AuditEntry{
				Type:  "response",
				Error: "permission denied",
				Request: AuditRequest{Operation: "create", Path: "kv/data/secret", MountType: "kv"},
			},
			wantValid: false,
		},
		{
			name: "non-kv mount type ignored",
			entry: AuditEntry{
				Type:  "response",
				Error: "",
				Request: AuditRequest{Operation: "create", Path: "transit/encrypt/mykey", MountType: "transit"},
			},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, valid := ClassifyOperation(tt.entry)
			if valid != tt.wantValid {
				t.Errorf("ClassifyOperation() valid = %v, want %v", valid, tt.wantValid)
			}
			if valid && op != tt.wantOp {
				t.Errorf("ClassifyOperation() op = %q, want %q", op, tt.wantOp)
			}
		})
	}
}

func TestDispatcher_PostsToCorrectURL(t *testing.T) {
	var receivedBody []byte
	var receivedAuth string

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBody = buf
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"processed"}`))
	}))
	defer targetServer.Close()

	routing := map[string]string{
		"team-a-kv": targetServer.URL,
	}

	d := NewDispatcher(routing, nil) // nil httpClient = default client

	event := DispatchEvent{
		Operation:    "create",
		SecretEngine: "team-a-kv",
		SecretPath:   "mysecret",
	}

	err := d.Dispatch(event)
	if err != nil {
		t.Fatal(err)
	}

	if receivedAuth != "" {
		// No auth client provided, so no auth header expected
	}

	var got map[string]string
	json.Unmarshal(receivedBody, &got)
	if got["operation"] != "create" {
		t.Errorf("expected operation 'create', got '%s'", got["operation"])
	}
	if got["secret_path"] != "mysecret" {
		t.Errorf("expected secret_path 'mysecret', got '%s'", got["secret_path"])
	}
}

func TestDispatcher_UnknownEngine(t *testing.T) {
	routing := map[string]string{
		"team-a-kv": "http://localhost:9999",
	}
	d := NewDispatcher(routing, nil)

	event := DispatchEvent{
		Operation:    "create",
		SecretEngine: "unknown-engine",
		SecretPath:   "mysecret",
	}

	err := d.Dispatch(event)
	if err == nil {
		t.Fatal("expected error for unknown engine")
	}
}

func TestFileTailer_ReadsNewLines(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "audit.log")

	// Write initial content
	if err := os.WriteFile(tmpFile, []byte("line1\nline2\n"), 0644); err != nil {
		t.Fatal(err)
	}

	lines := make(chan string, 10)
	tailer, err := NewFileTailer(tmpFile, 0)
	if err != nil {
		t.Fatal(err)
	}

	go tailer.Tail(lines)
	defer tailer.Stop()

	// Read the two existing lines
	got1 := <-lines
	if got1 != "line1" {
		t.Errorf("expected 'line1', got '%s'", got1)
	}
	got2 := <-lines
	if got2 != "line2" {
		t.Errorf("expected 'line2', got '%s'", got2)
	}

	// Append a new line
	f, err := os.OpenFile(tmpFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("line3\n")
	f.Close()

	got3 := <-lines
	if got3 != "line3" {
		t.Errorf("expected 'line3', got '%s'", got3)
	}
}

func TestDebouncer_DeduplicatesRapidEvents(t *testing.T) {
	received := make(chan DispatchEvent, 10)
	cb := func(event DispatchEvent) {
		received <- event
	}

	d := NewDebouncer(50*time.Millisecond, cb)
	defer d.Stop()

	// Send 5 rapid events for the same secret — should deduplicate to 1
	for i := 0; i < 5; i++ {
		d.Submit(DispatchEvent{Operation: "create", SecretEngine: "kv", SecretPath: "same-secret"})
	}

	// Wait for debounce window + some margin
	time.Sleep(150 * time.Millisecond)

	if len(received) != 1 {
		t.Errorf("expected 1 debounced event, got %d", len(received))
	}
}

func TestDebouncer_DifferentKeysNotMerged(t *testing.T) {
	received := make(chan DispatchEvent, 10)
	cb := func(event DispatchEvent) {
		received <- event
	}

	d := NewDebouncer(50*time.Millisecond, cb)
	defer d.Stop()

	d.Submit(DispatchEvent{Operation: "create", SecretEngine: "kv", SecretPath: "secret-a"})
	d.Submit(DispatchEvent{Operation: "update", SecretEngine: "kv", SecretPath: "secret-b"})

	time.Sleep(150 * time.Millisecond)

	if len(received) != 2 {
		t.Errorf("expected 2 events for different secrets, got %d", len(received))
	}
}

func TestDebouncer_LastOperationWins(t *testing.T) {
	received := make(chan DispatchEvent, 10)
	cb := func(event DispatchEvent) {
		received <- event
	}

	d := NewDebouncer(50*time.Millisecond, cb)
	defer d.Stop()

	d.Submit(DispatchEvent{Operation: "create", SecretEngine: "kv", SecretPath: "secret-x"})
	d.Submit(DispatchEvent{Operation: "update", SecretEngine: "kv", SecretPath: "secret-x"})
	d.Submit(DispatchEvent{Operation: "delete", SecretEngine: "kv", SecretPath: "secret-x"})

	time.Sleep(150 * time.Millisecond)

	event := <-received
	if event.Operation != "delete" {
		t.Errorf("expected last operation 'delete', got '%s'", event.Operation)
	}
}

func TestDispatcher_RetryOnFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"processed"}`))
	}))
	defer server.Close()

	routing := map[string]string{"kv": server.URL}
	d := NewDispatcher(routing, nil)
	d.MaxRetries = 5
	d.RetryBaseDelay = 10 * time.Millisecond

	err := d.Dispatch(DispatchEvent{Operation: "create", SecretEngine: "kv", SecretPath: "retry-secret"})
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestDispatcher_ExhaustsRetries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	routing := map[string]string{"kv": server.URL}
	d := NewDispatcher(routing, nil)
	d.MaxRetries = 2
	d.RetryBaseDelay = 10 * time.Millisecond

	err := d.Dispatch(DispatchEvent{Operation: "create", SecretEngine: "kv", SecretPath: "fail-secret"})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
}

func TestFileTailer_DetectsRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	// Write initial content
	os.WriteFile(logFile, []byte("line1\n"), 0644)

	lines := make(chan string, 10)
	tailer, err := NewFileTailer(logFile, 0)
	if err != nil {
		t.Fatal(err)
	}

	go tailer.Tail(lines)
	defer tailer.Stop()

	got := <-lines
	if got != "line1" {
		t.Errorf("expected 'line1', got '%s'", got)
	}

	// Simulate log rotation: remove old file, create new one
	os.Remove(logFile)
	os.WriteFile(logFile, []byte("rotated-line1\n"), 0644)

	// Should pick up the new file
	got2 := <-lines
	if got2 != "rotated-line1" {
		t.Errorf("expected 'rotated-line1', got '%s'", got2)
	}
}

func TestValidateConfig_MissingAuditLogPath(t *testing.T) {
	cfg := LogParserConfig{
		SecretEngines: []string{"kv"},
		Routing:       map[string]string{"kv": "http://localhost:8080"},
	}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for missing audit_log_path")
	}
}

func TestValidateConfig_EmptySecretEngines(t *testing.T) {
	cfg := LogParserConfig{
		AuditLogPath:  "/vault/audit.log",
		SecretEngines: []string{},
		Routing:       map[string]string{"kv": "http://localhost:8080"},
	}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty secret_engines")
	}
}

func TestValidateConfig_EmptyRouting(t *testing.T) {
	cfg := LogParserConfig{
		AuditLogPath:  "/vault/audit.log",
		SecretEngines: []string{"kv"},
		Routing:       map[string]string{},
	}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty routing")
	}
}

func TestValidateConfig_MissingRouteForEngine(t *testing.T) {
	cfg := LogParserConfig{
		AuditLogPath:  "/vault/audit.log",
		SecretEngines: []string{"kv", "team-b-kv"},
		Routing:       map[string]string{"kv": "http://localhost:8080"},
	}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for engine without route")
	}
}

func TestValidateConfig_Valid(t *testing.T) {
	cfg := LogParserConfig{
		AuditLogPath:  "/vault/audit.log",
		SecretEngines: []string{"kv"},
		Routing:       map[string]string{"kv": "http://localhost:8080"},
	}
	err := ValidateConfig(cfg)
	if err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}
}
