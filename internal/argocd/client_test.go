package argocd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClient_DisabledWhenNoServer(t *testing.T) {
	c := &Client{Server: "", Token: "x", Enable: true}
	if c.Enabled() {
		t.Fatal("expected Enabled()=false when Server empty")
	}

	c = &Client{Server: "https://argo", Token: "x", Enable: false}
	if c.Enabled() {
		t.Fatal("expected Enabled()=false when Enable=false")
	}

	c = &Client{Server: "https://argo", Token: "", Enable: true}
	if c.Enabled() {
		t.Fatal("expected Enabled()=false when Token empty")
	}

	c = &Client{Server: "https://argo", Token: "x", Enable: true}
	if !c.Enabled() {
		t.Fatal("expected Enabled()=true")
	}
}

func TestRefreshAndSync_CallsBothEndpointsAndSetsBearer(t *testing.T) {
	var refreshCalled, syncCalled int32
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/applications/demo") && r.URL.Query().Get("refresh") == "hard":
			atomic.AddInt32(&refreshCalled, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"metadata":{"name":"demo"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/applications/demo/sync":
			atomic.AddInt32(&syncCalled, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"synced"}`)
		default:
			t.Errorf("unexpected request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &Client{Server: srv.URL, Token: "jwt-abc", Enable: true, HTTP: srv.Client()}
	if err := c.RefreshAndSync(context.Background(), "demo"); err != nil {
		t.Fatalf("RefreshAndSync failed: %v", err)
	}
	if atomic.LoadInt32(&refreshCalled) != 1 {
		t.Errorf("expected 1 refresh call, got %d", refreshCalled)
	}
	if atomic.LoadInt32(&syncCalled) != 1 {
		t.Errorf("expected 1 sync call, got %d", syncCalled)
	}
	if gotAuth != "Bearer jwt-abc" {
		t.Errorf("unexpected Authorization header: %q", gotAuth)
	}
}

func TestRefreshAndSync_PropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"permission denied"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &Client{Server: srv.URL, Token: "t", Enable: true, HTTP: srv.Client()}
	err := c.RefreshAndSync(context.Background(), "demo")
	if err == nil {
		t.Fatal("expected error from 403 sync response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected error to mention status 403, got: %v", err)
	}
}

func TestRefreshAndSync_NoopWhenDisabled(t *testing.T) {
	c := &Client{Server: "", Token: "", Enable: false}
	if err := c.RefreshAndSync(context.Background(), "demo"); err != nil {
		t.Fatalf("disabled client should no-op, got: %v", err)
	}
}

func TestNewClient_ReadsEnv(t *testing.T) {
	t.Setenv("ARGOCD_SERVER", "https://argo.example")
	t.Setenv("ARGOCD_AUTH_TOKEN", "jwt")
	t.Setenv("ARGOCD_SYNC_ENABLED", "true")

	c := NewClient()
	if c.Server != "https://argo.example" {
		t.Errorf("Server=%q", c.Server)
	}
	if c.Token != "jwt" {
		t.Errorf("Token=%q", c.Token)
	}
	if !c.Enable {
		t.Error("expected Enable=true")
	}
	if !c.Enabled() {
		t.Error("expected Enabled()=true")
	}
}

func TestNewClient_DefaultDisabled(t *testing.T) {
	t.Setenv("ARGOCD_SERVER", "")
	t.Setenv("ARGOCD_AUTH_TOKEN", "")
	t.Setenv("ARGOCD_SYNC_ENABLED", "")
	c := NewClient()
	if c.Enabled() {
		t.Error("expected Enabled()=false when env unset")
	}
}
