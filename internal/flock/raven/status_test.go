package raven_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/volck/raven/internal/flock/raven"
)

func TestStatus_OK(t *testing.T) {
	t.Parallel()
	want := raven.Status{
		Engine:   "dev",
		DestEnv:  "dev",
		VaultURL: "https://vault.example",
		Sync: raven.SyncSummary{
			LastSync:     time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC),
			NextSync:     time.Date(2026, 5, 22, 12, 1, 0, 0, time.UTC),
			SleepSeconds: 60,
		},
		Secrets: []raven.SecretFile{
			{Name: "foo.yaml", SecretName: "foo", Modified: time.Date(2026, 5, 22, 11, 0, 0, 0, time.UTC),
				K8s: &raven.SecretK8sState{Deployments: []string{"my-app"}, Source: "k8s"}},
			{Name: "bar.yaml", SecretName: "bar", Modified: time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)},
		},
		SecretCount: 2,
		EventCount:  17,
		GeneratedAt: time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/status" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	t.Cleanup(srv.Close)

	c, _ := raven.New(raven.WithRequestTimeout(2 * time.Second))
	got, err := c.Status(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Status err = %v", err)
	}
	if got.Engine != "dev" || got.SecretCount != 2 || got.EventCount != 17 {
		t.Fatalf("got = %+v", got)
	}
	if len(got.Secrets) != 2 || got.Secrets[0].SecretName != "foo" {
		t.Fatalf("secrets = %+v", got.Secrets)
	}
	if got.Secrets[0].K8s == nil || got.Secrets[0].K8s.Deployments[0] != "my-app" {
		t.Fatalf("k8s state = %+v", got.Secrets[0].K8s)
	}
}

func TestStatus_Non2xxIsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c, _ := raven.New(raven.WithRequestTimeout(time.Second))
	_, err := c.Status(context.Background(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 error, got %v", err)
	}
}

func TestStatus_BadURL(t *testing.T) {
	t.Parallel()
	c, _ := raven.New(raven.WithRequestTimeout(time.Second))
	if _, err := c.Status(context.Background(), "no-scheme-here"); err == nil {
		t.Fatal("expected url error")
	}
}

func TestStatus_GarbageBody(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	t.Cleanup(srv.Close)
	c, _ := raven.New(raven.WithRequestTimeout(time.Second))
	if _, err := c.Status(context.Background(), srv.URL); err == nil {
		t.Fatal("expected decode error")
	}
}
