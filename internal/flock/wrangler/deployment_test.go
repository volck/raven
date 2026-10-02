package wrangler_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	wrclient "github.com/volck/raven/internal/flock/wrangler"
)

func TestClient_Deployment(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ravens/ssg-dev/deployment" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"name":"ssg-dev","namespace":"ssg","desired":1,"ready":0,
			"conditions":[{"type":"Available","status":"False","reason":"MinimumReplicasUnavailable"}],
			"pods":[{"name":"ssg-dev-abc","phase":"Pending","ready":false,"restarts":3,"reason":"ImagePullBackOff"}]
		}`))
	}))
	t.Cleanup(server.Close)

	client, err := wrclient.New(server.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := client.Deployment(context.Background(), "ssg-dev")
	if err != nil {
		t.Fatalf("Deployment: %v", err)
	}
	if got.Namespace != "ssg" || got.Desired != 1 || got.Ready != 0 {
		t.Errorf("got %+v", got)
	}
	if len(got.Pods) != 1 || got.Pods[0].Reason != "ImagePullBackOff" {
		t.Errorf("pods = %+v", got.Pods)
	}
	if len(got.Conditions) != 1 || got.Conditions[0].Reason != "MinimumReplicasUnavailable" {
		t.Errorf("conditions = %+v", got.Conditions)
	}
}

// A raven wrangler does not know about must be distinguishable from an outage,
// so flock can answer 404 rather than 502.
func TestClient_Deployment_NotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	client, err := wrclient.New(server.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := client.Deployment(context.Background(), "nope"); !errors.Is(err, wrclient.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// The raven name lands in the path, so it must be escaped rather than
// concatenated.
func TestClient_Deployment_EscapesName(t *testing.T) {
	t.Parallel()

	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"name":"x"}`))
	}))
	t.Cleanup(server.Close)

	client, err := wrclient.New(server.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := client.Deployment(context.Background(), "../rollouts"); err != nil {
		t.Fatalf("Deployment: %v", err)
	}
	if gotPath != "/api/v1/ravens/..%2Frollouts/deployment" {
		t.Errorf("path = %q, want the name escaped", gotPath)
	}
}
