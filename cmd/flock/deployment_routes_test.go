package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/volck/raven/internal/flock"
	wrclient "github.com/volck/raven/internal/flock/wrangler"
)

type fakeDeployments struct {
	deployment *wrclient.Deployment
	err        error
	calls      int
}

func (f *fakeDeployments) Deployment(_ context.Context, _ string) (*wrclient.Deployment, error) {
	f.calls++
	return f.deployment, f.err
}

func deploymentServer(t *testing.T, deployments DeploymentFetcher) http.Handler {
	t.Helper()

	snap := &fakeSnap{
		snap:  flock.Snapshot{Engines: []string{"kv"}, Routing: map[string][]string{"kv": {"https://ssg-dev"}}},
		ready: true,
	}

	mux := http.NewServeMux()
	addDeploymentRoutes(mux, slog.New(slog.NewTextHandler(io.Discard, nil)), snap, deployments)
	return mux
}

func getDeployment(t *testing.T, deployments DeploymentFetcher, name string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ravens/"+name+"/deployment", nil)
	deploymentServer(t, deployments).ServeHTTP(rec, req)
	return rec
}

func TestHandleGetRavenDeployment(t *testing.T) {
	t.Parallel()

	fake := &fakeDeployments{deployment: &wrclient.Deployment{
		Name:      "kv",
		Namespace: "ssg",
		Desired:   1,
		Pods:      []wrclient.PodStatus{{Name: "kv-abc", Reason: "CrashLoopBackOff", Restarts: 7}},
	}}

	rec := getDeployment(t, fake, "kv")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got wrclient.Deployment
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Pods) != 1 || got.Pods[0].Reason != "CrashLoopBackOff" {
		t.Errorf("pods = %+v", got.Pods)
	}
	if got.Namespace != "ssg" {
		t.Errorf("namespace = %q, want ssg", got.Namespace)
	}
}

// A raven flock does not route to is a 404 before wrangler is ever asked.
func TestHandleGetRavenDeployment_UnknownRaven(t *testing.T) {
	t.Parallel()

	fake := &fakeDeployments{}

	if rec := getDeployment(t, fake, "nope"); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if fake.calls != 0 {
		t.Errorf("asked wrangler about a raven flock does not route to")
	}
}

// Without a wrangler there is no source of deployment status, which is a
// different answer from "this raven has no deployment".
func TestHandleGetRavenDeployment_NoWrangler(t *testing.T) {
	t.Parallel()

	if rec := getDeployment(t, nil, "kv"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestHandleGetRavenDeployment_WranglerNotFound(t *testing.T) {
	t.Parallel()

	fake := &fakeDeployments{err: wrclient.ErrNotFound}

	if rec := getDeployment(t, fake, "kv"); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// An unreachable wrangler is flock's upstream failing, not flock failing.
func TestHandleGetRavenDeployment_WranglerUnreachable(t *testing.T) {
	t.Parallel()

	fake := &fakeDeployments{err: errors.New("connection refused")}

	if rec := getDeployment(t, fake, "kv"); rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}
