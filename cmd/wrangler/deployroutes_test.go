package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestHandleGetDeployment(t *testing.T) {
	t.Parallel()

	reader := newDeploymentReader(k8sfake.NewSimpleClientset(
		ravenDeployment("ssg-dev", "ssg", 1, 0),
		ravenPod("ssg-dev-abc", "ssg", "ssg-dev", &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}, 7),
	), "ssg")

	mux := http.NewServeMux()
	addRoutes(mux, serverDeps{deployments: reader, verifier: fakeVerifier{}, requiredScope: "raven:provision"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ravens/ssg-dev/deployment", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got deploymentStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Namespace != "ssg" {
		t.Errorf("namespace = %q, want ssg", got.Namespace)
	}
	if len(got.Pods) != 1 || got.Pods[0].Reason != "CrashLoopBackOff" {
		t.Errorf("pods = %+v, want one CrashLoopBackOff", got.Pods)
	}
}

func TestHandleGetDeployment_UnknownRaven(t *testing.T) {
	t.Parallel()

	reader := newDeploymentReader(k8sfake.NewSimpleClientset(), "ssg")

	mux := http.NewServeMux()
	addRoutes(mux, serverDeps{deployments: reader, verifier: fakeVerifier{}, requiredScope: "raven:provision"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ravens/nope/deployment", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// Reading deployment status is not gated, matching the rollout feed.
func TestHandleGetDeployment_NeedsNoToken(t *testing.T) {
	t.Parallel()

	reader := newDeploymentReader(k8sfake.NewSimpleClientset(ravenDeployment("ssg-dev", "ssg", 1, 1)), "ssg")

	mux := http.NewServeMux()
	addRoutes(mux, serverDeps{
		deployments:   reader,
		verifier:      fakeVerifier{err: errors.New("denied")},
		requiredScope: "raven:provision",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ravens/ssg-dev/deployment", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
