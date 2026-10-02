package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func appConfig() ApplicationConfig {
	return ApplicationConfig{
		TargetRevision: "HEAD",
		DestServer:     "https://kubernetes.default.svc",
	}
}

// ArgoCD only reconciles an Application from the namespace its controller
// watches, and these are per-tenant: landing in argocd would never sync.
func TestRenderApplication_LivesInDestEnv(t *testing.T) {
	t.Parallel()

	spec := validSpec()
	spec.Namespace = "ssg"
	spec.DestEnv = "kafkaledger"

	got, err := RenderApplication(spec, appConfig())
	if err != nil {
		t.Fatalf("RenderApplication() error = %v", err)
	}
	for _, want := range []string{
		"  namespace: kafkaledger",
		"  project: kafkaledger",
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("rendered Application missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), "namespace: ssg") {
		t.Errorf("Application targets the raven's own namespace, want DestEnv:\n%s", got)
	}
}

func TestRenderApplication(t *testing.T) {
	t.Parallel()

	got, err := RenderApplication(validSpec(), appConfig())
	if err != nil {
		t.Fatalf("RenderApplication() error = %v", err)
	}

	golden := filepath.Join("testdata", "application.golden.yaml")
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("rendered Application mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderApplication_InvalidSpec(t *testing.T) {
	t.Parallel()

	spec := validSpec()
	spec.Name = ""
	if _, err := RenderApplication(spec, appConfig()); err == nil {
		t.Fatal("RenderApplication() = nil error, want error for invalid spec")
	}
}

// The Application must sync the directory raven actually writes to. Raven keys
// that on DestEnv; syncing the SecretEngine path yields a silently empty app.
func TestRenderApplication_PathFollowsDestEnv(t *testing.T) {
	t.Parallel()

	spec := validSpec()
	spec.SecretEngine = "kv"
	spec.DestEnv = "int"

	got, err := RenderApplication(spec, appConfig())
	if err != nil {
		t.Fatalf("RenderApplication() error = %v", err)
	}
	if want := "path: declarative/int/sealedsecrets"; !strings.Contains(string(got), want) {
		t.Errorf("rendered Application missing %q:\n%s", want, got)
	}
	if strings.Contains(string(got), "declarative/kv/") {
		t.Errorf("path was built from SecretEngine, want DestEnv:\n%s", got)
	}
}
