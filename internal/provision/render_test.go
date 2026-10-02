package provision

import (
	"strings"
	"testing"
)

// The Deployment, Service and Route live only in the cluster. If this test
// ever sees more than one file, manifests (and secrets) are leaking into git.
func TestRender_OnlyApplicationReachesGit(t *testing.T) {
	t.Parallel()

	files, err := Render(validSpec(), appConfig())
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if len(files) != 1 {
		names := make([]string, len(files))
		for i, f := range files {
			names[i] = f.Name
		}
		t.Fatalf("Render() returned %d files %v, want exactly 1 (the Application)", len(files), names)
	}
	if want := "declarative/dev/infra/argocd/applications/sealed-secrets.yaml"; files[0].Name != want {
		t.Fatalf("file name = %q, want %q", files[0].Name, want)
	}
	if !strings.Contains(string(files[0].Data), "kind: Application") {
		t.Fatalf("file data is not an Application:\n%s", files[0].Data)
	}
}

func TestRender_InvalidSpecShortCircuits(t *testing.T) {
	t.Parallel()

	spec := validSpec()
	spec.Namespace = ""
	files, err := Render(spec, appConfig())
	if err == nil {
		t.Fatal("Render() = nil error, want error for invalid spec")
	}
	if files != nil {
		t.Fatalf("Render() returned %d files on error, want none", len(files))
	}
}
